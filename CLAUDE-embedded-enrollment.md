# CLAUDE-embedded-enrollment.md — Embedded Device Enrollment (WireGuard + Matter)

Companion to `CLAUDE.md`. Follow all conventions there. Two unrelated
protocols that fit the same operational shape: minting identities for
devices that aren't full-blown TLS clients. Could be split into two
specs; kept together because they share enough infrastructure (new
profile types, JSON APIs, no ACME/SCEP/EST surface) that the work
sequences naturally.

---

## What this is

PyPKI's existing enrollment protocols (ACME, SCEP, EST, CMP) all
assume the requester can do an X.509 / TLS handshake. Plenty of
identity issuance doesn't fit that mold:

- **WireGuard** uses Curve25519 keys with no certificate concept;
  operators want a CA-like authority that mints peer identities and
  binds them to network policy.
- **Matter** (the IoT smart-home stack) uses X.509 but with a tightly
  prescribed profile, vendor-specific OIDs, and a deployment model
  where the CA is a "Product Attestation Authority" rather than a
  general-purpose TLS CA.

Both share a JSON-only API style, no enrollment-protocol negotiation,
and a CertProfile-driven model. They're cheap to add together; harder
to retrofit later than to design now.

---

## Part 1: WireGuard PKI

### What it adds

A "WireGuard CA" that:

- Generates or accepts Curve25519 keypairs.
- Binds them to identities (`peer_name`), network policy (`allowed_ips`,
  `endpoint`, `keepalive`), and lifecycle (`valid_after`, `valid_before`).
- Emits ready-to-paste `wg` config snippets.
- Tracks active peers and supports revocation (by dropping from the
  configuration distribution).

WireGuard itself has no on-the-wire cert concept. Revocation works by
*removing* the peer from the central config — the WireGuard server
won't accept handshakes from removed peers. The "CA" here is really
an identity-and-config registry with a CA-like UX.

### Wire surface

```
POST /api/wg/peers
{
  "peer_name": "alice@laptop",
  "key_pair_generation": "server" | "csr",     // who generates the key
  "public_key": "<base64 if csr>",
  "allowed_ips": ["10.10.0.5/32"],
  "endpoint": null,                             // for clients usually null
  "persistent_keepalive": 25,
  "valid_seconds": 2592000,
  "tenant_id": "<optional>"
}
```

Server response (when `key_pair_generation: server`):

```json
{
  "peer_id": "wg-2026-0042",
  "public_key": "...",
  "private_key": "...",        // only when server-generated; never again
  "config": "[Interface]\nPrivateKey = ...\nAddress = 10.10.0.5/32\n\n[Peer]\nPublicKey = <server>\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n",
  "qr_code_png_base64": "..."  // optional, for mobile setup
}
```

CSR-style (`key_pair_generation: "csr"`) is preferred for production:
the device generates its keypair locally, sends only the public key,
and the server returns the config minus the private key.

### Server configuration distribution

The other half of "WireGuard PKI" is keeping the server's
`/etc/wireguard/wg0.conf` in sync. Two delivery modes:

1. **Pull** — a small `pypki-wg-sync` agent runs on each WireGuard
   server, polls `GET /api/wg/server-config/<server-id>`, writes the
   config, runs `wg syncconf wg0 <(wg-quick strip wg0)` to apply
   without reconnect.
2. **Push** — PyPKI POSTs the new config to a configured webhook URL
   on every change. The receiving service applies it.

Both ship; pull is the default. The agent is a single Python file
under `tools/pypki-wg-sync/` with no deps.

### Schema

```sql
-- db_migrations/pki/00X_wireguard.sql
CREATE TABLE wg_peers (
    id              {{auto_pk}},
    peer_id         TEXT UNIQUE NOT NULL,         -- "wg-2026-0042"
    peer_name       TEXT NOT NULL,
    public_key      TEXT NOT NULL,                -- base64
    allowed_ips     TEXT NOT NULL,                -- JSON array
    endpoint        TEXT,
    persistent_keepalive INTEGER,
    valid_after     INTEGER NOT NULL,
    valid_before    INTEGER NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0,
    revoked_at      INTEGER,
    tenant_id       TEXT NOT NULL DEFAULT '__system',
    created_at      INTEGER NOT NULL
);
CREATE INDEX idx_wg_peers_active ON wg_peers(revoked, valid_after, valid_before);

CREATE TABLE wg_servers (
    server_id       TEXT PRIMARY KEY,
    public_key      TEXT NOT NULL,
    endpoint        TEXT NOT NULL,
    listen_port     INTEGER NOT NULL,
    network_cidr    TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '__system'
);

CREATE TABLE wg_assignments (
    peer_id         TEXT NOT NULL,
    server_id       TEXT NOT NULL,
    assigned_at     INTEGER NOT NULL,
    PRIMARY KEY (peer_id, server_id)
);
```

### CertProfile (sibling type)

WireGuard doesn't issue X.509 certs, so the existing `CertProfile`
doesn't fit. Add `WireGuardProfile` next to `SSHCertProfile`:

```python
@dataclass(frozen=True)
class WireGuardProfile:
    max_validity_seconds: int
    allowed_ip_pattern: str           # regex on CIDR strings
    require_csr: bool                 # if True, refuse server-side key gen
    portal_self_revoke: bool

WG_PROFILES = {
    "wg_user_vpn": WireGuardProfile(
        max_validity_seconds=2592000,
        allowed_ip_pattern=r"^10\.10\.\d+\.\d+/32$",
        require_csr=False,
        portal_self_revoke=True,
    ),
    "wg_site_to_site": WireGuardProfile(
        max_validity_seconds=31536000,
        allowed_ip_pattern=r"^10\.\d+\.\d+\.\d+/(24|16)$",
        require_csr=True,
        portal_self_revoke=False,
    ),
}
```

---

## Part 2: Matter / Thread device certs

### Background

Matter (the IoT protocol from the Connectivity Standards Alliance)
uses three certificate roles per device:

- **PAA** (Product Attestation Authority) — root CA, vendor-controlled.
  Registered with the CSA in the DCL (Distributed Compliance Ledger).
- **PAI** (Product Attestation Intermediate) — intermediate signed by
  PAA. Per product line or product family.
- **DAC** (Device Attestation Certificate) — leaf signed by PAI.
  One per device, manufactured-in.

PyPKI's role: be the PAA + PAI infrastructure for a Matter device
maker, and issue DACs at manufacturing time via a JSON API.

### Matter-specific X.509 profile

DACs follow a strict profile defined in the Matter Core Specification
§6.2.2. Highlights (verify against the current spec at release time):

- **Key**: ECDSA P-256 only. No RSA, no other curves.
- **Signature algorithm**: ECDSA with SHA-256.
- **Subject DN**: contains `matter-vendor-id` and
  `matter-product-id` attributes (OIDs `1.3.6.1.4.1.37244.2.1` and
  `1.3.6.1.4.1.37244.2.2` — Matter's private arc).
- **Issuer DN**: derived from PAI's subject.
- **Validity**: typically 10 years (devices have long lives, no field
  rotation expected).
- **Basic Constraints**: `cA=false` for DACs.
- **Key Usage**: `digitalSignature` only.
- **Extended Key Usage**: omitted in DACs (per spec).
- **AKI / SKI**: required.
- **CRL distribution / OCSP**: omitted (Matter doesn't use traditional
  revocation; it uses the DCL's revocation set).
- **No SANs.** This is unusual; the device is identified by the
  vendor/product OIDs in the subject, not by SAN.

PAI has similar rules with `cA=true`, path length 0, and includes the
Matter vendor ID in its subject.

### Wire surface

```
POST /api/matter/dac
{
  "vendor_id":   "0xFFF1",
  "product_id":  "0x8000",
  "subject_serial": "ABCD1234EFGH5678",      // device-unique
  "public_key_pem": "-----BEGIN PUBLIC KEY-----...",
  "pai_id": "pai-2026-acme-lightbulbs",
  "valid_years": 10
}
```

Response: PEM-encoded DAC + the issuing PAI + (optionally) the PAA in
a single file. Matter provisioning tools accept this concatenation
directly.

```
POST /api/matter/pai
{
  "name": "Acme Lightbulbs Q3 2026",
  "vendor_id": "0xFFF1",
  "product_ids": ["0x8000", "0x8001"],       // optional; PAI can cover multiple
  "paa_id": "paa-acme-root",
  "valid_years": 20
}
```

PAA generation: standard sub-CA flow with the Matter profile applied,
exposed via existing `/api/issue-sub-ca` with `profile=matter_paa`.

### Schema

```sql
-- db_migrations/pki/00X_matter.sql
CREATE TABLE matter_authorities (
    id              {{auto_pk}},
    name            TEXT NOT NULL,             -- "paa-acme-root", "pai-2026-..."
    role            TEXT NOT NULL,             -- 'paa' | 'pai'
    vendor_id_hex   TEXT NOT NULL,             -- '0xFFF1'
    product_ids_hex TEXT,                      -- JSON array, NULL for PAA / PAI-allproducts
    serial          TEXT NOT NULL UNIQUE,
    not_after       INTEGER NOT NULL,
    parent_id       INTEGER,                   -- NULL for PAA
    tenant_id       TEXT NOT NULL DEFAULT '__system',
    FOREIGN KEY (parent_id) REFERENCES matter_authorities(id)
);

CREATE TABLE matter_dacs (
    serial          TEXT PRIMARY KEY,
    vendor_id_hex   TEXT NOT NULL,
    product_id_hex  TEXT NOT NULL,
    subject_serial  TEXT NOT NULL,
    issuer_pai_id   INTEGER NOT NULL,
    issued_at       INTEGER NOT NULL,
    not_after       INTEGER NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (issuer_pai_id) REFERENCES matter_authorities(id)
);
CREATE INDEX idx_matter_dacs_vendor_product ON matter_dacs(vendor_id_hex, product_id_hex);
```

### CertProfile entries

Add three Matter profiles. Use the existing `CertProfile` dataclass —
DACs/PAIs/PAAs *are* X.509 certs, just shaped differently:

```python
"matter_dac": CertProfile(
    key_usage=KeyUsage(digital_signature=True),
    extended_key_usages=[],                            # omitted in Matter DACs
    validity_years=10,
    allowed_algorithms={"ecdsa-p256"},
    matter_specific=MatterSpec(
        require_vendor_id=True,
        require_product_id=True,
        forbid_sans=True,
        forbid_crl_dp=True,
        forbid_ocsp_aia=True,
    ),
),
"matter_pai": CertProfile(
    is_ca=True,
    path_length=0,
    key_usage=KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True),
    validity_years=20,
    allowed_algorithms={"ecdsa-p256"},
    matter_specific=MatterSpec(require_vendor_id=True, forbid_sans=True),
),
"matter_paa": CertProfile(
    is_ca=True,
    path_length=1,
    key_usage=KeyUsage(key_cert_sign=True, crl_sign=True),
    validity_years=30,
    allowed_algorithms={"ecdsa-p256"},
    matter_specific=MatterSpec(forbid_sans=True),
),
```

`MatterSpec` is a new optional field on `CertProfile`. When present,
the issuance path applies additional constraints (vendor/product OID
encoding, SAN/extension forbidding) on top of the base profile logic.

### Thread

Thread (the underlying mesh-networking protocol Matter sits atop) has
its own commissioning credentials, distinct from Matter's DACs. Out of
scope here; Thread credentials are short-lived setup tokens rather than
manufacturing identities. Document the boundary in `docs/MATTER.md`.

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `wireguard_ca.py` | New module: peer generation, config emission, KRL equivalent |
| `matter.py`       | New module: Matter-profile cert builder, OID handling        |
| `pki_server.py`   | New endpoints, `MatterSpec` integration, `WireGuardProfile` catalog |
| `web_ui.py`       | WireGuard peer manager, Matter authority dashboard           |
| `db_migrations/pki/00X_wireguard.sql`, `db_migrations/pki/00X_matter.sql` | Schema |
| `tools/pypki-wg-sync/sync.py` | New: lightweight WireGuard server agent  |
| `pypki_admin.py`  | `wg-peer-list`, `wg-peer-revoke`,                            |
|                   | `matter-paa-list`, `matter-dac-bulk-issue`                   |
| `test_pki_server.py` | `TestWireGuardPeerLifecycle`, `TestWireGuardConfigDistribution`, |
|                   | `TestMatterDAC`, `TestMatterProfileEnforcement`              |
| `README.md`       | Two new sections                                             |
| `CHANGELOG.md`    | `### Added`                                                  |
| `docs/WIREGUARD.md`, `docs/MATTER.md` | Operator runbooks                |

### Bulk DAC issuance

Manufacturing-line use case: a factory needs to mint 10k DACs in a
short window, each with a unique `subject_serial`. The existing
issuance path is one-cert-at-a-time and goes through the full
audit/policy stack — too slow for production lines.

Add a streaming bulk endpoint:

```
POST /api/matter/dac/bulk
[
  {"subject_serial": "S001", "public_key_pem": "..."},
  {"subject_serial": "S002", "public_key_pem": "..."},
  ...
]
```

Returns NDJSON, one line per cert, streamed as issuance proceeds.
Batches the audit-log writes (one envelope per N certs, default 100)
to keep the chain manageable. Throughput target: 100 DACs/second on a
laptop, 1000/second on a server with EC accel.

The bulk endpoint is gated by a separate role (`pki:matter-factory`)
and rate-limited per-tenant. It bypasses normal per-request policy
evaluation in favor of a once-at-batch-start policy decision logged
alongside the batch.

---

## CLI flags

```
# WireGuard
--wg-enabled true
--wg-default-network-cidr 10.10.0.0/24
--wg-config-sync-mode pull|push
--wg-config-push-webhook https://...

# Matter
--matter-enabled true
--matter-bulk-batch-size 100
--matter-bulk-rate-per-second 500
--matter-csa-dcl-anchor-uri https://on.dcl.csa-iot.org/   # for future DCL submission
```

---

## Tests

```
class TestWireGuardPeerLifecycle(unittest.TestCase):
    def test_server_generated_keys_returned_once(self): ...
    def test_server_generated_private_key_not_persisted(self): ...
    def test_csr_mode_returns_no_private_key(self): ...
    def test_allowed_ips_regex_enforced(self): ...
    def test_validity_capped_at_profile_max(self): ...
    def test_peer_revocation_removes_from_server_config(self): ...
    def test_config_output_parses_as_valid_wg_config(self): ...   # via subprocess to wg

class TestWireGuardConfigDistribution(unittest.TestCase):
    def test_pull_agent_applies_idempotently(self): ...
    def test_pull_agent_handles_partial_update(self): ...
    def test_push_webhook_called_on_change(self): ...
    def test_push_webhook_retried_on_failure(self): ...

class TestMatterDAC(unittest.TestCase):
    def test_dac_has_vendor_and_product_oids_in_subject(self): ...
    def test_dac_has_no_sans(self): ...
    def test_dac_has_no_crl_dp(self): ...
    def test_dac_has_no_ocsp_aia(self): ...
    def test_dac_uses_ecdsa_p256(self): ...
    def test_dac_rejects_non_p256_key(self): ...
    def test_pai_subject_includes_vendor_id(self): ...
    def test_paa_subject_omits_product_id(self): ...
    def test_chain_validates_paa_pai_dac(self): ...
    def test_bulk_endpoint_issues_10k_certs(self): ...
    def test_bulk_endpoint_handles_partial_failure(self): ...
    def test_bulk_audit_envelope_links_to_individual_serials(self): ...

class TestMatterProfileEnforcement(unittest.TestCase):
    def test_attempt_to_add_san_to_dac_rejected(self): ...
    def test_attempt_to_use_rsa_for_dac_rejected(self): ...
    def test_attempt_to_set_path_length_2_on_pai_rejected(self): ...
```

The `subprocess to wg` test and chain-validation against the Matter
reference verifier (when available) are the interop guarantees.

---

## Per-change checklist

- [ ] `wireguard_ca.py`, `matter.py` — new modules
- [ ] `pki_server.py` — endpoints, `MatterSpec` field on `CertProfile`,
      `WireGuardProfile` catalog, bulk audit batching
- [ ] `web_ui.py` — peer manager + Matter dashboard
- [ ] `db_migrations/pki/00X_wireguard.sql`,
      `db_migrations/pki/00X_matter.sql` — schemas
- [ ] `tools/pypki-wg-sync/sync.py` — WireGuard server agent
- [ ] `pypki_admin.py` — `wg-*` and `matter-*` subcommands
- [ ] `test_pki_server.py` — four new test classes
- [ ] `README.md` — WireGuard + Matter sections
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `docs/WIREGUARD.md`, `docs/MATTER.md` — runbooks
- [ ] `pypki-flows.html` — WireGuard enrollment + Matter manufacturing flow
- [ ] `examples/wireguard/` — sample homelab setup
- [ ] `examples/matter/` — sample manufacturing-line script

Run `./run_tests.sh`.

---

## Open questions

1. **WireGuard via portal**: end users self-serving their own VPN
   peers through the portal (`CLAUDE-portal.md`) is a natural fit —
   "give me a VPN config for my new laptop" works the same way as
   "renew my TLS cert." Wire the WG profile into portal owner
   resolution; let users revoke their own peers but not others'.

2. **Matter DCL integration**: the CSA's Distributed Compliance
   Ledger holds the canonical registry of valid PAAs and revoked
   DACs. v1 doesn't talk to it; operators submit out of band. v2
   could integrate, but the DCL is a permissioned blockchain and
   integration adds dependencies. Defer until a user explicitly asks.

3. **Tailscale and Nebula alongside WireGuard**: both have similar
   "central identity registry" needs. Tailscale uses its own protocol;
   Nebula uses its own X.509 profile. If WG works well, these are
   plausible extensions. Out of scope here.

4. **Matter v2**: the Matter spec is evolving. v2 may introduce new
   cert profile constraints, additional OIDs, or new credential types.
   The `MatterSpec` dataclass is designed to be extended additively.
   Pin the spec version (`matter_spec_version: "1.3"`) in audit logs
   so old certs are interpretable years later.

5. **Hardware secure element provisioning**: production Matter
   manufacturing typically injects DACs into hardware secure elements
   (NXP SE050, Microchip ATECC608, etc.) during board test. PyPKI
   produces the DAC; getting it into the SE is the factory's
   problem. Document the typical CSV/JSON formats those factories
   expect as output so PyPKI integrates with existing programming
   stations.
