# CLAUDE-ssh-ca.md — SSH Certificate Authority

Companion to `CLAUDE.md`. Follow all conventions there. New territory:
this is the first non-X.509 issuance path in the codebase, so a few
patterns need extending. The CA's existing keys (Ed25519, ECDSA, RSA)
are reused — no new key material, just a second issuance surface.

---

## What SSH CA is

OpenSSH supports certificate-based authentication where the CA signs
short-lived SSH user certs (replacing per-host `authorized_keys`
sprawl) and host certs (replacing per-host fingerprint trust-on-first-use).
The wire format is OpenSSH's own, documented in `PROTOCOL.certkeys` in
the OpenSSH source tree, not an IETF RFC.

Shipping this lets PyPKI displace HashiCorp Vault's SSH secrets engine
and `step-ca`'s SSH issuance for ops teams that want one CA for
everything.

---

## OpenSSH cert format (binary-affecting — read carefully)

Cert key types, by underlying key:

| CA key       | SSH cert key type                              |
| ------------ | ---------------------------------------------- |
| Ed25519      | `ssh-ed25519-cert-v01@openssh.com`             |
| ECDSA P-256  | `ecdsa-sha2-nistp256-cert-v01@openssh.com`     |
| ECDSA P-384  | `ecdsa-sha2-nistp384-cert-v01@openssh.com`     |
| ECDSA P-521  | `ecdsa-sha2-nistp521-cert-v01@openssh.com`     |
| RSA          | `rsa-sha2-256-cert-v01@openssh.com` (signature) / `ssh-rsa-cert-v01@openssh.com` (key type) |

ML-DSA / SLH-DSA / Ed448 / composite: not supported by OpenSSH as of
9.x. Reject at issuance time with a clear error.

Wire encoding is SSH wire format (RFC 4251 §5): length-prefixed strings,
big-endian, no padding. Field order is fixed by `PROTOCOL.certkeys`:

```
string    "ssh-ed25519-cert-v01@openssh.com" (or other)
string    nonce            (32 bytes of randomness)
<...>     algorithm-specific public key fields
uint64    serial
uint32    type             (1 = user, 2 = host)
string    key id           (audit-friendly identifier; freeform)
string    valid principals (list of strings, each length-prefixed)
uint64    valid after      (unix seconds, 0 = always)
uint64    valid before     (unix seconds, 2^64-1 = never)
string    critical options (list of name-value pairs, see below)
string    extensions       (list of name-value pairs, see below)
string    reserved         (empty string)
string    signature key    (CA pubkey in SSH wire format)
string    signature        (signature over all preceding fields)
```

Implement an `ssh_wire` helper module mirroring the ASN.1 helpers in
`scep_server.py` — `_ssh_string`, `_ssh_uint32`, `_ssh_uint64`,
`_ssh_mpint`, `_ssh_name_list`. ~150 LoC.

### Critical options vs extensions

**Critical options** (server MUST reject if it doesn't understand):

| Option              | Value type | Purpose                                    |
| ------------------- | ---------- | ------------------------------------------ |
| `force-command`     | string     | Override the user's requested command      |
| `source-address`    | string     | Comma-separated CIDRs the cert is valid from |
| `verify-required`   | empty      | Require touch on FIDO2 key                 |

**Extensions** (server SHOULD ignore if unknown):

| Extension                  | Default for user cert |
| -------------------------- | --------------------- |
| `permit-X11-forwarding`    | enabled               |
| `permit-agent-forwarding`  | enabled               |
| `permit-port-forwarding`   | enabled               |
| `permit-pty`               | enabled               |
| `permit-user-rc`           | enabled               |
| `no-touch-required`        | omitted (touch required) |

Host certs: no extensions, no critical options by default.

---

## API surface

### Sign user cert

```
POST /api/ssh/sign
{
  "public_key": "ssh-ed25519 AAAA... user@laptop",  // OpenSSH authorized_keys format
  "key_id": "alice@corp:laptop-2026-05",
  "principals": ["alice", "deploy"],
  "valid_seconds": 3600,
  "critical_options": {
    "source-address": "10.0.0.0/8,192.168.0.0/16"
  },
  "extensions": ["permit-pty", "permit-agent-forwarding"],
  "profile": "ssh_user"
}
```

Response: signed cert in OpenSSH `ssh-ed25519-cert-v01@openssh.com AAAA...`
format (single-line, paste-ready into `~/.ssh/`).

### Sign host cert

```
POST /api/ssh/host-cert
{
  "public_key": "ecdsa-sha2-nistp256 AAAA... root@web01",
  "key_id": "host:web01.prod",
  "principals": ["web01.prod.example.com", "web01"],
  "valid_seconds": 2592000,           // 30 days
  "profile": "ssh_host"
}
```

### Known-hosts feed

```
GET /api/ssh/known-hosts
```

Returns lines of the form `@cert-authority *.prod.example.com ssh-ed25519
AAAA...` ready to drop into `/etc/ssh/ssh_known_hosts` so clients trust
the CA for host certs.

---

## Implementation

### Files touched

| File                | Change                                                |
| ------------------- | ----------------------------------------------------- |
| `ssh_ca.py`         | New module: wire encoding, cert builder, signer       |
| `ssh_wire.py`       | New module: SSH wire-format primitives                |
| `pki_server.py`     | New endpoints, profile catalog entries                |
| `web_ui.py`         | SSH cert issuance page, principals manager            |
| `db_migrations/pki/00X_ssh.sql` | New tables                                |
| `test_pki_server.py` | `TestSSHCAUserCert`, `TestSSHCAHostCert`, `TestSSHWire` |
| `README.md`         | New section, CLI/API docs                             |
| `CHANGELOG.md`      | `### Added`                                           |
| `pypki-flows.html`  | SSH issuance + verification flow                      |

### CertProfile catalog additions

Two new entries near line 606 in `pki_server.py`. SSH profiles diverge
from X.509 profiles enough that they need a sibling dataclass
`SSHCertProfile`:

```python
@dataclass(frozen=True)
class SSHCertProfile:
    cert_type: int                       # 1 user, 2 host
    max_validity_seconds: int
    default_validity_seconds: int
    allowed_principals_regex: str        # e.g. r"^[a-z][a-z0-9_-]{0,30}$"
    default_extensions: frozenset[str]
    allowed_critical_options: frozenset[str]

SSH_PROFILES = {
    "ssh_user": SSHCertProfile(
        cert_type=1,
        max_validity_seconds=86400,
        default_validity_seconds=3600,
        allowed_principals_regex=r"^[a-z][a-z0-9_-]{0,30}$",
        default_extensions=frozenset({"permit-pty", "permit-agent-forwarding"}),
        allowed_critical_options=frozenset({"source-address", "force-command", "verify-required"}),
    ),
    "ssh_host": SSHCertProfile(
        cert_type=2,
        max_validity_seconds=2592000,
        default_validity_seconds=2592000,
        allowed_principals_regex=r"^[a-z0-9.-]+$",
        default_extensions=frozenset(),
        allowed_critical_options=frozenset(),
    ),
}
```

### Schema

```sql
-- db_migrations/pki/00X_ssh.sql
CREATE TABLE ssh_certificates (
    id              {{auto_pk}},
    serial          INTEGER NOT NULL UNIQUE,    -- SSH cert serial is uint64
    key_id          TEXT NOT NULL,
    cert_type       INTEGER NOT NULL,           -- 1 = user, 2 = host
    principals      TEXT NOT NULL,              -- JSON array
    valid_after     INTEGER NOT NULL,           -- unix seconds
    valid_before    INTEGER NOT NULL,           -- unix seconds
    public_key_fpr  TEXT NOT NULL,              -- SHA256:... of subject pubkey
    ca_key_fpr      TEXT NOT NULL,              -- SHA256:... of signing CA pubkey
    cert_blob       BLOB NOT NULL,              -- the signed cert (binary form)
    revoked         INTEGER NOT NULL DEFAULT 0,
    revoked_at      INTEGER,
    profile         TEXT NOT NULL
);
CREATE INDEX idx_ssh_certs_key_id     ON ssh_certificates(key_id);
CREATE INDEX idx_ssh_certs_principal  ON ssh_certificates(principals);
CREATE INDEX idx_ssh_certs_valid_after ON ssh_certificates(valid_after);
```

SSH serials are 64-bit; use the same `advisory_lock("serial-allocation")`
machinery, but with a separate `ssh_serial_counter` (X.509 serials are
random 20-byte; SSH serials are typically monotonic).

### Revocation: KRL files

SSH doesn't do OCSP/CRL. It uses Key Revocation Lists (`man ssh-keygen`
`-k -s`). Generate KRL files on demand: signed binary file listing
revoked serials by CA key.

Endpoint: `GET /api/ssh/krl/<ca-key-fpr>` returns the current KRL signed
by the CA. Operators drop this on hosts via config-management and set
`RevokedKeys /etc/ssh/krl` in `sshd_config`.

Implement KRL serialization in `ssh_ca.py` — wire format documented in
the OpenSSH source (`krl.h`). Cache the signed KRL with a 5-minute TTL
to amortize signing cost.

---

## CLI flags

```
--ssh-ca-enabled                    # default false until first release
--ssh-ca-key-source ca|separate     # reuse CA key or generate dedicated SSH CA key
--ssh-user-max-validity 86400       # seconds, hard cap
--ssh-host-max-validity 2592000     # seconds
--ssh-krl-ttl 300                   # cached KRL signing interval
```

`pypki_admin.py` subcommands:

- `ssh-revoke --serial N --reason superseded`
- `ssh-list --principal alice`
- `ssh-krl-export --out /tmp/krl`

---

## Tests

```
class TestSSHWire(unittest.TestCase):
    def test_string_round_trip(self): ...
    def test_uint32_uint64_encoding(self): ...
    def test_mpint_handles_high_bit(self): ...
    def test_name_list_empty_and_single_and_multiple(self): ...

class TestSSHCAUserCert(unittest.TestCase):
    def test_round_trip_ed25519(self): ...
    def test_round_trip_ecdsa_p256(self): ...
    def test_round_trip_rsa_sha256(self): ...
    def test_principals_enforced_against_regex(self): ...
    def test_validity_capped_at_profile_max(self): ...
    def test_force_command_critical_option(self): ...
    def test_source_address_critical_option(self): ...
    def test_unknown_critical_option_rejected_at_issue(self): ...
    def test_openssh_verifies_our_cert(self): ...   # subprocess to ssh-keygen -L
    def test_cert_signed_by_ml_dsa_ca_rejected(self): ...

class TestSSHCAHostCert(unittest.TestCase):
    def test_round_trip(self): ...
    def test_no_default_extensions(self): ...
    def test_known_hosts_feed_format(self): ...

class TestSSHKRL(unittest.TestCase):
    def test_krl_after_revocation_contains_serial(self): ...
    def test_krl_signed_by_ca_key(self): ...
    def test_openssh_accepts_our_krl(self): ...     # ssh-keygen -Q
```

The `ssh-keygen -L` / `ssh-keygen -Q` subprocess tests are non-negotiable:
they're how we know we agree with the real implementation. Skip them
gracefully if `ssh-keygen` is missing from the test environment.

---

## Per-change checklist

- [ ] `ssh_wire.py` — new module
- [ ] `ssh_ca.py` — new module (cert builder, signer, KRL)
- [ ] `pki_server.py` — endpoint wiring, `SSHCertProfile` catalog, audit events
- [ ] `db_migrations/pki/00X_ssh.sql` — new table
- [ ] `web_ui.py` — SSH issuance page, KRL download
- [ ] `pypki_admin.py` — `ssh-revoke`, `ssh-list`, `ssh-krl-export`
- [ ] `hooks.py` — `ssh_cert.issued`, `ssh_cert.revoked` events
- [ ] `test_pki_server.py` — four new test classes
- [ ] `README.md` — new top-level "SSH CA" section, CLI/API docs
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `pypki-flows.html` — SSH issuance and KRL flow
- [ ] `docs/SSH.md` — operator runbook (config-management snippets,
      sshd_config, `TrustedUserCAKeys`, `HostCertificate`)

Run `./run_tests.sh`.

---

## Open questions

1. **Separate SSH CA key vs reuse X.509 CA key**: technically fine to
   reuse; ergonomically dangerous (a single key compromise hits both
   PKIs). Default to `--ssh-ca-key-source separate` and generate a
   dedicated Ed25519 SSH CA key under `ca/ssh/`. Document the tradeoff.

2. **Sub-CAs for SSH**: X.509 has clean sub-CA semantics; SSH has none
   (it's a single signature, no chain). For multi-tenant deployments,
   issue from the same CA but use `key_id` namespacing
   (`tenant_a/alice@laptop`) and KRL-per-tenant. Document this in
   `docs/SSH.md`.

3. **FIDO2-backed user keys (`sk-ed25519`, `sk-ecdsa-sha2-nistp256`)**:
   subject pubkey wire format differs (`@openssh.com` suffix variants).
   Detect and pass through; the CA doesn't care about the subject key
   type as long as it can re-serialize it. Add `verify-required`
   critical option support for these.

4. **Principal "*" wildcards**: OpenSSH supports glob-style principals
   (e.g. `*.deploy`). The profile regex must permit `*` for these.
   Decide per-profile: `ssh_admin` profile allows wildcards,
   `ssh_user` does not. Operator opt-in.

5. **ACME for SSH**: there's `draft-ietf-acme-ssh`, currently expired.
   If it revives, SSH issuance gets an ACME flow for free (reuses
   `acme_server.py`). Until then, REST-only.
