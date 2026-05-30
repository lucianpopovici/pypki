# CLAUDE-acme-onion.md — ACME for .onion Hidden Services (RFC 9799)

Companion to `CLAUDE.md`. Follow all conventions there. **Conditional**:
ship this only when a concrete deployment target needs it. PyPKI's current
homelab + enterprise mTLS focus does not. Keep this spec ready so the work
is one merge request away if a user asks.

---

## What RFC 9799 is

ACME extensions (June 2025) for issuing certificates whose Subject CN /
SAN is a Tor v3 onion address (56 base32 chars + `.onion`). Two
contributions:

1. **`onion-csr-01` challenge type** — proof of control via a signed nonce
   embedded in the CSR, since `http-01` / `dns-01` don't work for hidden
   services.
2. **In-band CAA** — `.onion` services can't publish DNS CAA records;
   RFC 9799 §5 defines a caaIdentities mechanism delivered inside the
   ACME challenge response.

Targets the CA/Browser Forum baseline for `.onion` certificates and is
already supported by HARICA's public ACME endpoint.

---

## Wire surface

### Directory metadata additions

```
{
  "meta": {
    "onionCAAEnabled": true,
    "onionCAAValidationMethods": ["onion-csr-01"]
  }
}
```

### New challenge type

`onion-csr-01`: server returns a `token` in the challenge object plus a
`nonce`. Client builds a CSR whose extensions include:

- `cabf-onion-nonce` (OID `1.3.6.1.4.1.44947.1.1.1`) — the server nonce.
- `cabf-onion-caa` (OID `1.3.6.1.4.1.44947.1.1.2`) — the caaIdentities
  asserted by the operator, signed by the onion service key.

Server validates by:

1. Parsing the CSR's `cabf-onion-nonce` extension; assert it matches the
   issued nonce.
2. Verifying the CSR signature against the Ed25519 onion service
   identity key (derived from the `.onion` address — Tor v3 addresses
   are Ed25519 public keys + checksum + version, base32-encoded).
3. If `onionCAARequired` is true for this CA, validating the in-band
   CAA against the CA's identity per §5.

### New error type

```
urn:ietf:params:acme:error:onionCAARequired
```

Returned when the CA mandates in-band CAA but the client didn't supply it.

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `acme_server.py`  | New `_handle_onion_csr_challenge()`, identifier type `dns` extended to accept `.onion`, directory metadata, error type registration |
| `onion.py`        | New module: Tor v3 address parsing/validation, Ed25519 key recovery from address, CAA verification |
| `pki_server.py`   | SAN validation: allow `.onion` in `dNSName` for `onion_eligible` profile |
| `db_migrations/acme/00X_onion.sql` | Schema for caaIdentities tracking      |
| `test_pki_server.py` | `TestRFC9799ACMEOnion`, `TestTorV3AddressDecode`          |
| `README.md`       | Protocol compliance row, CLI documentation, deployment caveat |
| `CHANGELOG.md`    | `### Added`                                                  |

### Tor v3 address decode

Tor v3 onion addresses encode an Ed25519 public key. The 56-char base32
string decodes to 35 bytes: `pubkey(32) || checksum(2) || version(1)`.

```python
def decode_v3_onion(addr: str) -> ed25519.Ed25519PublicKey:
    """addr is the base32-without-padding hostname minus '.onion'."""
    if not addr.endswith(".onion"):
        raise ValueError("not an onion address")
    body = addr[:-len(".onion")]
    if len(body) != 56:
        raise ValueError("not a v3 onion address")
    raw = base64.b32decode(body.upper())
    if len(raw) != 35:
        raise ValueError("decoded length wrong")
    pubkey_bytes, checksum, version = raw[:32], raw[32:34], raw[34]
    if version != 0x03:
        raise ValueError("only v3 supported")
    expected_checksum = hashlib.sha3_256(
        b".onion checksum" + pubkey_bytes + bytes([version])
    ).digest()[:2]
    if checksum != expected_checksum:
        raise ValueError("checksum mismatch")
    return ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
```

CSR signature verification then becomes "verify the CSR signature with
this recovered Ed25519 key" — same primitive as the rest of the codebase.

### Schema

```sql
-- db_migrations/acme/00X_onion.sql
CREATE TABLE acme_onion_caa (
    cert_id          TEXT PRIMARY KEY,    -- AKI.serial like ARI
    onion_address    TEXT NOT NULL,
    caa_identities   TEXT NOT NULL,       -- JSON array of asserted CA identities
    asserted_at      INTEGER NOT NULL,    -- unix seconds
    asserted_via     TEXT NOT NULL        -- "in-band" or "dns"
);
CREATE INDEX idx_acme_onion_addr ON acme_onion_caa(onion_address);
```

In-band CAA is logged but not authoritative on its own — the CA still
makes the issuance decision per its CPS.

---

## CLI flags

```
--acme-onion-enabled            # default false
--acme-onion-caa-required       # default false; if true, reject without in-band CAA
--acme-onion-allowed-tld        # default ".onion"; do not change unless testing
```

CAA identity for this CA is configured via existing `--cps-uri` /
`--cps-policy-oid` flags plus a new `--ca-caa-identity` (the string the
in-band CAA asserts trust in).

---

## Tests

```
class TestRFC9799ACMEOnion(unittest.TestCase):
    def test_directory_advertises_onion_caa_when_enabled(self): ...
    def test_directory_omits_onion_caa_when_disabled(self): ...
    def test_onion_csr_challenge_returns_nonce(self): ...
    def test_csr_with_correct_nonce_validates(self): ...
    def test_csr_with_wrong_nonce_fails(self): ...
    def test_csr_signed_by_wrong_key_fails(self): ...
    def test_in_band_caa_recorded_in_audit_log(self): ...
    def test_onion_caa_required_returns_specific_error(self): ...
    def test_san_allows_onion_addresses(self): ...
    def test_san_rejects_invalid_onion_addresses(self): ...

class TestTorV3AddressDecode(unittest.TestCase):
    # Test vectors from Tor specification rend-spec-v3 §6
    def test_well_known_facebook_onion(self): ...
    def test_v2_addresses_rejected(self): ...
    def test_truncated_addresses_rejected(self): ...
    def test_bad_checksum_rejected(self): ...
```

Interop target: HARICA's onion ACME endpoint produces real-world test
vectors. Mirror at least one of their issuance flows in
`tests/interop/test_onion_acme.sh`.

---

## Per-change checklist

- [ ] `onion.py` — new module
- [ ] `acme_server.py` — onion-csr-01 handler, directory metadata, error
- [ ] `pki_server.py` — `.onion` SAN allowlist for `onion_eligible` profile
- [ ] `db_migrations/acme/00X_onion.sql` — caa identities table
- [ ] `test_pki_server.py` — `TestRFC9799ACMEOnion`, `TestTorV3AddressDecode`
- [ ] `README.md` — Protocol compliance row + caveat ("not for default
      deployment; opt-in via `--acme-onion-enabled`")
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `pypki-flows.html` — onion-csr-01 flow diagram
- [ ] `docs/ONION.md` — operator runbook for issuing to hidden services

Run `./run_tests.sh`.

---

## When to actually do this

Build this only when one of the following is true:

- A user (homelab or enterprise) is operating Tor hidden services and
  needs certificates for them.
- PyPKI is being trialed as a `.onion` CA by an existing public CA
  operator (HARICA, DigiCert).
- The CA/Browser Forum mandates support and PyPKI's compliance posture
  benefits from claiming it.

Until then, this spec stays on the shelf. The `RFC 9799` row in the
README's Protocol compliance table should remain absent rather than be
marked "planned" — claiming planned support invites bug reports against
unshipped code.

---

## Open questions

1. **SAN encoding for `.onion`**: CABF Baseline Requirements §3.2.2.4
   permits `dNSName` for `.onion` (it's a Special-Use Domain). Verify
   our `x509.SubjectAlternativeName` builder doesn't reject it — the
   `cryptography` library is sometimes pickier than needed.

2. **Validity period cap**: CABF caps `.onion` cert lifetime at the
   same level as TLS server certs. Inherit the profile's `validity_days`
   unless a future BR change tightens it for onion.

3. **Logging**: onion addresses are sensitive operational metadata for
   some operators (e.g. journalists). The structured JSON audit log
   should hash or truncate onion addresses by default, with
   `--acme-onion-audit-full` to opt into full logging. Default to
   privacy-preserving.

4. **Rate limits**: Tor name lookup is slower than DNS. The existing
   token-bucket limiter is fine, but new `acme_onion_validations_total`
   and `acme_onion_validation_duration_seconds` metrics let operators
   see if onion validation is a bottleneck.
