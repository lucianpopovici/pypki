# CLAUDE-composite-mldsa.md — Composite ML-DSA in X.509

Companion to `CLAUDE.md`. Follow all conventions there. Builds on the existing
ML-DSA work in `pki_server.py` (`issue_ml_dsa_certificate`, hand-rolled
TBSCertificate DER) — same pattern, more algorithm IDs.

---

## What composite signatures are

`draft-ietf-lamps-pq-composite-sigs` defines a single AlgorithmIdentifier
that wraps ML-DSA plus one classical algorithm (RSA-PSS, RSA-PKCS#1v1.5,
ECDSA P-256/P-384/P-521, Ed25519, Ed448). One public key, one signature,
verified by checking both components. Adversary must break both to forge.

Versus RFC 9763 paired certs (already shipped):

| Property                  | RFC 9763 paired       | Composite               |
| ------------------------- | --------------------- | ----------------------- |
| Certificates              | Two (one per algo)    | One                     |
| Backwards-compat with non-hybrid TLS stacks | Yes (legacy uses classical cert) | No (needs algo OID support) |
| Migration story           | Dual-stack today      | Single-stack tomorrow   |
| Signature size            | Sum of both sigs      | Sum of both sigs        |
| Cert chain validation     | Independent chains    | Single chain            |

Ship both. They're not competitors; they target different deployment phases.

---

## Standards status (verify before shipping)

- IETF Last Call closed 2026-02-03.
- Current revision: `-18` (April 2026), in RFC Editor queue.
- Composite OIDs are stable in `-18` (one renumber happened at `-13` when
  the doc switched to HPKE-style domain separators per
  `draft-irtf-cfrg-concrete-hybrid-kems`). The `-13`→`-18` series is
  binary-compatible.
- **Risk**: OIDs could shift one more time in AUTH48. Keep a single
  module-level `COMPOSITE_OIDS` table and gate behind
  `--enable-composite-mldsa` (default off) until the RFC publishes.

Re-verify at https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/
before each release.

---

## Algorithm catalog

Initial scope — ship four. Add the rest only if a user asks.

| Composite name                            | Classical    | ML-DSA level | OID source              |
| ----------------------------------------- | ------------ | ------------ | ----------------------- |
| `id-MLDSA44-RSA2048-PSS-SHA256`           | RSA-2048 PSS | ML-DSA-44    | draft §6.1              |
| `id-MLDSA44-ECDSA-P256-SHA256`            | ECDSA P-256  | ML-DSA-44    | draft §6.1              |
| `id-MLDSA65-ECDSA-P384-SHA512`            | ECDSA P-384  | ML-DSA-65    | draft §6.1              |
| `id-MLDSA87-ECDSA-P521-SHA512`            | ECDSA P-521  | ML-DSA-87    | draft §6.1              |

Defer: Ed25519/Ed448/RSA-3072/RSA-4096 combinations until a user asks.

---

## Wire encoding (binary-affecting — read draft §4 carefully)

### Public key

`subjectPublicKey BIT STRING` contains the concatenation
`mldsa_pub || classical_pub` with the encodings fixed by the draft:

- ML-DSA: raw bytes, FIPS 204 §5 lengths (1312 / 1952 / 2592 for 44/65/87).
- RSA: `RSAPublicKey` (RFC 8017 Appendix A.1.1) DER.
- ECDSA: raw X9.62 uncompressed (no SubjectPublicKeyInfo, no OCTET STRING
  wrapping — explicit clarification in `-13`).
- Ed25519/Ed448: 32/57 raw bytes (no OCTET STRING wrapping — `-13` fix).

Get this wrong and interop fails silently. The `-13` changelog is the
canonical list of "things implementers got wrong before."

### Signature

`signature BIT STRING` contains the DER `SEQUENCE` of two `BIT STRING`s:

```
CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
```

Hand-roll with the existing helpers in `scep_server.py`: `_seq`,
`_bit_string` (add this one — pattern follows `_octet_string`), `_encode_length`.

### Signing combiner

Per draft §4.2 with `-13` HPKE-style domain separators:

```
M' = Prefix || Domain || HashedAttrs(M)
sig_classical = Sign_classical(sk_classical, M')
sig_mldsa     = Sign_mldsa(sk_mldsa, M')
```

`Domain` is the HPKE label string for the composite OID (NOT the OID DER
bytes — that was the `-13` change). `Prefix` is constant
`"CompositeAlgorithmSignatures2025"` per draft §4.2.

The randomizer that existed in `-07`/`-08` has been removed since `-12`
(reverted to a HashComposite-like construction). Do not reintroduce it.

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `pki_server.py`   | `issue_composite_certificate()`, `verify_composite_signature()`, key gen, CertProfile entry, signing path |
| `composite.py`    | New module: combiner, OID table, key/sig serialization       |
| `scep_server.py`  | Add `_bit_string` helper (also useful elsewhere)             |
| `web_ui.py`       | Issuance form: dropdown adds composite key types             |
| `db_migrations/pki/00X_composite.sql` | None — `der BLOB` accommodates  |
| `test_pki_server.py` | `TestCompositeMLDSA`, `TestCompositeMLDSAInterop`         |
| `README.md`       | Protocol compliance row, CLI documentation                   |
| `CHANGELOG.md`    | `### Added`                                                  |

### CertProfile entry

Add near line 606 in `pki_server.py`:

```python
"composite_signing": CertProfile(
    key_usage=KeyUsage(digital_signature=True, ...),
    extended_key_usages=[],   # composite is a key type, not an EKU role
    validity_days=365,
    allowed_algorithms={"composite-mldsa44-rsa2048-pss",
                        "composite-mldsa44-ecdsa-p256",
                        "composite-mldsa65-ecdsa-p384",
                        "composite-mldsa87-ecdsa-p521"},
),
```

### Key generation

```python
def generate_composite_key(name: str) -> CompositeKey:
    classical = _gen_classical_for(name)
    mldsa     = _gen_mldsa_for(name)
    return CompositeKey(classical=classical, mldsa=mldsa, oid=COMPOSITE_OIDS[name])
```

Private key serialization: `OneAsymmetricKey` (RFC 5958) with the composite
OID, `privateKey` = `OCTET STRING` wrapping `SEQUENCE OF two OneAsymmetricKey`
entries per draft §6.2. PKCS#8 only — same RFC 5958 enforcement as the
rest of the codebase.

### TBSCertificate hand-rolling

Same approach as `issue_ml_dsa_certificate`: build TBS DER directly because
`cryptography` 48.0.0 `CertificateBuilder` doesn't accept composite keys.
Re-evaluate once upstream lands support — likely after the RFC publishes.

---

## CLI flags

```
--enable-composite-mldsa            # gate; default false until RFC publishes
--ca-key-type composite-mldsa44-rsa2048-pss
--ca-key-type composite-mldsa44-ecdsa-p256
--ca-key-type composite-mldsa65-ecdsa-p384
--ca-key-type composite-mldsa87-ecdsa-p521
```

`POST /api/issue` accepts `"key_type": "composite-mldsa65-ecdsa-p384"`.
No new endpoint — issuance is uniform across key types.

---

## Tests

```
class TestCompositeMLDSA(unittest.TestCase):
    def test_oid_table_matches_draft_18(self): ...
    def test_pubkey_concatenation_order(self): ...
    def test_signature_is_der_sequence_of_two_bit_strings(self): ...
    def test_domain_separator_is_hpke_label_not_oid_der(self): ...
    def test_no_randomizer_in_combiner(self): ...
    def test_classical_only_verify_fails_when_mldsa_corrupted(self): ...
    def test_mldsa_only_verify_fails_when_classical_corrupted(self): ...
    def test_pkcs8_private_key_round_trip(self): ...
    def test_certificate_signed_by_composite_ca_verifies(self): ...

class TestCompositeMLDSAInterop(unittest.TestCase):
    # Vector-based — pin against the draft's Appendix C test vectors
    def test_appendix_c_mldsa44_rsa2048_pss_vector(self): ...
    def test_appendix_c_mldsa65_ecdsa_p384_vector(self): ...
```

Interop targets once they exist: OpenCA `crypto-conditions`, BoringSSL
`bssl pq-x509`, Bouncy Castle composite branch. Track these in
`docs/INTEROP.md`.

---

## Per-change checklist

- [ ] `composite.py` — new module
- [ ] `pki_server.py` — issuance, verification, CertProfile, key gen wiring
- [ ] `scep_server.py` — `_bit_string` helper
- [ ] `web_ui.py` — UI dropdown
- [ ] `test_pki_server.py` — `TestCompositeMLDSA`, `TestCompositeMLDSAInterop`
- [ ] `README.md` — Protocol compliance row, CLI docs, PQC migration guide updates
- [ ] `CHANGELOG.md` — `### Added` under `## [Unreleased]`
- [ ] `pypki-flows.html` — composite issuance flow
- [ ] `docs/PQC.md` — composite vs RFC 9763 paired-cert tradeoffs

Run `./run_tests.sh`. Manual interop test against one external implementation
before flipping `--enable-composite-mldsa` default to true (do that only
after the RFC publishes).

---

## Migration plan when the RFC publishes

1. Re-fetch the OIDs from the published RFC; diff against `COMPOSITE_OIDS`.
2. If unchanged: flip default to true, update README compliance row from
   `draft-18` to `RFC NNNN`, CHANGELOG `### Changed`.
3. If OIDs shifted: bump `COMPOSITE_OIDS`, write a compatibility shim
   accepting old OIDs for verification only, log a deprecation warning.
   Six-month sunset window.

---

## Open questions

1. **CRL signing with composite keys**: a composite-signed CRL must be
   verifiable by relying parties that understand the algo. For the
   transition period, default the CA's CRL signing to the classical algo
   in the composite (i.e. CRL keeps validating in non-PQ-aware stacks)
   and offer `--composite-crl-signing` as an opt-in.

2. **OCSP responder signing**: same tradeoff. Default classical for
   compatibility; expose `--composite-ocsp-signing` opt-in.

3. **CMP/SCEP/EST issuance of composite EE certs**: enrollment protocols
   need to advertise the composite algo in their algorithm advertisement.
   CMP already does this (RFC 9481); add composite OIDs to the advertised
   list. EST `csrattrs` needs a draft-defined attribute — defer until the
   draft adds one or a user requests it.
