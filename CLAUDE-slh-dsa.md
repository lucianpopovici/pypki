# CLAUDE-slh-dsa.md — SLH-DSA (FIPS 205) in X.509

Companion to `CLAUDE.md`. Follow all conventions there. Sibling work to the
ML-DSA support already in `pki_server.py` — same hand-rolled TBSCertificate
DER pattern, different algorithm family.

---

## What SLH-DSA is

FIPS 205 (Aug 2024), stateless hash-based signatures (SPHINCS+ family).
NIST's conservative PQ signature: no number-theoretic assumptions, only
preimage/collision resistance of the underlying hash. Designed as a
fallback if lattice problems turn out to be weaker than expected.

Twelve parameter sets across two hash families (SHA-2 and SHAKE) and three
security levels (128 / 192 / 256), each in "small" (`s`) and "fast" (`f`)
variants. Tradeoff: small signatures vs fast signing.

X.509 algorithm identifiers and SubjectPublicKeyInfo encodings: `draft-ietf-lamps-x509-slhdsa` (currently `-09`, June 2025).

---

## Cost: signature sizes

This is the headline tradeoff. SLH-DSA signatures are **large**.

| Parameter set        | Pub key | Priv key | Signature | Sign perf |
| -------------------- | ------- | -------- | --------- | --------- |
| SLH-DSA-SHA2-128s    | 32      | 64       | 7,856     | slow      |
| SLH-DSA-SHA2-128f    | 32      | 64       | 17,088    | fast      |
| SLH-DSA-SHA2-192s    | 48      | 96       | 16,224    | slow      |
| SLH-DSA-SHA2-192f    | 48      | 96       | 35,664    | fast      |
| SLH-DSA-SHA2-256s    | 64      | 128      | 29,792    | slow      |
| SLH-DSA-SHA2-256f    | 64      | 128      | 49,856    | fast      |

Bytes. SHAKE variants are the same sizes with SHA-2 swapped for SHAKE-256.

Implications:

- A 49KB signature on a leaf cert blows past common MTU paths; TLS 1.3
  ClientHello/ServerHello messages get fragmented. Document this in
  `docs/PQC.md` under deployment caveats.
- CRLs signed with SLH-DSA grow accordingly. For a CA with 10k revoked
  certs, the CRL signature alone is a meaningful fraction of total size.
- OCSP responses: 49KB is fine for HTTP but defeats stapling on most
  middleboxes. Recommend pairing SLH-DSA CA signing with **classical**
  OCSP responder cert signing for the transition period.

The `s`/`f` choice belongs to the operator. Default to `f` for CA keys
(signing happens rarely, verification often), `s` is reasonable for EE
certs where small-on-the-wire matters.

---

## Algorithm catalog

Ship all twelve parameter sets — they're cheap to add once the SHA-2 path
works, and operators will want the freedom to pick.

| Parameter set            | Family  | Security level | Variant |
| ------------------------ | ------- | -------------- | ------- |
| `slh-dsa-sha2-128s`      | SHA-2   | 128            | small   |
| `slh-dsa-sha2-128f`      | SHA-2   | 128            | fast    |
| `slh-dsa-sha2-192s`      | SHA-2   | 192            | small   |
| `slh-dsa-sha2-192f`      | SHA-2   | 192            | fast    |
| `slh-dsa-sha2-256s`      | SHA-2   | 256            | small   |
| `slh-dsa-sha2-256f`      | SHA-2   | 256            | fast    |
| `slh-dsa-shake-128s`     | SHAKE   | 128            | small   |
| `slh-dsa-shake-128f`     | SHAKE   | 128            | fast    |
| `slh-dsa-shake-192s`     | SHAKE   | 192            | small   |
| `slh-dsa-shake-192f`     | SHAKE   | 192            | fast    |
| `slh-dsa-shake-256s`     | SHAKE   | 256            | small   |
| `slh-dsa-shake-256f`     | SHAKE   | 256            | fast    |

OIDs: read from `draft-ietf-lamps-x509-slhdsa-09` §6. Same gating posture
as composite ML-DSA — keep `SLH_DSA_OIDS` table central, gate behind
`--enable-slh-dsa` until the draft publishes.

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `pki_server.py`   | `issue_slh_dsa_certificate()`, key gen, CertProfile entry, signing path |
| `slh_dsa.py`      | New module: parameter sets, OID table, FIPS 205 wrapper      |
| `web_ui.py`       | Issuance form dropdown                                       |
| `db_migrations/pki/00X_slh_dsa.sql` | None — `der BLOB` accommodates    |
| `test_pki_server.py` | `TestSLHDSAX509`, `TestSLHDSAInterop`                     |
| `README.md`       | Protocol compliance row, CLI documentation, signature-size caveats |
| `CHANGELOG.md`    | `### Added`                                                  |

### FIPS 205 implementation

No mature pure-Python SLH-DSA exists that's worth pulling in as a dep.
Options:

1. **stdlib + cryptography only**: implement FIPS 205 ourselves. ~1,500
   lines for all twelve parameter sets, well within the project's
   "stdlib-first" philosophy. Reference NIST test vectors.
2. **pyca/cryptography**: as of `48.0.0` no SLH-DSA support. Track upstream;
   when it lands, drop the in-house impl.
3. **liboqs via ctypes**: avoid — adds a C dependency, defeats the
   no-pip-deps principle and complicates packaging.

Pick option 1. The hash-tree construction is mechanical; the WOTS+ and
FORS pieces are well-specified. Reference impl: NIST PQC reference code,
`stdlib.hashlib` for SHA-2 and SHAKE-256.

Layout in `slh_dsa.py`:

```python
@dataclass(frozen=True)
class SLHDSAParams:
    name: str       # "slh-dsa-sha2-128f"
    n: int          # security parameter, bytes
    h: int          # total tree height
    d: int          # number of layers
    h_prime: int    # height of each subtree
    a: int          # FORS tree height
    k: int          # number of FORS trees
    lg_w: int       # Winternitz parameter exponent
    hash_family: str  # "sha2" | "shake"
    sig_size: int   # for sanity-check after sign

SLH_DSA_PARAMS: dict[str, SLHDSAParams] = { ... }  # all twelve

def keygen(params: SLHDSAParams, rng=os.urandom) -> tuple[bytes, bytes]: ...
def sign(params: SLHDSAParams, sk: bytes, msg: bytes,
         randomizer: bytes | None = None) -> bytes: ...
def verify(params: SLHDSAParams, pk: bytes, msg: bytes, sig: bytes) -> bool: ...
```

`randomizer=None` → deterministic mode (FIPS 205 §10.2). Default to
hedged mode (random `addrnd`) — it's strictly safer and the standard
recommends it.

### CertProfile entry

Add near line 606 in `pki_server.py`:

```python
"slh_dsa_signing": CertProfile(
    key_usage=KeyUsage(digital_signature=True, ...),
    extended_key_usages=[],
    validity_days=365,
    allowed_algorithms={f"slh-dsa-{f}-{lvl}{v}"
                        for f in ("sha2", "shake")
                        for lvl in ("128", "192", "256")
                        for v in ("s", "f")},
),
```

### TBSCertificate hand-rolling

`cryptography` 48.0.0 doesn't accept SLH-DSA public keys in
`CertificateBuilder`. Same workaround as ML-DSA: build TBS DER directly.
Refactor opportunity: extract the hand-rolling helpers from
`issue_ml_dsa_certificate` into a shared `_build_tbs_certificate(...)`
function so ML-DSA, SLH-DSA, and composite all share it.

### Storage and audit considerations

The `der BLOB` column accommodates SLH-DSA certs (largest cert with
SLH-DSA-256f signature: roughly 50KB). Verify SQLite default `SQLITE_MAX_LENGTH`
is sufficient (it's 1GB, so yes). Audit-log payloads stay text-only;
don't log the signature.

---

## CLI flags

```
--enable-slh-dsa                    # gate; default false until draft publishes
--ca-key-type slh-dsa-sha2-128s
--ca-key-type slh-dsa-sha2-128f
... (all twelve)
--slh-dsa-deterministic             # disable hedging (testing only)
```

`POST /api/issue` accepts `"key_type": "slh-dsa-sha2-192f"` etc.

---

## Tests

```
class TestSLHDSAX509(unittest.TestCase):
    def test_oid_table_matches_draft_09(self): ...
    def test_all_twelve_parameter_sets_keygen(self): ...
    def test_signature_sizes_match_fips_205(self): ...
    def test_pubkey_sizes_match_fips_205(self): ...
    def test_hedged_signing_produces_different_sigs(self): ...
    def test_deterministic_signing_is_reproducible(self): ...
    def test_certificate_chain_validates(self): ...
    def test_pkcs8_private_key_round_trip(self): ...

class TestSLHDSAInterop(unittest.TestCase):
    # NIST KAT (Known Answer Test) vectors
    def test_nist_kat_sha2_128f(self): ...
    def test_nist_kat_sha2_192s(self): ...
    def test_nist_kat_shake_256f(self): ...
    # Cross-verify a sig produced by liboqs (committed test vectors,
    # not a runtime dep)
    def test_liboqs_test_vector_sha2_128s(self): ...
```

NIST publishes KATs for all parameter sets; check them in under
`tests/vectors/slh_dsa/`. These are the canonical interop guarantee.

---

## Per-change checklist

- [ ] `slh_dsa.py` — new module, FIPS 205 implementation
- [ ] `pki_server.py` — issuance, CertProfile, key gen wiring,
      extract shared `_build_tbs_certificate`
- [ ] `web_ui.py` — UI dropdown
- [ ] `test_pki_server.py` — `TestSLHDSAX509`, `TestSLHDSAInterop`
- [ ] `tests/vectors/slh_dsa/` — NIST KATs
- [ ] `README.md` — Protocol compliance row, signature-size caveats
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `pypki-flows.html` — SLH-DSA issuance flow
- [ ] `docs/PQC.md` — when to choose ML-DSA vs SLH-DSA vs composite
- [ ] `docs/DEPLOYMENT.md` — MTU/fragmentation caveats for SLH-DSA chains

Run `./run_tests.sh`. NIST KAT tests are non-negotiable — failing means
the implementation is wrong, not flaky.

---

## Open questions

1. **CT logs and SLH-DSA**: pre-cert flows already shipped (RFC 6962).
   CT logs don't currently sign SCTs with PQ algorithms, but accept any
   leaf algorithm. Verify our pre-cert path produces a parseable leaf
   when the CA key is SLH-DSA; CT log will sign the SCT with whatever
   it uses (typically ECDSA P-256).

2. **OCSP responder signing**: same tradeoff as composite — large
   signatures hurt stapling. Default OCSP responder keys to classical
   even when the CA is SLH-DSA, unless `--slh-dsa-ocsp-signing` is set.

3. **CMP/SCEP/EST advertisement**: SLH-DSA OIDs in the algorithm
   advertisement list (CMP RFC 9481). SCEP `getCACaps` already advertises
   per `--scep-caps`; add the SLH-DSA capability tokens when CA key is
   SLH-DSA.

4. **HSM support**: PKCS#11 v3.1 added SLH-DSA mechanisms
   (`CKM_HSS_LMS_*` is a different algorithm — don't confuse them;
   SLH-DSA uses `CKM_SLH_DSA_*` per OASIS v3.1). Few HSMs implement it
   yet. `hsm_backend.py` should fall back to in-process signing for
   SLH-DSA until vendor support catches up — log a warning on startup.
