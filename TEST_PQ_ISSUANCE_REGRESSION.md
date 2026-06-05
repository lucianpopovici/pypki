# CLAUDE.md — PQ Issuance Audit Regression Coverage

## Purpose

Lock dead the `audit.record()` defect found in the validation run:
`issue_ml_dsa_certificate()`, `issue_composite()`, and `issue_slh_dsa()` passed
`requester_ip=requester_ip` (keyword) to `AuditLog.record()`, whose parameter is
positional `ip` — so **all three PQ issuance paths raised `TypeError` before
returning a cert**, via both the admin API and any internal caller. They were
non-functional and no test exercised them end-to-end. This adds coverage so the
regression cannot recur silently.

## Decide first: the canonical calling convention

The run fixed it by conforming the three callers to positional. Before writing the
test, confirm that is the intended direction and not the inverse:

- (A) callers pass `ip` positionally — `AuditLog.record(..., requester_ip)` *(run's fix)*
- (B) callers pass `ip=requester_ip` — keyword, correct name
- (C) `AuditLog.record` signature renamed to `requester_ip=` — then **all** callers
  of `record()` across the codebase must be audited, not just these three

The test below asserts **behavior** (cert returned + audit row written with the IP),
not how the argument is passed — so it survives any of A/B/C. But pick one as
canonical and note it, so the codebase is internally consistent.

## Placement

Merge into the existing `test_pki_server.py`. **Do not create a new test file** —
single-consolidated-test-file rule. Add as a new test class/section there.

## Confirm against source before pasting (anchors to resolve)

The skeleton uses placeholders. Replace each by reading the actual source; do not
assume these names:

- **CA construction**: the helper/fixture other `issue_*` tests use to build a
  `CertificateAuthority` (search the file for existing `issue_certificate` tests).
- **Method signatures**: exact names + required args of `issue_ml_dsa_certificate`,
  `issue_slh_dsa`, `issue_composite` (subject form? `requester_ip` param name?).
- **Audit accessors**: how to count / fetch the last audit entry and the field that
  holds the IP (`AuditLog` table/DAL — hand-rolled SQL, so likely a query helper).
- **OID constants**: import the OID constants PyPKI already defines per algorithm —
  do **not** hardcode dotted strings. (For reference only, to sanity-check the
  constants resolve to the right family: ML-DSA is the `2.16.840.1.101.3.4.3.{17,18,19}`
  arc, SLH-DSA the adjacent NIST arc, composite an implementation-chosen draft OID —
  confirm PyPKI's actual choices from source.)

## Test skeleton (unittest + subTest; zero new deps)

If `test_pki_server.py` is pytest-based, convert to `@pytest.mark.parametrize`. Kept
dependency-free here to honor the no-new-deps constraint.

```python
# --- PQ issuance audit-path regression -----------------------------------------
# Guards the audit.record() bug that silently broke issue_ml_dsa_certificate(),
# issue_slh_dsa(), and issue_composite(). Each path MUST return a real cert AND
# write an audit row. The bug raised TypeError at the audit.record() call, so a
# path that returns a parseable cert with a matching audit entry proves the fix.

from datetime import datetime, timezone  # if timestamps are asserted
from cryptography import x509

# CONFIRM imports against source:
#   from pki_server import CertificateAuthority, OID_ML_DSA_65, OID_SLH_DSA, OID_COMPOSITE
#   (use whatever the actual constant names are)

def _as_cert(result):
    """Normalize issuance return (DER bytes / PEM bytes / x509.Certificate) to a cert."""
    if isinstance(result, x509.Certificate):
        return result
    data = result if isinstance(result, (bytes, bytearray)) else getattr(result, "cert_der", None)
    if data is None:
        raise AssertionError("issuance returned no certificate material")
    try:
        return x509.load_der_x509_certificate(bytes(data))
    except ValueError:
        return x509.load_pem_x509_certificate(bytes(data))

class TestPQIssuanceAuditRegression(unittest.TestCase):

    def setUp(self):
        self.ca = make_test_ca()        # CONFIRM: reuse existing CA helper/fixture
        self.audit = self.ca.audit      # CONFIRM: audit accessor

    def _cases(self):
        # (label, issue_callable, expected_oid_constant)
        cn = "CN=pq-regression"
        return [
            ("ml_dsa",    lambda: self.ca.issue_ml_dsa_certificate(cn, requester_ip="127.0.0.1"), OID_ML_DSA_65),
            ("slh_dsa",   lambda: self.ca.issue_slh_dsa(cn, requester_ip="127.0.0.1"),            OID_SLH_DSA),
            ("composite", lambda: self.ca.issue_composite(cn, requester_ip="127.0.0.1"),          OID_COMPOSITE),
        ]   # CONFIRM every method name, arg name, and OID constant

    def test_pq_paths_issue_and_record_audit(self):
        for label, issue, expected_oid in self._cases():
            with self.subTest(path=label):
                before = self.audit.count()           # CONFIRM count API

                # The bug raised TypeError HERE. No exception == fix present.
                cert = _as_cert(issue())

                # 1. a real, parseable certificate came back
                self.assertIsInstance(cert, x509.Certificate)

                # 2. correct algorithm — compare to PyPKI's own OID constant
                self.assertEqual(
                    cert.signature_algorithm_oid.dotted_string,
                    expected_oid.dotted_string,
                )

                # 3. the audit path actually executed (bug crashed before this)
                self.assertEqual(self.audit.count(), before + 1)

                # 4. the entry carries the requester IP (convention-agnostic:
                #    asserts the recorded value, not how it was passed)
                last = self.audit.last()              # CONFIRM accessor + field
                self.assertEqual(last.ip, "127.0.0.1")
```

## Optional: API-path guard

The defect also 500'd the admin API issue endpoint. If `test_pki_server.py` has an
HTTP test client, add one case issuing ML-DSA via the API and assert a 2xx + a
parseable cert in the response. (The 201-vs-200 handling that bit the harness was a
*harness* bug, not PyPKI's — but a test asserting the endpoint returns success and a
cert guards the PyPKI side.) Skip if no client fixture exists rather than inventing
one.

## Why this catches the exact bug

The original defect raised `TypeError` at the `audit.record()` call inside each
method — so the method never returned. Assertion (3), the audit-row count, is the
precise guard: a cert can only come back *and* the count increment *only if* the
record call succeeded with correct arguments. Assertions (1)/(2) additionally pin
that the right algorithm was issued (catching the separate silent EC-fallback noted
in the run, if the path is invoked without a CSR and shouldn't downgrade).

## Success criteria

- All three subTests green against current source after the fix.
- Reverting the fix (restoring `requester_ip=` keyword) makes the test fail at
  `issue()` with `TypeError` for all three paths — verify this once to confirm the
  test actually guards the regression rather than passing vacuously.

## Non-goals
- No new test file; no new pip dependency.
- Not re-deciding the audit-record API here — that's the "decide first" step above;
  the test only encodes the resulting behavior.
- Silent EC fallback (issuing EC when an explicit PQ algorithm can't be honored) is
  noted but is a separate fix — consider erroring instead of downgrading; a dedicated
  test for that belongs with that change, not here.
