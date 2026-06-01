# PyPKI Interop Matrix

Current pass/fail status for every protocol claim. Updated after each test run.

**Legend**: ✓ = green, ✗ = failing, · = manual/not-yet-run, — = known gap

## Required protocols

| Protocol | Operation            | Client              | Status | Notes |
| -------- | -------------------- | ------------------- | ------ | ----- |
| SCEP     | getca                | sscep 0.5.x         | ·      | Not yet run |
| SCEP     | getcacert            | sscep               | ·      | Not yet run |
| SCEP     | enroll               | sscep               | ·      | Not yet run |
| SCEP     | renew                | sscep               | ·      | Not yet run |
| ACME     | http-01              | certbot             | ·      | Not yet run |
| ACME     | dns-01               | certbot             | ·      | Not yet run |
| ACME     | http-01              | acme.sh             | ·      | Not yet run |
| ACME     | http-01              | lego                | ·      | Not yet run |
| ACME     | http-01              | caddy               | ·      | Not yet run |
| ACME     | EAB                  | certbot             | ·      | Not yet run |
| ACME     | STAR renewal         | certbot             | ·      | Not yet run |
| ACME     | revoke               | certbot             | ·      | Not yet run |
| EST      | cacerts              | libest estclient    | ·      | Not yet run |
| EST      | simpleenroll         | libest estclient    | ·      | Not yet run |
| EST      | simplereenroll       | libest estclient    | ·      | Not yet run |
| EST      | csrattrs             | libest estclient    | ·      | Not yet run |
| CMP      | ir (init request)    | openssl cmp         | ·      | Not yet run |
| CMP      | cr (cert request)    | openssl cmp         | ·      | Not yet run |
| CMP      | kur (key update)     | openssl cmp         | ·      | Not yet run |
| CMP      | rr (revoke)          | openssl cmp         | ·      | Not yet run |
| CMP      | genm (alg advert)    | openssl cmp         | ·      | Not yet run |
| OCSP     | live response        | openssl ocsp        | ·      | Not yet run |
| OCSP     | pre-generated        | openssl ocsp        | ·      | Not yet run |
| OCSP     | nonce                | openssl ocsp        | ·      | Not yet run |
| TSA      | sign                 | openssl ts          | ·      | Not yet run |
| TSA      | verify               | openssl ts          | ·      | Not yet run |
| TSA      | policy-OID match     | openssl ts          | ·      | Not yet run |
| CRL      | parse                | openssl crl         | ·      | Not yet run |
| CRL      | signature validate   | openssl crl         | ·      | Not yet run |
| S/MIME   | sign                 | openssl cms         | ·      | Not yet run |
| S/MIME   | verify               | openssl cms         | ·      | Not yet run |
| S/MIME   | encrypt              | openssl cms         | ·      | Not yet run |
| ML-DSA   | verify cert chain    | openssl+oqs-provider| ·     | Not yet run |
| PKCS#12  | import/export        | openssl pkcs12      | ·      | Not yet run |

## Known gaps (permanent, documented)

| Protocol | Gap | Rationale |
| -------- | --- | --------- |
| SCEP+NDES | Microsoft NDES interop | Requires Windows test lab; not automatable |
| S/MIME+MUA | Thunderbird/Outlook | Manual test only; documented in MANUAL_RUNBOOK.md |

## Last full run

Not yet run. Run `./interop/run_all.sh` to populate this table.
