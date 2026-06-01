# PyPKI — Dependency License Inventory

Every dependency used by PyPKI (runtime and dev) is listed here. When adding
a new dependency, update this file in the same PR. CI blocks merges that add
a package without a license entry.

## Runtime dependencies (`requirements.txt`)

| Package         | Version (pinned) | License           | Notes                                       |
| --------------- | ---------------- | ----------------- | ------------------------------------------- |
| `cryptography`  | ≥ 41.0           | Apache 2.0 / BSD  | Core crypto; backed by OpenSSL (Apache 2.0) |
| `psycopg`       | ≥ 3.0 (optional) | LGPL 3+           | Postgres driver; optional runtime dep       |
| `psycopg-pool`  | ≥ 3.0 (optional) | LGPL 3+           | Connection pool for psycopg; optional       |
| `pyasn1`        | ≥ 0.5 (optional) | BSD 2-Clause      | ASN.1 types used by cmp_server.py           |
| `pyasn1-modules`| ≥ 0.3 (optional) | BSD 2-Clause      | ASN.1 module definitions; used with pyasn1  |

## Development / test dependencies (`requirements-dev.txt`)

| Package          | Version | License       | Notes                                       |
| ---------------- | ------- | ------------- | ------------------------------------------- |
| `pytest`         | ≥ 7.4   | MIT           | Test runner                                 |
| `playwright`     | ≥ 1.40  | Apache 2.0    | Browser-based UI tests                      |
| `requests`       | ≥ 2.31  | Apache 2.0    | HTTP client for interop tests               |
| `urllib3`        | ≥ 2.0   | MIT           | HTTP library (requests dependency)          |
| `atheris`        | ≥ 2.3   | Apache 2.0    | libFuzzer Python bindings (optional)        |
| `pip-audit`      | ≥ 2.7   | Apache 2.0    | Vulnerability scanner                       |
| `cyclonedx-bom`  | ≥ 4.0   | Apache 2.0    | SBOM generator                              |
| `coverage`       | ≥ 7.4   | Apache 2.0    | Code coverage measurement                   |
| `mypy`           | ≥ 1.8   | MIT           | Static type checker                         |

## Third-party test data

| Resource                     | License       | Location                        |
| ---------------------------- | ------------- | ------------------------------- |
| NIST PKITS corpus            | Public domain | `conformance/pkits/data/`       |
| BetterTLS test cases         | MIT           | `conformance/bettertls/`        |

## Transitive dependencies

Transitive deps inherit from their root package's license. The SBOM
(generated at release time) captures the full closure with hashes.
The `pip-audit` scan covers transitive deps for known CVEs.

## Policy

- GPL dependencies are not permitted in runtime `requirements.txt`.
  LGPL is acceptable for optional runtime deps (psycopg) because PyPKI
  does not link them statically and they are used through the standard
  Python import mechanism.
- Any change to the license of an existing dep must be flagged in the PR
  description.
- New deps require explicit license review in the PR. Security-sensitive
  packages (crypto, ASN.1 parsing) require maintainer approval.
