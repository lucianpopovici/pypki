# PyPKI Interop Test Suite

Proves every protocol PyPKI claims is wire-compatible with independent
reference clients. Unit tests prove self-consistency; this suite proves
real-world compatibility.

## Running the suite

```bash
# Full required matrix
./interop/run_all.sh

# Single protocol
bash interop/scep/run.sh
bash interop/acme/certbot/run.sh
bash interop/cmp/run.sh

# With best-effort protocols
./interop/run_all.sh --include-best-effort
```

## Prerequisites

- Docker and docker compose
- `openssl` ≥ 3.0 (for CMP, OCSP, TSA, CRL, S/MIME tests)
- `sscep` (for SCEP; built in Docker container)
- `certbot`, `acme.sh`, `lego` (in Docker containers)

No reference client is installed on the host. All clients run in their
Docker containers. PyPKI starts fresh (ephemeral CA) for each test.

## Protocol coverage

| Protocol   | Reference client(s)                       | Status    |
| ---------- | ----------------------------------------- | --------- |
| SCEP       | `sscep`                                   | Required  |
| ACME       | `certbot`, `acme.sh`, `lego`, `caddy`     | Required  |
| EST        | `libest` / `estclient`                    | Required  |
| CMP        | `openssl cmp` (≥ 3.0)                     | Required  |
| OCSP       | `openssl ocsp`                            | Required  |
| TSA        | `openssl ts`                              | Required  |
| CRL        | `openssl crl`                             | Required  |
| S/MIME     | `openssl cms`                             | Required  |
| ML-DSA     | `openssl` + oqs-provider                  | Required  |
| PKCS#12    | `openssl pkcs12`                          | Required  |
| SCEP+NDES  | Microsoft NDES (manual)                   | Known gap |
| S/MIME+MUA | Thunderbird / Outlook (manual)            | Best-effort|

## Conventions

- **Idempotent**: each `run.sh` tears down and rebuilds state on every run.
- **No external network**: all clients talk to local PyPKI only.
- **One trust anchor per test**: PyPKI starts fresh and mints its CA.
- **Wire captures on failure**: failed runs dump request/response to
  `interop/<proto>/_failures/<ts>/`.

## Findings workflow

Each interop bug produces:
1. Captured request/response DER (in `_failures/<ts>/`).
2. A regression test in `test_pki_server.py` (`TestTier6Interop<proto>`).
3. A fix in the protocol module.
4. A note in `INTEROP_MATRIX.md`.

## Status tracking

See [`INTEROP_MATRIX.md`](./INTEROP_MATRIX.md) for current pass/fail state.
