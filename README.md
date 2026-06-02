# PyPKI — Private PKI Server

> Last reviewed: 2026-06-02

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)

A self-contained, production-grade private Certificate Authority. Supports
**CMPv2/v3** (RFC 4210 / RFC 9480), **ACME** (RFC 8555), **SCEP** (RFC 8894),
**EST** (RFC 7030), **OCSP** (RFC 6960), **TSA** (RFC 3161), **S/MIME** (RFC 8551),
**WireGuard PKI**, **Matter DAC/PAI/PAA** (CSA spec §6.2.2), plus
cloud KMS, multi-tenancy, OIDC SSO, and a code-signing portal with
in-toto/DSSE attestations and a Merkle transparency log.

No runtime dependencies beyond `cryptography` and `psycopg3` (PostgreSQL only).

---

## Documentation

| Doc | Description |
|-----|-------------|
| **[docs/HOWTO/](docs/HOWTO/README.md)** | Protocol server setup guides — ACME, SCEP, EST, OCSP, CMP, CRL, Web UI, TSA, S/MIME |
| [docs/DEPLOYMENT/](docs/DEPLOYMENT/) | Topology install guides — homelab, Kubernetes, offline root, VPN, IoT |
| [docs/SSO.md](docs/SSO.md) | OIDC SSO setup — Keycloak, Okta, Entra ID, Google Workspace |
| [docs/PORTAL.md](docs/PORTAL.md) | Self-service cert portal — ownership model, renewal, revocation |
| [docs/KMS.md](docs/KMS.md) | Cloud KMS — AWS KMS, GCP Cloud KMS, Azure Key Vault |
| [docs/MULTITENANCY.md](docs/MULTITENANCY.md) | Multi-tenancy — isolation model, tenant CRUD, quotas, routing |
| [docs/WIREGUARD.md](docs/WIREGUARD.md) | WireGuard peer identity registry and config distribution |
| [docs/MATTER.md](docs/MATTER.md) | Matter DAC/PAI/PAA device attestation certs |
| [docs/CODESIGN.md](docs/CODESIGN.md) | Code-signing portal with in-toto/DSSE attestations and Merkle log |
| [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) | Terraform provider, cert-manager, Vault PKI, Prometheus |
| [docs/AGILITY.md](docs/AGILITY.md) | Crypto-agility dashboard — PQ migration tracker and forecasting |
| [docs/BACKUP.md](docs/BACKUP.md) | Backup and restore procedures |
| [docs/DR.md](docs/DR.md) | Disaster recovery runbooks |
| [docs/CEREMONY.md](docs/CEREMONY.md) | Offline root key ceremony |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Security analysis: trust boundaries, adversary model |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Issuance throughput, OCSP latency, storage growth |
| [docs/STORAGE.md](docs/STORAGE.md) | SQLite vs PostgreSQL backends, HA topology |
| [docs/MIGRATION.md](docs/MIGRATION.md) | SQLite → Postgres migration runbook |
| [docs/CPS.md](docs/CPS.md) | Certification Practice Statement template (RFC 3647) |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

---

## Features

### Core PKI
- Self-signed RSA-4096 root CA, auto-generated on first run; ECDSA and Ed25519 CA keys supported
- Intermediate CA mode — full chain served across all protocols
- SQLite (default) and PostgreSQL backends; DAL with advisory locks for race-free serial allocation
- Eight built-in certificate profiles (`tls_server`, `tls_client`, `code_signing`, `email_signing`, `ocsp_signing`, `sub_ca`, `short_lived`, `default`) plus Matter and ephemeral profiles
- RFC 9608 `noRevAvail` for short-lived certs (CDP and AIA-OCSP auto-suppressed)
- RFC 9336 `document_signing` profile (id-kp-documentSigning)
- RFC 4158 AIA `caIssuers` path-building pointer
- Name constraints for technically-constrained sub-CAs
- CertificatePolicies with CPS URI and UserNotice (RFC 5280 §4.2.1.4 / RFC 6818)
- IDNA: U-label DNS → A-label; `SmtpUTF8Mailbox` for non-ASCII email (RFC 9549/9598)
- Key archival / key escrow (AES-256-CBC encrypted)
- Certificate Transparency: pre-cert flow + SCT embedding (RFC 6962)
- Policy engine: JSON policy-as-code, 13 match predicates, hot-reload via SIGHUP

### Protocols
- **CMPv2/v3** (RFC 4210 / RFC 9480/9481/9482/9811) — ir/cr/kur/rr/certConf/genm, all CMPv3 extensions
- **ACME** (RFC 8555) — http-01/dns-01/tls-alpn-01, IP identifiers (RFC 8738), STAR (RFC 8739), ARI (RFC 9773), .onion (RFC 9799, gated)
- **SCEP** (RFC 8894) — compatible with Cisco IOS, Intune, Jamf, sscep; OTP challenge mode
- **EST** (RFC 7030) — cacerts/simpleenroll/simplereenroll/csrattrs/serverkeygen; HTTP Basic + mTLS
- **OCSP** (RFC 6960 / RFC 5019) — POST and GET bindings; nonce enforcement; pre-computed responses
- **TSA** (RFC 3161 / RFC 5816) — SHA-256/384/512; `signingCertificateV2` signed attribute
- **S/MIME** (RFC 8551) — CMS sign/verify/encrypt/decrypt; RSA-OAEP, ECDH, AES-256-GCM
- **IPsec PKI** (RFC 4945 / RFC 4806 / RFC 4809) — three profiles, approval queue, IKEv2 inline OCSP

### Post-quantum
- **ML-DSA** (FIPS 204) — `issue_ml_dsa_certificate()`, ML-DSA-44/65/87; hand-rolled TBSCertificate DER
- **SLH-DSA** (FIPS 205) — leaf certs, gated (`--enable-slh-dsa`; requires `pip install slh-dsa`)
- **Composite ML-DSA** (draft-ietf-lamps-pq-composite-sigs) — gated (`--enable-composite-mldsa`)
- **RFC 9763** — Related Certificates for paired classical + ML-DSA certs

### Platform features
- **OIDC SSO** — Authorization Code + PKCE (RFC 7636); RS256/ES256/EdDSA JWS; JWKS cache; role mapping; DB-backed sessions; Bearer token API access
- **Self-service portal** — per-user scoped cert view/renewal/revocation; ownership model; static mappings; profile-level gates
- **Code-signing portal** — in-toto/DSSE attestations; OIDC CI identity; ephemeral signing certs (10 min); RFC 6962 Merkle transparency log with inclusion proofs
- **Multi-tenancy** — `TenantScopedConnection` DAL layer; URL path and DNS routing; quota enforcement; tenant CRUD admin CLI
- **Crypto-agility dashboard** — DER-based classifier, aggregator, migration forecaster, Prometheus sweeper; Grafana dashboard
- **Cloud KMS** — AWS KMS (SigV4), GCP Cloud KMS (OAuth2), Azure Key Vault (AAD); no pip deps
- **WireGuard PKI** — Curve25519 peer registry, config distribution, pull-mode sync agent
- **Matter certs** — DAC/PAI/PAA with vendor/product OIDs; ECDSA P-256 enforced; bulk NDJSON streaming

### Operations
- First-run bootstrap CLI (`pypki_init.py`) — homelab 6-step and enterprise wizard
- Systemd hardening (AppArmor, seccomp, CapabilityBoundingSet)
- Preflight check runner — 8 check modules, Prometheus output
- 11-state upgrade state machine with transactional migrations and canary health window
- Backup/restore: AES-256-GCM + scrypt, Ed25519-signed manifests, Shamir M-of-N passphrase
- Audit chain: tamper-evident hash-chained audit log
- Lifecycle webhooks (cert.issued, cert.revoked, cert.expiring, ...)
- Prometheus metrics + Grafana dashboards; OpenTelemetry tracing
- OpenAPI 3.0 spec at `GET /api/openapi.json`; `/api/v1/` versioned prefix

---

## Requirements

```bash
pip install cryptography
# PostgreSQL deployments only:
pip install 'psycopg[binary]'
```

Python 3.12+.

---

## Quick start

```bash
# Development — plain HTTP, auto-generated RSA-4096 CA
python pki_server.py

# TLS + single-port dispatcher with web UI, ACME, SCEP, EST, OCSP
python pki_server.py \
  --tls --port 8443 \
  --web-prefix / \
  --acme-prefix /acme \
  --scep-prefix /scep \
  --est-prefix /est \
  --ocsp-prefix /ocsp \
  --ocsp-url http://pki.internal:8443/ocsp \
  --crl-url  http://pki.internal:8443/ca/crl \
  --ca-issuers-url http://pki.internal:8443/ca/ca.crt

# First-run wizard (enterprise mode)
python pypki_init.py --enterprise

# Admin CLI: list subcommands
python pypki_admin.py --help
```

See **[docs/HOWTO/](docs/HOWTO/README.md)** for per-protocol setup guides.

---

## CA directory layout

```
ca/
├── ca.key              CA private key (keep secret; back up off-site)
├── ca.crt              CA certificate (distribute to clients)
├── ca-chain.pem        Parent chain (intermediate CA mode)
├── ca.crl              Certificate Revocation List
├── certificates.db     SQLite: all issued certificates (main PKI DB)
├── acme.db             SQLite: ACME accounts, orders, challenges
├── scep.db             SQLite: SCEP enrolment transactions
├── audit.db            Structured audit log (tamper-evident hash chain)
├── ocsp.key / ocsp.crt OCSP signing key + cert (auto-issued, 30-day)
└── config.json         Live server configuration (hot-reloadable)
```

> **Security:** `ca.key` is stored unencrypted by default. Use `--hsm-module`
> for PKCS#11 or `--ca-key-backend aws-kms|gcp-kms|azure-kv` for cloud KMS
> to keep the key off disk. See [docs/KMS.md](docs/KMS.md).

---

## Testing

```bash
./run_tests.sh
# or
python -m pytest test_pki_server.py -v
```

1222 tests across 90+ test classes. 2 Postgres-gated tests skip without
`PYPKI_TEST_POSTGRES_DSN`.

---

## License

MIT — see [LICENSE](LICENSE).
