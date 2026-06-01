# PyPKI Service Guides

> Last reviewed: 2026-06-01 (commit 453e7ba)

Each guide answers "how do I deploy this specific service?" after PyPKI is
already installed. For installation, start with
[`docs/DEPLOYMENT/homelab-single-node.md`](../DEPLOYMENT/homelab-single-node.md).

## Service index

| Service | What it does | When to use it | RFC | Guide |
|---------|-------------|----------------|-----|-------|
| **ACME** | Automated certificate issuance via HTTPS challenge | certbot, acme.sh, cert-manager, Caddy | RFC 8555 | [acme.md](acme.md) |
| **SCEP** | Certificate enrolment for network devices | Cisco IOS, Windows devices, MDM systems | RFC 8894 | [scep.md](scep.md) |
| **EST** | Certificate enrolment over TLS with mTLS option | Linux devices, strongSwan, libest | RFC 7030 | [est.md](est.md) |
| **OCSP** | Online revocation checking | All TLS clients, browsers | RFC 6960 | [ocsp.md](ocsp.md) |
| **CMP** | CMPv2/v3 certificate management | VPN gateways, enterprise PKI clients | RFC 4210 / 9480 | [cmp.md](cmp.md) |
| **CRL** | Certificate Revocation List distribution | Offline validators, Windows, OpenSSL | RFC 5280 | [crl.md](crl.md) |
| **Web UI + REST** | Browser-based administration and REST API | Operators, automation scripts | — | [webui-rest.md](webui-rest.md) |
| **TSA** | RFC 3161 timestamp authority | Code signing, document signing | RFC 3161 | [tsa.md](tsa.md) |
| **S/MIME** | Email signing, encryption, and verification | Thunderbird, Outlook, email automation | RFC 8551 | [smime.md](smime.md) |

## Common starting point

Every service assumes PyPKI is installed and a CA is initialized:

```bash
# Install (from source)
pip install cryptography psycopg[binary]   # runtime deps only

# Initialize a CA
python3 pki_server.py --ca-dir /etc/pypki/ca --port 8080

# Confirm the CA is up
curl http://localhost:8080/health
```

Then pick the guide for the service you want to deploy.

## Systemd units

Pre-written systemd units for each service are in [`units/`](units/). Each
guide references the appropriate unit. The units use `DynamicUser=yes` and
the hardening from `docs/DEPLOYMENT/homelab-single-node.md`.

## Related docs

- [`docs/DEPLOYMENT/`](../DEPLOYMENT/) — topology-first installation guides
- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) — security analysis per service
- [`docs/PERFORMANCE.md`](../PERFORMANCE.md) — sizing numbers
- [`docs/MIGRATION.md`](../MIGRATION.md) — SQLite → Postgres migration
