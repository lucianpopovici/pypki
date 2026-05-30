#!/usr/bin/env bash
# PyPKI ufw firewall setup script.
# Port matrix reference: CLAUDE-os-hardening-firewall.md
set -euo pipefail

ufw --force reset
ufw default deny incoming
ufw default deny outgoing

ufw allow in on lo
ufw allow out on lo

ufw allow from 10.0.0.0/8 to any port 22 proto tcp comment 'SSH from RFC1918'
ufw allow 80/tcp comment 'ACME http-01'
ufw allow 443/tcp comment 'HTTPS / Admin / OCSP / CRL'
ufw allow from 10.10.0.0/16 to any port 9090 proto tcp comment 'Prometheus'

ufw allow out 53 comment 'DNS'
ufw allow out 123/udp comment 'NTP'
ufw allow out 443/tcp comment 'HTTPS egress (KMS, OIDC)'
ufw allow out 80/tcp comment 'HTTP egress for OCSP/CRL upstream'
ufw allow out 5432/tcp comment 'Postgres'
ufw allow out 6432/tcp comment 'PgBouncer'

ufw logging medium
ufw --force enable
ufw status verbose
