# Deployment: homelab single-node

> Last reviewed: 2026-06-01 (commit 453e7ba)

This is the simplest PyPKI deployment: one host, one CA key, SQLite for storage, optional reverse proxy. It's what most people should start with — easy to set up, easy to back up, easy to understand. Migrate to a more elaborate topology only when you actually need to.

## What this gives you

- A working internal CA you can issue certs from in a few minutes
- CMP, ACME, SCEP, EST, OCSP, CRL endpoints all served from a single process
- Web UI for ad-hoc operations
- REST API for automation
- One file to back up: the CA directory

## What this does NOT give you

- Multi-node availability (only one PyPKI host)
- Hardware key protection (the CA key lives on the filesystem)
- Multi-operator separation (one operator account)
- Zero-downtime upgrades (PyPKI restart = brief unavailability)

For any of those, see the other deployment guides. For most homelabs and small teams, this topology is correct and sufficient.

## Prerequisites

- Linux host with Python 3.12+
- Hostname resolvable on your internal network (e.g., `pki.home.arpa`)
- Disk encryption at rest if the host has any chance of physical compromise (LUKS or equivalent)
- A backup target (another host, NAS, cloud bucket — separate from the CA host)

## Install

```bash
sudo useradd --system --home /var/lib/pypki --shell /usr/sbin/nologin pypki
sudo mkdir -p /var/lib/pypki/ca /etc/pypki
sudo chown -R pypki:pypki /var/lib/pypki
sudo chmod 700 /var/lib/pypki/ca

# Drop the PyPKI source into /opt/pypki (or wherever you prefer)
sudo mkdir -p /opt/pypki
sudo cp -r pypki-main/* /opt/pypki/
sudo chown -R root:root /opt/pypki

# Install Python deps
sudo python3 -m pip install -r /opt/pypki/requirements.txt
```

## CA passphrase

Generate a strong passphrase and store it in a password manager. The passphrase encrypts the CA private key on disk. **There is no recovery if you lose it** — the CA is gone.

```bash
# Pick something with at least 25 characters of entropy:
openssl rand -base64 32
```

Put it in a passphrase file readable only by the pypki user. **Do not put it in CLI args (visible in `ps`).** The PyPKI server reads `PYPKI_CA_PASSPHRASE` from the environment.

```bash
sudo install -m 600 -o pypki -g pypki /dev/null /etc/pypki/passphrase
# Open the file in an editor and paste the passphrase, then save and quit:
sudo -u pypki vi /etc/pypki/passphrase
```

## systemd service

```ini
# /etc/systemd/system/pypki.service
[Unit]
Description=PyPKI server (homelab single-node)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pypki
Group=pypki
WorkingDirectory=/var/lib/pypki

# Read the passphrase from a file the service user owns, NOT from CLI.
EnvironmentFile=-/etc/pypki/passphrase.env

# Adjust ports and prefixes for your network policy.
ExecStart=/usr/bin/python3 /opt/pypki/pki_server.py \
    --ca-dir /var/lib/pypki/ca \
    --tls-port 8443 \
    --cmp-prefix /cmp \
    --acme-prefix /acme \
    --ocsp-prefix /ocsp \
    --scep-prefix /scep \
    --est-prefix /.well-known/est \
    --ipsec-prefix /ipsec \
    --web-ui \
    --cps-uri https://pki.home.arpa/cps.txt \
    --cps-policy-oid 1.3.6.1.4.1.<YOUR_PEN>.1.1 \
    --ocsp-require-nonce \
    --log-level INFO

Restart=on-failure
RestartSec=10s

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/pypki
PrivateTmp=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
```

Note the `EnvironmentFile=-/etc/pypki/passphrase.env`. The format of that file is:

```
# /etc/pypki/passphrase.env  —  mode 600, owned by pypki:pypki
PYPKI_CA_PASSPHRASE=your-actual-passphrase-here
```

Then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable pypki
sudo systemctl start pypki
sudo systemctl status pypki
```

## Reverse proxy (recommended)

Putting nginx in front gives you HTTP→HTTPS upgrade, well-known cert termination using PyPKI itself (chicken-and-egg avoided by initial bootstrap with self-signed), and easier multi-vhost handling.

```nginx
# /etc/nginx/sites-available/pypki
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name pki.home.arpa;

    ssl_certificate     /etc/nginx/certs/pki.home.arpa.crt;
    ssl_certificate_key /etc/nginx/certs/pki.home.arpa.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Health check
    location = /healthz {
        proxy_pass http://127.0.0.1:8443/healthz;
        access_log off;
    }

    # All PyPKI endpoints
    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SCEP and CMP can have larger payloads
        client_max_body_size 1m;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name pki.home.arpa;
    return 301 https://$host$request_uri;
}
```

The reverse proxy itself needs a TLS cert. Bootstrap it self-signed for the first 24 hours, then re-issue it from PyPKI itself once PyPKI is running:

```bash
# After PyPKI is running, issue nginx's own cert from PyPKI:
curl -sS -X POST https://pki.home.arpa/api/issue \
  -H "X-API-Key: $PYPKI_API_KEY" \
  -d '{"subject": "CN=pki.home.arpa", "san_dns": ["pki.home.arpa"], "validity_days": 90}' \
  | jq -r .cert_pem > /etc/nginx/certs/pki.home.arpa.crt

# Reload nginx:
sudo systemctl reload nginx
```

Set up cert-manager-style auto-renewal via cron or a systemd timer.

## Backups

The single most important operational discipline. **Back up `/var/lib/pypki` every day.**

```bash
# /etc/cron.daily/pypki-backup
#!/bin/bash
set -euo pipefail

BACKUP_DIR=/srv/backups/pypki
DATE=$(date +%Y%m%d)
mkdir -p "$BACKUP_DIR"

# Stop the service for a consistent snapshot of all four DBs.
# A few seconds of downtime is acceptable.
systemctl stop pypki
tar czf "$BACKUP_DIR/pypki-$DATE.tar.gz" -C /var/lib pypki/
systemctl start pypki

# Encrypt the backup with a key OFF the CA host.
gpg --encrypt --recipient backup@home.arpa "$BACKUP_DIR/pypki-$DATE.tar.gz"
rm "$BACKUP_DIR/pypki-$DATE.tar.gz"

# Sync to off-host storage.
rsync -av --remove-source-files "$BACKUP_DIR/" backup-host:/srv/pypki-backups/

# Keep 30 days of local snapshot history if you want.
find /srv/backups/pypki/ -name "pypki-*.tar.gz.gpg" -mtime +30 -delete
```

**Test your backups** by restoring to a throwaway VM at least once a year. A backup you've never restored is an aspiration, not a backup.

The CA passphrase is part of the recovery package but **MUST be backed up separately** (different storage, different access controls). Losing the passphrase is equivalent to losing the CA.

## Initial CA bootstrap

The first time PyPKI starts, it generates a CA key and self-signs a CA cert. This is fine for homelab use. After it starts:

```bash
# Confirm the CA started and the API works
curl https://pki.home.arpa/healthz

# Pull the CA cert (distribute to your devices' trust stores)
curl https://pki.home.arpa/ca.crt > /tmp/home-ca.crt

# Add to system trust store on Linux:
sudo cp /tmp/home-ca.crt /usr/local/share/ca-certificates/home-ca.crt
sudo update-ca-certificates
```

For other OSes, see your platform's docs for adding a custom CA. macOS: Keychain Access. Windows: certmgr.msc. iOS: install via configuration profile then enable in Settings > General > About > Certificate Trust Settings. Android: install via Settings > Security > Encryption & credentials > Install a certificate (caveat: many apps now ignore user-installed CAs unless they opt in via Network Security Config).

## Operations checklist

| Frequency | Task |
|---|---|
| On every release | Read CHANGELOG, run `pytest test_pki_server.py` against the new version, then upgrade |
| Daily | Backups (automated above), check `journalctl -u pypki` for errors |
| Weekly | Review the audit log for anomalous issuance: `sqlite3 /var/lib/pypki/ca/audit.db 'SELECT ts, event, detail FROM audit ORDER BY id DESC LIMIT 100'` |
| Monthly | Review issued cert inventory; revoke any that are no longer needed |
| Quarterly | Test backup restore to a throwaway VM |
| Yearly | Rotate the CA passphrase if your policy requires it (run `--rotate-ca-passphrase`); review the CPS document for accuracy |
| 1 year before CA cert expiry | Plan and execute CA cert renewal — distribute new cert before the old one expires |

## What you should monitor

At minimum:
- `pypki.service` is running (Systemd unit health, alert on `failed`)
- HTTPS endpoint returns 200 (`curl https://pki.home.arpa/healthz`)
- OCSP responder returns a fresh response for a known cert
- Backup completed successfully today
- Audit log size growing as expected (if growth stops, something stopped writing audit events)
- CRL `nextUpdate` is in the future (a stale CRL means CRL generation is failing silently)

If you're using Prometheus, PyPKI exposes `/metrics` (RFC 4 — Prometheus format). Set up basic alerts on:
- `pypki_certificate_issued_total` rate (sudden spike = possible compromise; flat zero for >24h = something broken)
- `pypki_revoked_certificates_total` rate
- `pypki_ca_cert_expiry_seconds` — alert when this falls below 6 months
- `pypki_ocsp_requests_total{status="malformed"}` — sudden growth = misbehaving client or attack

## When to graduate from this topology

This topology is fine until one of these is true:
- You need PyPKI to keep working through a host failure → migrate to multi-node Postgres backend
- You need to comply with controls that require key separation → migrate to offline-root-online-subca topology
- You have personnel turnover that requires multi-operator separation → wait for Tier 5.4 RA workflow, or implement process-level controls
- You're issuing for a Kubernetes cluster → keep this PyPKI as the root, add the [kubernetes-cert-manager.md](kubernetes-cert-manager.md) deployment alongside

## References

- [CPS.md](../CPS.md) — Certification Practice Statement template
- [THREAT_MODEL.md](../THREAT_MODEL.md) — adversary model
- [kubernetes-cert-manager.md](kubernetes-cert-manager.md) — adding k8s issuance on top of this
