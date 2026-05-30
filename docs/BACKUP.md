# PyPKI Backup and Restore

Operational guide for the backup system introduced in `CLAUDE-backup-restore.md`.

---

## Backup format

A backup is a gzip tarball named `pypki-backup-<timestamp>.tar.gz` (or `.tar.gz.enc`
if encrypted) with the following layout:

```
pypki-backup-<ts>/
  manifest.json       — SHA-256 hashes of every file, signing pubkey, created_at
  signature           — Ed25519 signature over manifest.json bytes
  db/
    pki.sql.gz        — SQLite dump of certificates.db (gzipped SQL)
    acme.sql.gz       — (if present)
    scep.sql.gz       — (if present)
    est.sql.gz        — (if present)
  keys/
    ca.key.pem        — CA private key (already passphrase-encrypted)
  config/
    config.yaml       — server config (if present)
  audit-seal.json     — latest audit_log id + chain_hash at backup time
```

`manifest.json` lists the SHA-256 of every file. `signature` is an Ed25519 signature
over the manifest bytes. Any change to any file invalidates the signature.

**Encryption (optional):** The whole tarball is wrapped with AES-256-GCM + scrypt
(N=2¹⁷, r=8, p=1 per RFC 7914). Encrypted backups have `.enc` extension.

---

## Setup

### 1. Create a backup passphrase (optional but recommended)

```bash
# Generate a random passphrase and store it securely
openssl rand -base64 32 > /etc/pypki/backup.passphrase
chmod 600 /etc/pypki/backup.passphrase
chown pypki:pypki /etc/pypki/backup.passphrase
```

### 2. Create the backup target directory

```bash
mkdir -p /var/lib/pypki/backups
chown pypki:pypki /var/lib/pypki/backups
chmod 700 /var/lib/pypki/backups
```

### 3. Take a manual backup to verify the setup

```bash
python pypki_admin.py backup-now \
    --ca-dir /var/lib/pypki/ca \
    --target file:///var/lib/pypki/backups/ \
    --passphrase-file /etc/pypki/backup.passphrase
```

Expected output:
```
Backup created: /var/lib/pypki/backups/pypki-backup-20260525T030000Z.tar.gz.enc
```

### 4. Verify the backup

```bash
python -c "
from pathlib import Path
from backup import BackupConfig, BackupEngine
from db import make_db

config = BackupConfig(
    targets=('file:///var/lib/pypki/backups/',),
    passphrase=open('/etc/pypki/backup.passphrase','rb').read().rstrip(b'\n'),
    retention_count=30, retention_days=90,
)
engine = BackupEngine(
    ca_dir=Path('/var/lib/pypki/ca'),
    db=make_db('sqlite:///var/lib/pypki/ca/certificates.db'),
    config=config,
)
manifest = engine.verify_backup(Path('/var/lib/pypki/backups/<filename>.tar.gz.enc'))
print('OK — manifest version', manifest['format_version'])
"
```

### 5. Schedule with cron

```cron
# Daily backup at 03:00, retain 30 copies, delete after 90 days
0 3 * * * pypki python /opt/pypki/pypki_admin.py backup-now \
    --ca-dir /var/lib/pypki/ca \
    --target file:///var/lib/pypki/backups/ \
    --passphrase-file /etc/pypki/backup.passphrase \
    >> /var/log/pypki/backup.log 2>&1
```

### 6. Schedule with systemd timer

`/etc/systemd/system/pypki-backup.service`:
```ini
[Unit]
Description=PyPKI daily backup

[Service]
Type=oneshot
User=pypki
ExecStart=/usr/bin/python /opt/pypki/pypki_admin.py backup-now \
    --ca-dir /var/lib/pypki/ca \
    --target file:///var/lib/pypki/backups/ \
    --passphrase-file /etc/pypki/backup.passphrase
StandardOutput=journal
StandardError=journal
```

`/etc/systemd/system/pypki-backup.timer`:
```ini
[Unit]
Description=Daily PyPKI backup

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now pypki-backup.timer
```

---

## Restore

### Full restore

```bash
# 1. Stop the running server
systemctl stop pypki

# 2. Dry-run to verify integrity (no files written)
python pypki_admin.py restore \
    --from /var/lib/pypki/backups/pypki-backup-<ts>.tar.gz.enc \
    --to /var/lib/pypki-staging \
    --passphrase-file /etc/pypki/backup.passphrase \
    --dry-run

# 3. Full restore to staging directory
python pypki_admin.py restore \
    --from /var/lib/pypki/backups/pypki-backup-<ts>.tar.gz.enc \
    --to /var/lib/pypki-staging \
    --passphrase-file /etc/pypki/backup.passphrase

# 4. Verify audit chain in the restored DB
python pypki_admin.py audit-verify \
    --ca-dir /var/lib/pypki-staging

# 5. Promote staging to live (atomic directory swap)
mv /var/lib/pypki/ca /var/lib/pypki/ca.incident-$(date +%Y%m%d)
mv /var/lib/pypki-staging/db/pki.sql.gz /tmp/  # (or restore SQL directly)

# See docs/DR.md for the full procedure with exact commands.

# 6. Start the server
systemctl start pypki
```

### DB-only restore (preserve existing keys)

Use when the DB is corrupted but the CA keys on the live system are intact:

```bash
python pypki_admin.py restore \
    --from /var/lib/pypki/backups/pypki-backup-<ts>.tar.gz \
    --to /var/lib/pypki-staging \
    --db-only
```

### Selective table restore (leaf compromise)

Restore only `certificates` and `revocations` without touching `audit_log`:

```bash
python pypki_admin.py restore \
    --from /var/lib/pypki/backups/pypki-backup-<ts>.tar.gz \
    --to /var/lib/pypki-staging \
    --tables certificates revocations
```

Safe-to-replace tables: `certificates`, `revocations`, `certificate_requests`,
`pending_requests`. Other tables (audit, policy, etc.) cannot be selectively
restored — doing so would break audit chain integrity.

---

## Nightly restore drill

Run this in CI nightly to confirm backup + restore end-to-end:

```bash
# 1. Take a fresh backup
python pypki_admin.py backup-now --ca-dir ./ca --target file:///tmp/drill-backups/

# 2. Dry-run restore (verifies signature and hashes)
BACKUP=$(ls -t /tmp/drill-backups/*.tar.gz | head -1)
python pypki_admin.py restore --from "$BACKUP" --to /tmp/drill-restore --dry-run

# Exit 0 = backup is valid and restorable.
```

---

## Backup registry

Every backup attempt is recorded in the `backups` table:

```sql
SELECT created_at, target_uri, size_bytes, upload_status, audit_final_id
FROM backups
ORDER BY created_at DESC
LIMIT 10;
```

`upload_status` values: `success`, `partial` (multi-target with some failures), `failed`.

---

## Retention

`--backup-retention-count N` keeps the N most recent backups per target.
`--backup-retention-days D` deletes backups older than D days.
Both can be combined; whichever is more restrictive wins per file.
Pruning runs automatically after each successful backup.
