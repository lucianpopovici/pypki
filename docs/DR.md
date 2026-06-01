# PyPKI Disaster Recovery Runbooks

> Last reviewed: 2026-06-01 (commit 453e7ba)

Three scenarios in order of severity. Read all three before an incident so you
know which one applies. Mean times are for a rehearsed operator; add 2–4× for
first-time responders.

---

## Scenario 1: Leaf compromise

**Trigger:** One or more leaf private keys were exfiltrated, or a class of leaves needs
mass-reissuance (e.g. CA/Browser Forum incident, vendor-side key exposure).

**Severity:** Moderate. The CA itself is intact; only end-entity certs are affected.

**Mean time to remediation:** Minutes (with ARI-capable clients), hours otherwise.

### Step-by-step

**1. Identify affected certificates**

```bash
# Find all certs issued before the incident window, for a given CN pattern
sqlite3 /var/lib/pypki/ca/certificates.db \
    "SELECT serial, subject, not_before, not_after
     FROM certificates
     WHERE subject LIKE '%example.com%'
     AND revoked = 0
     ORDER BY not_before DESC;"

# Export serials to a file for batch revocation
sqlite3 /var/lib/pypki/ca/certificates.db \
    "SELECT serial FROM certificates
     WHERE issued_at < '2026-05-25T12:00:00'
     AND profile = 'tls_server'
     AND revoked = 0;" > /tmp/compromised-serials.txt
```

**2. Dry-run to confirm the list**

```bash
python pypki_admin.py revoke-batch \
    --ca-dir /var/lib/pypki/ca \
    --serial-file /tmp/compromised-serials.txt \
    --reason key_compromise \
    --dry-run
```

**3. Mass-revoke**

```bash
python pypki_admin.py revoke-batch \
    --ca-dir /var/lib/pypki/ca \
    --serial-file /tmp/compromised-serials.txt \
    --reason key_compromise
```

The audit log records every revocation with reason code and timestamp.

**4. OCSP and CRL refresh**

OCSP responder picks up revocations on the next request (on-demand mode).
CRL: trigger a manual refresh via the API or wait for the next CRL cycle.

```bash
curl -s -X POST https://pki.example.com/api/crl/refresh
```

**5. ARI bulk-shorten (if ARI enabled)**

For ACME clients using RFC 9773 ARI, shorten renewal windows so affected clients
re-enroll faster:

```bash
# (from ACME ARI tooling — see CLAUDE-ari.md)
python pypki_admin.py ari-bulk-shorten \
    --filter "serial IN (SELECT serial FROM certificates WHERE profile='tls_server')"
```

**6. Post-incident**

- Confirm zero un-revoked certs in the affected class:
  ```bash
  sqlite3 /var/lib/pypki/ca/certificates.db \
      "SELECT COUNT(*) FROM certificates WHERE revoked=0 AND <affected-filter>;"
  ```
- Review audit log for unexpected issuances during the incident window.
- File incident report if this CA chains to a publicly-trusted root.

---

## Scenario 2: DB compromise or corruption

**Trigger:** SQLite file corruption (disk failure, partial write), accidental `DROP TABLE`,
schema migration failure, ransomware, accidental `rm`.

**Severity:** High. CA keys likely intact; cert history lost since last backup.

**Mean time to remediation:** ~30 minutes with rehearsed runbook.

### Step-by-step

**1. Stop PyPKI immediately**

```bash
systemctl stop pypki
```

**2. Assess the damage**

```bash
# Try opening the DB — if this fails, it's corrupted
sqlite3 /var/lib/pypki/ca/certificates.db ".tables"

# Check the audit log DB separately
sqlite3 /var/lib/pypki/ca/audit.db ".tables"
```

**3. Find the most recent valid backup**

```bash
ls -lt /var/lib/pypki/backups/ | head -10
```

Pick the most recent backup that predates the incident. If the incident time is
uncertain, pick the most recent one and check its `audit_seal.json` after restore.

**4. Dry-run to verify backup integrity**

```bash
python pypki_admin.py restore \
    --from /var/lib/pypki/backups/pypki-backup-<ts>.tar.gz.enc \
    --to /var/lib/pypki-staging \
    --passphrase-file /etc/pypki/backup.passphrase \
    --dry-run
```

If this fails with a hash mismatch or signature error, try the previous backup.

**5. Restore to staging**

```bash
python pypki_admin.py restore \
    --from /var/lib/pypki/backups/pypki-backup-<ts>.tar.gz.enc \
    --to /var/lib/pypki-staging \
    --passphrase-file /etc/pypki/backup.passphrase
```

**6. Verify audit chain**

```bash
# The restored DB SQL is in staging/db/pki.sql.gz; restore it to a temp DB first
mkdir -p /tmp/restored-ca
cp -r /var/lib/pypki-staging/ /tmp/restored-ca/
zcat /var/lib/pypki-staging/db/pki.sql.gz | sqlite3 /tmp/restored-ca/certificates.db

python pypki_admin.py audit-verify \
    --ca-dir /tmp/restored-ca
```

The `audit_seal.json` in the backup tells you the last audit entry at backup time.
Any certs issued between the last backup and the incident are gone; document the gap.

**7. Promote staging to live**

```bash
# Archive the corrupted state for forensics
mv /var/lib/pypki/ca /var/lib/pypki/ca.incident-$(date +%Y%m%d)
mkdir -p /var/lib/pypki/ca

# Restore the SQL dump into a fresh DB
zcat /var/lib/pypki-staging/db/pki.sql.gz \
    | sqlite3 /var/lib/pypki/ca/certificates.db

# Copy back the CA key (already passphrase-encrypted)
cp /var/lib/pypki-staging/keys/ca.key.pem /var/lib/pypki/ca/ca.key

# Copy config if restored
cp /var/lib/pypki-staging/config/config.yaml /var/lib/pypki/ca/config.yaml 2>/dev/null || true

# Fix ownership
chown -R pypki:pypki /var/lib/pypki/ca
```

**8. Start and verify**

```bash
systemctl start pypki

# Issue a test cert to confirm CA is operational
openssl s_client -connect pki.example.com:443 </dev/null 2>&1 | grep "Verify return"
```

**9. Reconcile the gap**

Certs issued between last backup and incident no longer exist in the DB. Decide per
profile:

- **TLS server certs (ACME):** ACME clients will auto-renew on the next ARI polling
  cycle. Shorten ARI windows to force faster renewal.
- **Short-lived certs:** Wait for natural expiry; clients will re-enroll.
- **Long-lived certs (code signing, client auth):** Actively notify holders and
  re-issue with the same subject.

---

## Scenario 3: CA key compromise

**Trigger:** Signs of unauthorized HSM/KMS access; exfiltrated encrypted CA key file;
share-holder compromise; key material in logs.

**Severity:** Critical. This is the worst-case scenario. All certs issued by the
compromised CA are suspect.

**Mean time to remediation:** Hours to days. The Shamir ceremony is the long pole.

### Step-by-step

**1. Halt all issuance immediately**

```bash
python pypki_admin.py emergency-stop \
    --ca-dir /var/lib/pypki/ca \
    --reason "ca_key_compromise: <brief description of trigger>"
```

This sets `emergency_state.halted = 1` in the DB. The running server will refuse
new certificate issuance on the next request without restart.

Confirm the halt is active:
```bash
sqlite3 /var/lib/pypki/ca/certificates.db \
    "SELECT halted, halt_reason, halted_at FROM emergency_state;"
```

**2. Notify stakeholders**

- Security team
- CA/Browser Forum (if this CA is publicly trusted)
- Internal relying parties
- CT log operators (if applicable — file a malformed-cert incident)

**3. Revoke the compromised intermediate** (from the offline root)

If you have an offline root CA:

```bash
# If using Shamir shares, collect M shares from share-holders
python pypki_admin.py ca-recover \
    --bundle /offline-media/root-bundle.tar.gz.enc \
    --csr-in /tmp/new-intermediate.csr.pem \
    --cert-out /tmp/new-intermediate.crt.pem \
    --shares 3

# The old intermediate's serial must be added to the root CRL.
# Use the ceremony sign-csr flow with --revoke-serial <old-serial>.
```

**4. Generate a replacement intermediate**

```bash
# On the PyPKI host, generate a new CA key and CSR
openssl ecparam -name prime256v1 -genkey -noout -out /var/lib/pypki/ca-new/ca.key
openssl req -new -key /var/lib/pypki/ca-new/ca.key \
    -subj "/CN=PyPKI Intermediate CA 2/O=Example/C=US" \
    -out /var/lib/pypki/ca-new/ca.csr

# Sign it from the offline root (ceremony — see docs/CEREMONY.md)
python pypki_admin.py sign-csr \
    --bundle /offline-media/root-bundle.tar.gz.enc \
    --csr-in /var/lib/pypki/ca-new/ca.csr \
    --cert-out /var/lib/pypki/ca-new/ca.crt \
    --validity-days 1825
```

**5. Cross-sign (optional)**

If relying parties must trust both the old and new intermediate during transition,
cross-sign the new intermediate with the old one (before revoking it). This avoids
a trust break for currently-valid client certs.

Skip this step if the compromise is severe enough that the old intermediate must
not be trusted for any purpose.

**6. Re-enable PyPKI with the new CA key**

```bash
# Point PyPKI at the new CA directory
# Edit /etc/pypki/config or update --ca-dir

# Clear the emergency halt
python pypki_admin.py emergency-resume --ca-dir /var/lib/pypki/ca-new

# Start with new CA
systemctl start pypki
```

**7. Re-issue all currently-valid certificates**

ACME clients will auto-renew; non-ACME clients need manual re-enrollment.

```bash
# List all unexpired, un-revoked certs from the old CA
sqlite3 /var/lib/pypki/ca/certificates.db \
    "SELECT serial, subject, profile, not_after
     FROM certificates
     WHERE revoked = 0
     AND not_after > datetime('now')
     ORDER BY profile, subject;"
```

Prioritize by profile: server TLS → code signing → client auth → everything else.

**8. Revoke the old intermediate at the root**

Once all certs under the old intermediate have been replaced (or are expired):

```bash
# Add the old intermediate serial to the root CRL.
# This requires another ceremony run against the offline root bundle.
python pypki_admin.py sign-csr \
    --bundle /offline-media/root-bundle.tar.gz.enc \
    --revoke-serial <old-intermediate-serial> \
    ...
```

**9. Post-incident review**

- How was the key accessed? HSM audit logs, KMS access logs, cloud trail.
- Was the key ever in plaintext on disk? (grep audit logs for key export events)
- Was the key backup (ceremony bundle) also compromised? If so, treat the root
  as compromised and escalate to root rollover.
- Update the threat model and certificate lifecycle policies.

---

## Decision matrix

| Incident | CA key intact? | DB intact? | Action |
|---|---|---|---|
| Leaf key exfil | Yes | Yes | Revoke-batch + ARI shorten |
| DB corruption | Yes | No | Restore from backup |
| DB + keys corrupted | Unclear | No | Restore from backup; verify keys separately |
| CA key exfil | No | Maybe | Emergency-stop → ceremony → new CA |
| Root key exfil | No | Maybe | Full trust-chain replacement |

When in doubt, emergency-stop first. You can always re-enable; you cannot un-issue certs.
