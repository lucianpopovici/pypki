# HOWTO: CRL Distribution (RFC 5280)

> Last reviewed: 2026-06-01 (commit 453e7ba)

## 1. When to use this

Use PyPKI's CRL distribution endpoint to serve Certificate Revocation Lists
for clients that cannot or do not use OCSP. CRLs are the original revocation
mechanism for X.509: a signed list of revoked serial numbers, signed by the CA,
distributed at a known URL embedded in every issued cert's CDP extension.

Typical users: Windows environments (crypt32.dll prefers CRL for corporate PKI),
OpenSSL verification pipelines (`openssl verify -crl_check`), offline validators,
air-gapped networks that batch-download CRLs.

If your relying parties support OCSP, pair CRL distribution with [`ocsp.md`](ocsp.md)
for a belt-and-suspenders setup. For most deployments, enabling both OCSP and
CRL distribution is the right choice.

## 2. Prerequisites

- PyPKI installed, CA initialized → [`docs/DEPLOYMENT/homelab-single-node.md`](../DEPLOYMENT/homelab-single-node.md)
- **Inbound ports**: 80 (CRL distribution is plain HTTP; the CRL is signed)
- **No outbound dependencies**

## 3. Configuration

### CLI flags

| Flag | Default | When to change |
|------|---------|----------------|
| `--crl-url URL` | `""` | Embed this URL in the CDP extension of all issued certs |

There is no separate `--crl-prefix` flag. The CRL endpoint is always mounted at
`/ca/crl` when PyPKI is running. The `--crl-url` flag only controls what URL is
embedded in issued certs' CDP extension.

### How CRL generation works

PyPKI generates a new CRL on:
1. Every server startup.
2. Every revocation via `revoke_certificate()`.
3. `pypki_admin.py generate-crl` (manual trigger).
4. The nightly cron entry in `packaging/cron.d/pypki-crl`.

The CRL is signed by the CA key and stored in `<ca-dir>/ca.crl`. The `/ca/crl`
endpoint serves this file as `application/pkix-crl` (DER) or
`application/x-pem-file` (PEM, when the `Accept` header requests it).

The `cRLNumber` extension increments monotonically. The `crl_number` DB table
(`db_migrations/pki/002_crl_number.sql`) persists the counter across restarts.

### Cron-based CRL refresh

For environments where the CRL must be refreshed on a schedule:

```
# /etc/cron.d/pypki-crl
*/15 * * * * pypki /opt/pypki/venv/bin/python3 /opt/pypki/pypki_admin.py \
  --ca-dir /var/lib/pypki/ca generate-crl
```

## 4. Starting the service

CRL distribution is always active when PyPKI is running. To embed the CRL URL
in issued certs, set `--crl-url`:

```bash
python3 pki_server.py \
  --ca-dir /etc/pypki/ca \
  --port 8080 \
  --crl-url http://pki.internal:8080/ca/crl
```

### Systemd unit

The standard PyPKI systemd unit (any guide) exposes `/ca/crl` automatically.
No separate CRL service is needed.

### Health check

```bash
# Download and parse the CRL
curl -s http://localhost:8080/ca/crl \
  | openssl crl -inform DER -noout -text | head -20

# Verify the CRL signature against the CA cert
curl -s http://localhost:8080/ca/crl -o /tmp/pypki.crl
openssl crl -in /tmp/pypki.crl -inform DER \
  -CAfile /etc/pypki/ca/ca.crt -noout
echo "CRL signature: $?"  # 0 = valid
```

## 5. Client configuration

### openssl verify with CRL checking

```bash
# Download the CRL
curl -s http://pki.internal:8080/ca/crl -o /tmp/pypki.crl

# Verify a cert with CRL check
openssl verify \
  -CAfile /etc/pypki/ca/ca.crt \
  -crl_check \
  -CRLfile /tmp/pypki.crl \
  /tmp/myservice.crt
# Expected: /tmp/myservice.crt: OK

# After revoking myservice.crt:
# Expected: /tmp/myservice.crt: CN=myservice.internal
#   error 23 at 0 depth lookup: certificate revoked
```

### mod_ssl (Apache)

```apache
# In SSLCACertificateFile context
SSLCARevocationFile /etc/apache2/pypki.crl
SSLCARevocationCheck chain

# Refresh the CRL via cron:
# curl -s http://pki.internal:8080/ca/crl | openssl crl -inform DER -out /etc/apache2/pypki.crl
```

### nginx

```nginx
ssl_client_certificate /etc/nginx/pypki-ca.crt;
ssl_crl /etc/nginx/pypki.crl;
ssl_verify_client on;
```

### Windows (certutil)

```bat
REM Download and add to the machine CRL cache
certutil -URLcache -split -f http://pki.internal:8080/ca/crl C:\pypki.crl
certutil -addstore CA C:\pypki.crl
```

## 6. Verification (smoke test)

```bash
tmpdir=$(mktemp -d)
python3 pki_server.py --ca-dir "$tmpdir" --port 18084 \
  --crl-url http://localhost:18084/ca/crl &
PYPKI_PID=$!
sleep 2

# Download and verify CRL
curl -s http://localhost:18084/ca/crl -o /tmp/test.crl
openssl crl -in /tmp/test.crl -inform DER -noout \
  -CAfile "$tmpdir/ca.crt" && echo "CRL valid"

# Check cRLNumber extension
openssl crl -in /tmp/test.crl -inform DER -text \
  | grep -i "crl number"
# Expected: CRL Number: 1 (or higher)

kill $PYPKI_PID; rm -rf "$tmpdir" /tmp/test.crl
echo "CRL smoke test passed"
```

## 7. Day-2 operations

**Revoking a cert and updating the CRL**: Any revocation via the Web UI, REST API,
or CMP `rr` triggers an immediate CRL re-generation. Clients caching the old CRL
will see the update within their CRL cache TTL (the `nextUpdate` field in the CRL).

**cRLNumber** monotonicity is an invariant: see `chaos/invariants/crl_number_monotonic.py`
and the chaos suite for verification.

**Manual CRL generation**:
```bash
python3 pypki_admin.py --ca-dir /etc/pypki/ca generate-crl
```

**Audit log**: CRL generation is logged as `event='crl'` entries.

## 8. Monitoring

| Metric | Type | Alert when |
|--------|------|------------|
| `pypki_certs_revoked_total` | counter | Unexpected spike |
| `pypki_ca_days_remaining` | gauge | < 30 days |

Monitor the CRL's `nextUpdate` field externally:
```bash
# Alert if the CRL is more than 1 hour past nextUpdate
openssl crl -in /tmp/pypki.crl -inform DER -noout -nextupdate
```

## 9. Troubleshooting

**"unable to get certificate CRL"** (openssl verify)
: The client can't reach the CDP URL embedded in the cert. Check network
connectivity to `--crl-url` and that the URL path is correct (`/ca/crl`).

**"CRL is expired"** (nextUpdate in the past)
: PyPKI generates a CRL with `nextUpdate` = now + 30 days. If the server has
been offline for > 30 days, generate a fresh CRL manually. For more frequent
refresh, use the cron entry.

**cRLNumber regression**
: If two PyPKI instances write to the same CA dir without coordination, cRLNumber
can collide. PyPKI uses `advisory_lock("crl-number")` to prevent this, but it only
works within the same process group. For multi-instance deployments, use Postgres
and `advisory_lock`.

Regression tests: `TestRFC5280CRL`, `TestCRLGeneration` in `test_pki_server.py`.

## 10. Security considerations

- CRL files are signed by the CA key; tampering is detectable. However, an
  attacker who can replace the file on the distribution server can serve an old
  CRL (suppressing recent revocations). Use a CDN or web server with strict ACLs.
- CRLs can grow large if many certs are revoked. For deployments issuing > 100k
  certs, monitor CRL size and consider delta-CRLs (not yet implemented).

## 11. References

- RFC 5280 §5 — CRL profile
- RFC 6818 — AKI / SKI in CRLs
- `pki_server.py:CertificateAuthority.generate_crl()` — CRL generation
- `db_migrations/pki/002_crl_number.sql` — cRLNumber persistence
- [`ocsp.md`](ocsp.md) — OCSP (complement to CRL)
