# HOWTO: SCEP Server (RFC 8894)

> Last reviewed: 2026-06-01 (commit 453e7ba)

## 1. When to use this

Use PyPKI's SCEP server for network device certificate enrolment. SCEP (Simple
Certificate Enrolment Protocol) is the enrollment protocol built into Cisco IOS,
Cisco ASA, Windows Network Device Enrolment Service (NDES), many MDM platforms
(Jamf, Microsoft Intune), and MicroTik RouterOS.

Typical users: network teams enrolling routers and firewalls, mobile device
management admins, IoT device fleets using MDM-managed enrollment.

If your devices support EST, prefer [`est.md`](est.md) — EST is newer, runs over
standard TLS, and does not require the DES/3DES cipher suite legacy that SCEP
inherited from PKCS#7.

## 2. Prerequisites

- PyPKI installed, CA initialized → [`docs/DEPLOYMENT/homelab-single-node.md`](../DEPLOYMENT/homelab-single-node.md)
- **Inbound ports**: 80 or 443 (SCEP clients connect to the CA HTTP endpoint)
- **No outbound dependencies**
- **Trust anchor**: device must trust the CA cert. SCEP's `GetCACert` operation
  distributes the CA cert — this is safe to do without pre-established trust.
- **Optional**: pre-shared challenge password or one-time OTP for enrollment auth

## 3. Configuration

### CLI flags

| Flag | Default | When to change |
|------|---------|----------------|
| `--scep-prefix PREFIX` | (disabled) | Required — set to `/scep` to enable |
| `--scep-challenge SECRET` | `""` (no challenge) | Set a shared secret for enrollment auth |
| `--scep-use-otp` | off | Enable single-use OTP challenges (minted via Web UI) |
| `--rate-limit N` | 0 | Requests per IP per minute; set to 60 for production |

### Challenge password modes

**No authentication** (open enrollment — development/homelab only):
```bash
python3 pki_server.py --scep-prefix /scep ...
```

**Shared challenge** (all devices use the same password):
```bash
python3 pki_server.py --scep-prefix /scep --scep-challenge "s3cr3t" ...
```

**One-time OTP** (per-device, single-use, generated via Web UI):
```bash
python3 pki_server.py --scep-prefix /scep --scep-use-otp ...
# Generate OTPs: POST /api/scep/otp (Web UI or REST API)
```

### Certificate profile

SCEP issuance uses the `tls_client` profile by default
(SAN=dNSName or iPAddress, keyUsage=digitalSignature+keyEncipherment, EKU=clientAuth).
Defined in `pki_server.py:CertProfile.PROFILES["tls_client"]`.

## 4. Starting the service

### Bare-metal

```bash
python3 pki_server.py \
  --ca-dir /etc/pypki/ca \
  --port 8080 \
  --scep-prefix /scep \
  --scep-challenge "your-challenge-password"
```

### Systemd unit

```bash
cp docs/HOWTO/units/pypki-scep.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pypki-scep
```

### Health check

```bash
# GetCACert — the basic SCEP health check
curl "http://localhost:8080/scep?operation=GetCACert&message=ca"
# Returns DER-encoded CA cert (binary). Exit 0 = service is up.
```

## 5. Client configuration

### sscep (Linux)

```bash
# Install
apt install sscep   # Debian/Ubuntu
dnf install sscep   # Fedora/RHEL

# Generate a key
openssl genrsa -out /tmp/device.key 2048

# GetCACert — fetch and trust the CA cert
sscep getca \
  -u http://pki.internal:8080/scep \
  -c /tmp/ca.crt

# Enroll (with challenge password)
sscep enroll \
  -u http://pki.internal:8080/scep \
  -c /tmp/ca.crt \
  -k /tmp/device.key \
  -r /tmp/device.csr \
  -l /tmp/device.crt \
  -p "your-challenge-password" \
  -n "CN=mydevice.internal"

# Renewal
sscep enroll \
  -u http://pki.internal:8080/scep \
  -c /tmp/ca.crt \
  -k /tmp/device.key \
  -O /tmp/device.crt \     # existing cert for authentication
  -K /tmp/device.key \     # existing key for authentication
  -l /tmp/device-new.crt

# Revocation
# SCEP does not define a revocation operation. Revoke via Web UI or API:
# curl -X POST http://localhost:8080/api/revoke \
#   -H "Content-Type: application/json" \
#   -d '{"serial": 1234, "reason": 0}'
```

### Cisco IOS

```
! Trust PyPKI CA
ip domain-name internal
crypto pki trustpoint PYPKI-CA
  enrollment url http://pki.internal:8080/scep
  password your-challenge-password
  revocation-check none        ! or crl
  rsakeypair PYPKI-KEY

crypto pki authenticate PYPKI-CA    ! Fetches and imports the CA cert
crypto pki enroll PYPKI-CA          ! Submits CSR, receives cert
```

## 6. Verification (smoke test)

```bash
tmpdir=$(mktemp -d)
python3 pki_server.py --ca-dir "$tmpdir" --port 18081 \
  --scep-prefix /scep --scep-challenge "test123" &
PYPKI_PID=$!
sleep 2

# GetCACert
curl -s "http://localhost:18081/scep?operation=GetCACert&message=ca" \
  | openssl x509 -inform DER -noout -subject
# Expected: subject=... matching the initialized CA

# GetCACaps
curl -s "http://localhost:18081/scep?operation=GetCACaps"
# Expected: "POSTPKIOperation\nSHA-256\nSHA-512\nAES\nDES3"

kill $PYPKI_PID
rm -rf "$tmpdir"
echo "SCEP smoke test passed"
```

## 7. Day-2 operations

**Rotating the CA key**: See [`docs/CEREMONY.md`](../CEREMONY.md). SCEP devices must
re-run `GetCACert` to pick up the new CA and then re-enroll with a new cert.
The old cert is revoked as part of the ceremony.

**Revoking a device cert**: Web UI → *Certs* → *Revoke* by serial number. The cert
appears in the next CRL. SCEP itself does not include a revocation request message.

**Audit log**: Filter on `event='issue'` with `detail LIKE '%scep%'`:
```sql
SELECT ts, detail FROM audit WHERE event='issue' AND detail LIKE '%scep%' LIMIT 20;
```

**OTP management**: List and revoke OTPs via `GET /api/scep/otp` (Web UI),
or `pypki_admin.py scep-otp-list`.

## 8. Monitoring

| Metric | Type | Alert when |
|--------|------|------------|
| `pypki_certs_issued_total` | counter | Sustained drop to 0 |
| `pypki_issuance_duration_seconds{protocol="scep"}` | histogram | p99 > 10s |
| `pypki_certs_expiring_7d` | gauge | > 0 (trigger device re-enrolment) |

## 9. Troubleshooting

**"GETCACERT returned wrong content type"**
: Some SCEP clients expect `application/x-x509-ca-cert` or `application/x-x509-ca-ra-cert`.
PyPKI serves the CA cert as DER with the correct MIME type; if your client fails,
check that the `--scep-prefix` matches the URL in the client.

**Challenge password rejected**
: Confirm `--scep-challenge` matches exactly (case-sensitive, no leading/trailing spaces).
For OTP mode, confirm the OTP was generated via `/api/scep/otp` and hasn't been
consumed yet.

**IOS: "PKI: SCEP enrollment failed — HTTP error"**
: IOS SCEP requires plain HTTP (not HTTPS) for enrollment by default, or you must
import the CA cert into the IOS trust chain before HTTPS works. Start with
`enrollment url http://`.

**DES/3DES cipher failures**
: Older SCEP clients (pre-RFC 8894) use DES/3DES in the CMS envelope. PyPKI supports
AES-256 (RFC 8894 recommended) and falls back to 3DES for legacy clients. If a client
sends DES and PyPKI rejects it, check `scep_server.py:_decrypt_envelope()` and the
client's cipher configuration.

Regression test: `TestSCEP` in `test_pki_server.py`.

## 10. Security considerations

See [`docs/THREAT_MODEL.md §3b.11`](../THREAT_MODEL.md) (SCEP OTC).

- Shared challenge passwords are visible in `ps auxe` if passed on the command line.
  Use a config file or environment variable: `export PYPKI_SCEP_CHALLENGE=...` and
  read via your shell/systemd `EnvironmentFile`.
- Without authentication (`--scep-challenge ""`), anyone who reaches the SCEP
  endpoint can enroll a cert. Use `--rate-limit` and network-level access control.
- OTP mode is the most secure: each device gets one OTP that is invalidated after
  use. See `docs/THREAT_MODEL.md §3b.11` for OTP delivery guidance.

## 11. References

- RFC 8894 — SCEP (Simple Certificate Enrolment Protocol)
- `scep_server.py` — SCEP server implementation; ASN.1 helpers
- [`docs/DEPLOYMENT/iot-devices-est.md`](../DEPLOYMENT/iot-devices-est.md)
