# PyPKI — Private PKI Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![RFC 4210](https://img.shields.io/badge/RFC-4210%20CMPv2-informational)](https://www.rfc-editor.org/rfc/rfc4210)
[![RFC 8555](https://img.shields.io/badge/RFC-8555%20ACME-informational)](https://www.rfc-editor.org/rfc/rfc8555)
[![RFC 8894](https://img.shields.io/badge/RFC-8894%20SCEP-informational)](https://www.rfc-editor.org/rfc/rfc8894)
[![RFC 9480](https://img.shields.io/badge/RFC-9480%20CMPv3-informational)](https://www.rfc-editor.org/rfc/rfc9480)
[![RFC 7030](https://img.shields.io/badge/RFC-7030%20EST-informational)](https://www.rfc-editor.org/rfc/rfc7030)
[![RFC 6960](https://img.shields.io/badge/RFC-6960%20OCSP-informational)](https://www.rfc-editor.org/rfc/rfc6960)
[![RFC 5019](https://img.shields.io/badge/RFC-5019%20OCSP%20GET-informational)](https://www.rfc-editor.org/rfc/rfc5019)
[![RFC 9608](https://img.shields.io/badge/RFC-9608%20noRevAvail-informational)](https://www.rfc-editor.org/rfc/rfc9608)
[![RFC 6818](https://img.shields.io/badge/RFC-6818%20X.509%20Updates-informational)](https://www.rfc-editor.org/rfc/rfc6818)

A self-contained, production-grade private Certificate Authority with support for four industry-standard certificate management protocols — **CMPv2/v3** (RFC 4210 / RFC 9480) for embedded/IoT devices, **ACME** (RFC 8555) for servers and workstations, **SCEP** (RFC 8894) for network devices and MDM-enrolled endpoints, and **EST** (RFC 7030) for TLS-capable devices — plus an Ansible role for distributing the CA certificate to client machines.

---

## Contents

| File / Directory | Description |
|---|---|
| [`pki_server.py`](#pki-server) | CA + CMPv2/v3 server + ACME + SCEP + EST integration |
| [`acme_server.py`](#acme-server) | ACME server module (RFC 8555) |
| [`scep_server.py`](#scep-server) | SCEP server module (RFC 8894) |
| [`est_server.py`](#est-server) | EST server module (RFC 7030) |
| [`ocsp_server.py`](#ocsp-responder) | OCSP responder (RFC 6960 / RFC 5019) |
| [`web_ui.py`](#web-dashboard) | HTML management dashboard |
| [`test_pki_server.py`](#testing) | Unit + RFC compliance test suite (178 tests) |
| [`ca_import/`](#ansible-ca-import-role) | Ansible role to push the CA cert to client machines |
| [`CHANGELOG.md`](CHANGELOG.md) | Full version history |
| [`LICENSE`](LICENSE) | MIT License |

---

## Features

### Certificate Authority
- Self-signed RSA-4096 root CA, auto-generated on first run
- SQLite-backed certificate store with full issuance history
- Certificate revocation with reason codes
- CRL generation — served by CMPv2, ACME, and SCEP
- Live-reloadable configuration (`PATCH /config` or `ca/config.json`)
- Eight certificate profiles with per-profile EKU, KeyUsage, and extension defaults
- RFC 9608 `noRevAvail` for short-lived certs; CDP and AIA-OCSP auto-suppressed
- RFC 9549/9598 IDNA: DNS U-label → A-label, `SmtpUTF8Mailbox` for non-ASCII email
- RFC 5280 §4.2.1.4 `CertificatePolicies` with CPS URI and UserNotice (RFC 6818)

### CMPv2 / CMPv3 Protocol (RFC 4210 / RFC 6712 / RFC 9480)
| Operation | Type | Description |
|---|---|---|
| Initialization Request | `ir` / `ip` | First-time certificate enrollment |
| Certification Request | `cr` / `cp` | General certificate request |
| Key Update Request | `kur` / `kup` | Certificate renewal with key rollover |
| Revocation Request | `rr` / `rp` | Certificate revocation |
| Certificate Confirmation | `certConf` / `pkiConf` | Two-phase commit |
| General Message | `genm` / `genp` | CA info query |
| PKCS#10 Request | `p10cr` / `cp` | Standard CSR submission |

**CMPv3 extensions (RFC 9480) — auto-negotiated via `pvno` field:**

| Feature | Description |
|---|---|
| `pvno=3` negotiation | Server mirrors client's pvno; CMPv2 clients unaffected |
| `GetCACerts` | Returns all CA certs as `CACertSeq` (genm id-it 17) |
| `GetRootCACertUpdate` | CA cert rollover preview — `newWithNew` (genm id-it 18) |
| `GetCertReqTemplate` | Key type + extension hints for CSR construction (genm id-it 19) |
| CRL update via genm | Returns current CRL (genm id-it 21/22) |
| Extended polling | `pollReq`/`pollRep` for all message types (RFC 9480 §3.4) |
| Well-known URI | `POST/GET /.well-known/cmp[/p/<label>]` (RFC 9811) |
| Client error ack | Server acknowledges client `error` messages with `pkiconf` |

### ACME Protocol (RFC 8555)
| Challenge type | Description |
|---|---|
| `http-01` | Token served at `/.well-known/acme-challenge/<token>` |
| `dns-01` | TXT record at `_acme-challenge.<domain>` |
| `tls-alpn-01` | RFC 8737 — challenge cert served on port 443 via ALPN |

Full key rollover support (RFC 8555 §7.3.5) — compatible with **acme.sh**, **certbot**, and any standard ACME client.

### SCEP Protocol (RFC 8894)
| Operation | Description |
|---|---|
| `GetCACaps` | Advertise server capabilities (AES, SHA-256, Renewal, POST) |
| `GetCACert` | Download CA certificate |
| `PKCSReq` | Enrol — submit CSR wrapped in CMS, receive signed certificate |
| `CertPoll` | Poll for a pending certificate by transaction ID |
| `GetCert` | Retrieve an issued certificate by serial number |
| `GetCRL` | Download the current Certificate Revocation List |
| `GetNextCACert` | Preview next CA certificate (rollover) |

Compatible with **Cisco IOS**, **Juniper**, **sscep**, **Windows NDES**, **Jamf**, **Microsoft Intune**, and any RFC 8894-compliant SCEP client.

### EST Protocol (RFC 7030)
| Operation | Description |
|---|---|
| `cacerts` | Download CA certificate chain (PKCS#7) |
| `simpleenroll` | Enrol — submit PKCS#10 CSR, receive signed cert |
| `simplereenroll` | Renew with existing TLS client certificate |
| `csrattrs` | Download CSR attribute hints (key type, extensions) |
| `serverkeygen` | Server generates key pair + cert, returns `multipart/mixed` |

Authentication: **HTTP Basic** (username:password) and/or **TLS client certificate** — both active simultaneously. EST always runs over HTTPS.

### TLS
- One-way TLS (`--tls`) and mutual TLS (`--mtls`)
- ALPN negotiation (RFC 7301): `http/1.1`, `h2`, `cmpc` (RFC 9483), `acme-tls/1` (RFC 8737)
- Hardened cipher suites (ECDHE+AESGCM, CHACHA20; no RC4/DES/MD5)
- TLS 1.2 minimum
- Bring-your-own certificate (`--tls-cert` / `--tls-key`)

### Ansible CA Import Role
- Installs CA into OS trust store (Debian, Ubuntu, RHEL, Fedora, macOS)
- Optional: Java cacerts (`keytool`), Python certifi, curl bundle, Mozilla NSS
- Post-install verification script deployed and run on each target
- Supports fetch-from-server, local file, or inline PEM (Vault-friendly)

---

## Requirements

```bash
pip install cryptography pyasn1 pyasn1-modules
```

Python 3.9 or later. No other runtime dependencies.

---

## Quick Start

### 1. Plain HTTP (development)

```bash
python pki_server.py
```

### 2. TLS + ACME + SCEP + EST (staging/production)

```bash
python pki_server.py \
  --tls --port 8443 \
  --tls-hostname pki.internal \
  --acme-port 8888 \
  --scep-port 8889 --scep-challenge mysecret \
  --est-port 8444 \
  --ocsp-port 8082 \
  --ocsp-url http://pki.internal:8082/ocsp \
  --crl-url http://pki.internal:8443/ca/crl \
  --web-port 8090 \
  --audit \
  --alpn-h2 --alpn-cmp --alpn-acme
```

### 3. Mutual TLS + bootstrap + all protocols

```bash
python pki_server.py \
  --mtls --port 8443 \
  --bootstrap-port 8080 \
  --acme-port 8888 \
  --scep-port 8889 --scep-challenge mysecret \
  --est-port 8444 --est-user admin:secret \
  --ocsp-port 8082 \
  --ocsp-url http://pki.internal:8082/ocsp \
  --crl-url http://pki.internal:8443/ca/crl \
  --web-port 8090 \
  --rate-limit 20 \
  --audit

# Issue a client cert via the bootstrap endpoint
curl http://localhost:8080/bootstrap?cn=myclient -o bundle.pem

# Split the bundle
openssl x509 -in bundle.pem -out client.crt
openssl pkey -in bundle.pem -out client.key

# Use it with mTLS
curl --cert client.crt --key client.key \
     --cacert ./ca/ca.crt \
     https://localhost:8443/health
```

---

## PKI Server

### All CLI flags

```
positional / connection:
  --host HOST               Bind address (default: 0.0.0.0)
  --port PORT               CMPv2/HTTPS port (default: 8080)
  --ca-dir DIR              CA data directory (default: ./ca)
  --log-level LEVEL         DEBUG | INFO | WARNING | ERROR

TLS options:
  --tls                     One-way TLS (server cert only)
  --mtls                    Mutual TLS (client cert required)
  --tls-hostname HOSTNAME   SAN for auto-issued server cert (default: localhost)
  --tls-cert PATH           Path to existing PEM server certificate
  --tls-key PATH            Path to matching private key

ALPN options (RFC 7301):
  --alpn-h2                 Advertise h2 (HTTP/2)
  --alpn-cmp                Advertise cmpc (CMP over TLS, RFC 9483)
  --alpn-acme               Advertise acme-tls/1 (RFC 8737)
  --no-alpn-http            Suppress http/1.1

Bootstrap:
  --bootstrap-port PORT     Plain HTTP port for initial client cert issuance

ACME options:
  --acme-port PORT          Run ACME server on this port
  --acme-base-url URL       Public base URL for ACME links
  --acme-auto-approve-dns   Skip DNS lookup for dns-01 (testing only)

Revocation & PKI infrastructure:
  --ocsp-port PORT          Start OCSP responder on this port (e.g. 8082)
  --ocsp-url URL            OCSP URL embedded in AIA extension of all issued certs
  --crl-url URL             CRL URL embedded in CDP extension of all issued certs
  --ocsp-cache-seconds N    OCSP response cache TTL (default: 300)

Operational options:
  --web-port PORT           Start web dashboard on this port (e.g. 8090)
  --rate-limit N            Max cert requests per IP per minute (0 = disabled)
  --audit                   Enable audit log in ca/audit.db (default: on)
  --no-audit                Disable audit log
  --default-profile PROF    Default cert profile for CMPv2 issuance (default: default)

CMPv3 options (RFC 9480):
  --cmpv3                   Enable CMPv3 handler (default: on)
  --no-cmpv3                Force CMPv2-only mode

EST options (RFC 7030):
  --est-port PORT           Run EST server on this port (e.g. 8444)
  --est-user USER:PASS      Add Basic auth user (repeatable)
  --est-require-auth        Require auth (Basic or TLS client cert)
  --est-tls-cert PATH       PEM server cert for EST HTTPS
  --est-tls-key PATH        PEM private key for --est-tls-cert

SCEP options:
  --scep-port PORT          Run SCEP server on this port (e.g. 8889)
  --scep-challenge SECRET   Challenge password for enrolment (empty = open)

Validity periods (also changeable live via PATCH /config):
  --end-entity-days DAYS    End-entity cert lifetime (default: 365)
  --client-cert-days DAYS   mTLS client cert lifetime (default: 365)
  --tls-server-days DAYS    TLS server cert lifetime (default: 365)
  --ca-days DAYS            CA cert lifetime on first creation (default: 3650)
```

### API endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/` | CMPv2 endpoint (`application/pkixcmp`) |
| `GET` | `/ca/cert.pem` | CA certificate (PEM) |
| `GET` | `/ca/cert.der` | CA certificate (DER) |
| `GET` | `/ca/crl` | Certificate Revocation List |
| `GET` | `/api/certs` | All issued certificates (JSON) |
| `GET` | `/api/whoami` | Authenticated mTLS client identity |
| `GET` | `/config` | Current server configuration |
| `PATCH` | `/config` | Live-update configuration |
| `GET` | `/bootstrap?cn=<n>` | Issue client cert bundle (bootstrap port) |
| `GET` | `/health` | Health check |
| `GET` | `/ca/delta-crl` | Delta CRL (RFC 5280 §5.2.4) |
| `GET` | `/api/certs/<serial>/pem` | Download certificate PEM |
| `GET` | `/api/certs/<serial>/p12` | Download PKCS#12 bundle (cert + CA chain) |
| `POST` | `/api/sub-ca` | Issue subordinate CA cert `{"cn":"...", "validity_days":1825}` |
| `POST` | `/api/revoke` | Revoke certificate `{"serial": N, "reason": 0}` |
| `GET` | `/api/audit` | Structured audit log (last 200 events) |
| `GET` | `/api/rate-limit` | Rate limit status for calling IP |
| `POST` | `/.well-known/cmp` | RFC 9811 well-known CMP endpoint |
| `POST` | `/.well-known/cmp/p/<label>` | Named CA CMP endpoint (RFC 9811) |
| `GET` | `/.well-known/cmp` | CA certificate (RFC 9811 discovery) |

### Live configuration

Validity periods can be changed without restarting:

```bash
# Via HTTP API
curl -X PATCH http://localhost:8080/config \
  -H "Content-Type: application/json" \
  -d '{"validity": {"end_entity_days": 90, "client_cert_days": 30}}'

# Via config file (hot-reloaded on next request)
cat ca/config.json
{
  "validity": {
    "end_entity_days": 90,
    "client_cert_days": 30,
    "tls_server_days": 365,
    "ca_days": 3650
  }
}
```

---

## ACME Server

Runs as a module integrated with the PKI server, or standalone:

```bash
# Standalone
python acme_server.py --port 8888 --ca-dir ./ca

# With dns-01 auto-approval (internal/testing only)
python acme_server.py --port 8888 --auto-approve-dns
```

### ACME endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/acme/directory` | Service discovery |
| `HEAD/GET` | `/acme/new-nonce` | Fresh replay nonce |
| `POST` | `/acme/new-account` | Create or find account |
| `POST` | `/acme/new-order` | Request certificate for identifiers |
| `POST` | `/acme/authz/<id>` | Get authorization details |
| `POST` | `/acme/challenge/<authz>/<id>` | Trigger challenge validation |
| `POST` | `/acme/order/<id>/finalize` | Submit CSR |
| `POST` | `/acme/cert/<id>` | Download certificate chain |
| `POST` | `/acme/revoke-cert` | Revoke certificate |
| `POST` | `/acme/key-change` | Account key rollover (RFC 8555 §7.3.5) |

### Using with acme.sh

```bash
acme.sh --issue \
  --server http://pki.internal:8888/acme/directory \
  -d mydevice.internal \
  --standalone \
  --insecure          # needed until the CA is in your system trust store
```

### Using with certbot

```bash
certbot certonly \
  --server http://pki.internal:8888/acme/directory \
  --standalone \
  -d mydevice.internal \
  --no-verify-ssl
```

---

## SCEP Server

Runs as a module integrated with the PKI server, or standalone:

```bash
# Standalone (open enrolment — no challenge)
python scep_server.py --port 8889 --ca-dir ./ca

# With challenge password
python scep_server.py --port 8889 --challenge mysecret
```

### SCEP endpoints

All operations are served at `/scep`. The server also accepts
`/cgi-bin/pkiclient.exe` and `/scep/pkiclient.exe` for compatibility
with Cisco IOS and Windows NDES clients.

| Method | `?operation=` | Description |
|---|---|---|
| `GET` | `GetCACaps` | Server capability advertisement |
| `GET` | `GetCACert` | Download CA certificate (DER) |
| `POST` | `PKCSReq` | Certificate enrolment (CMS-wrapped PKCS#10) |
| `POST` | `CertPoll` | Poll for pending certificate by transaction ID |
| `POST` | `GetCert` | Retrieve certificate by serial number |
| `POST` | `GetCRL` | Download current CRL |
| `GET` | `GetNextCACert` | Next CA certificate (rollover preview) |

### Authentication

**Challenge password** — set `--scep-challenge` to require a shared secret embedded in the PKCS#10 CSR `challengePassword` attribute. Compared using constant-time comparison to prevent timing attacks.

**Renewal without challenge** — if the requester includes a valid existing certificate (signed by this CA) in the CMS envelope, the challenge is automatically waived. This is the standard renewal flow used by MDM platforms.

### Using with sscep

```bash
# Fetch CA certificate
sscep getca -u http://pki.internal:8889/scep -c ca.crt

# Generate key + CSR
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/CN=mydevice.internal"

# Enrol
sscep enroll \
  -u http://pki.internal:8889/scep \
  -c ca.crt -k client.key -r client.csr -l client.crt \
  -p mysecret

# Renew (existing cert used instead of challenge)
sscep enroll \
  -u http://pki.internal:8889/scep \
  -c ca.crt -k client.key -r client.csr -l client-renewed.crt \
  -O client.crt
```

### Using with Cisco IOS

```
crypto pki trustpoint PYPKI
 enrollment url http://pki.internal:8889/scep
 subject-name CN=router1.internal,O=MyOrg
 revocation-check none

crypto pki authenticate PYPKI
crypto pki enroll PYPKI
 password mysecret
```

### Using with Microsoft Intune / NDES

Point the SCEP URL in your Intune configuration profile to:
```
http://pki.internal:8889/scep
```
The server accepts the `/cgi-bin/pkiclient.exe` path used by NDES-compatible clients automatically.

---

## EST Server

Runs as a module integrated with the PKI server, or standalone:

```bash
# Standalone — open enrolment (no auth required)
python est_server.py --port 8444 --ca-dir ./ca

# With HTTP Basic auth user(s)
python est_server.py --port 8444 --user admin:secret --user device:pass123

# Require authentication
python est_server.py --port 8444 --user admin:secret --require-auth
```

EST always runs over HTTPS. If no `--tls-cert`/`--tls-key` are provided, a server certificate is auto-issued from the CA.

### EST endpoints

All operations are under `/.well-known/est`. A CA label variant `/.well-known/est/<label>/<op>` is also accepted.

| Method | Path | Description |
|---|---|---|
| `GET` | `/.well-known/est/cacerts` | CA chain (base64 PKCS#7) |
| `GET` | `/.well-known/est/csrattrs` | CSR attribute hints (base64 DER) |
| `POST` | `/.well-known/est/simpleenroll` | Enrol — submit PKCS#10 CSR |
| `POST` | `/.well-known/est/simplereenroll` | Renew with existing cert |
| `POST` | `/.well-known/est/serverkeygen` | Server-generated key + cert |

### Authentication

EST supports both methods simultaneously. Either is sufficient:

**HTTP Basic** — configure users with `--est-user USER:PASS` (or `--user` standalone). The server sends `401 + WWW-Authenticate` on failure.

**TLS client certificate** — the server runs with `ssl.CERT_OPTIONAL`. A certificate signed by the CA is accepted automatically; no additional configuration needed.

Use `--est-require-auth` to enforce that at least one method succeeds; omit it for open internal CAs.

### Using with curl

```bash
# 1. Download CA chain
curl --cacert ./ca/ca.crt \
  https://pki.internal:8444/.well-known/est/cacerts \
  | base64 -d > chain.p7

# 2. Get CSR attribute hints
curl --cacert ./ca/ca.crt \
  https://pki.internal:8444/.well-known/est/csrattrs \
  | base64 -d | openssl asn1parse -inform DER

# 3. Generate key + CSR
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=mydevice.internal"

# 4. Enrol (Base64 DER CSR body, Basic auth)
curl -X POST --cacert ./ca/ca.crt \
  -u admin:secret \
  -H "Content-Transfer-Encoding: base64" \
  --data-binary "$(base64 client.csr)" \
  https://pki.internal:8444/.well-known/est/simpleenroll \
  | base64 -d > chain.p7

# 5. Extract certificate from PKCS#7
openssl pkcs7 -in chain.p7 -inform DER -print_certs -out client.crt

# 6. Server-generated key + cert (no CSR needed)
curl -X POST --cacert ./ca/ca.crt \
  -u admin:secret \
  https://pki.internal:8444/.well-known/est/serverkeygen \
  -o keygen_response.multipart
```

### Using with estclient (Python / Go tools)

Any RFC 7030-compliant client works. Popular options: `libest` (Cisco), `est` (Go), `python-estclient`. Point them at `https://pki.internal:8444/.well-known/est`.


---

## OCSP Responder

Runs as a module integrated with the PKI server, or standalone:

```bash
# Standalone
python ocsp_server.py --port 8082 --ca-dir ./ca

# Integrated
python pki_server.py --port 8080 --ocsp-port 8082 \
  --ocsp-url http://pki.internal:8082/ocsp \
  --crl-url  http://pki.internal:8080/ca/crl
```

### OCSP endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/ocsp` | RFC 6960 HTTP POST binding |
| `GET` | `/ocsp/<base64-req>` | RFC 5019 GET binding (CDN-cacheable) |

### Testing with OpenSSL

```bash
# Check a certificate
openssl ocsp \
  -issuer ca/ca.crt \
  -cert   client.crt \
  -url    http://localhost:8082/ocsp \
  -resp_text

# Expected output for a valid cert:
#   Response verify OK
#   client.crt: good
#   This Update: ...
#   Next Update: ...

# After revoking (serial 1001):
curl -X POST http://localhost:8080/api/revoke \
  -H 'Content-Type: application/json' \
  -d '{"serial": 1001, "reason": 1}'

# Re-check — now shows revoked + reason
openssl ocsp -issuer ca/ca.crt -cert client.crt -url http://localhost:8082/ocsp
```

The OCSP signing cert (`ca/ocsp.crt`) has the `id-pkix-ocsp-nocheck` extension so clients do not recurse into checking its own revocation status (RFC 6960 §4.2.2.2). It is auto-renewed when within 7 days of expiry.

---

## Certificate Profiles

Eight built-in profiles control key usage, EKU, and extensions:

| Profile | Key Usage | EKU | Notes |
|---|---|---|---|
| `default` | All | — | Previous behaviour, backward-compatible |
| `tls_server` | `digitalSignature`, `keyEncipherment` | `serverAuth` | SAN recommended |
| `tls_client` | `digitalSignature` | `clientAuth` | — |
| `code_signing` | `digitalSignature`, `contentCommitment` | `codeSigning` | — |
| `email` | `digitalSignature`, `keyEncipherment`, `contentCommitment` | `emailProtection` | — |
| `ocsp_signing` | `digitalSignature` | `OCSPSigning` | Auto-adds `id-pkix-ocsp-nocheck` |
| `sub_ca` | `keyCertSign`, `cRLSign`, `digitalSignature` | — | `BasicConstraints cA=True` |

Use `--default-profile tls_server` to apply a profile to all CMPv2-issued certs, or specify it per-request via the REST API.

---

## Subordinate CA

Issue a path-length-0 intermediate CA certificate:

```bash
# Via REST API
curl -X POST http://localhost:8080/api/sub-ca \
  -H 'Content-Type: application/json' \
  -d '{"cn": "PyPKI Intermediate CA 1", "validity_days": 1825}'

# Response includes cert_pem and key_pem
# Save them and use to sign end-entity certs with a second CA instance:
python pki_server.py --ca-dir ./sub-ca \
  --tls-cert sub-ca.crt --tls-key sub-ca.key
```

Sub-CA certificates use the `sub_ca` profile automatically (4096-bit RSA, path length 0).

---

## PKCS#12 Export

Download a certificate as a PKCS#12 bundle (cert + CA chain, no private key stored server-side):

```bash
# Download by serial number
curl http://localhost:8080/api/certs/1001/p12 -o cert-1001.p12

# Inspect with openssl
openssl pkcs12 -in cert-1001.p12 -nokeys -info

# Import into macOS Keychain
security import cert-1001.p12 -k ~/Library/Keychains/login.keychain-db
```

---

## Delta CRL

Download a delta CRL containing only revocations since the last base CRL snapshot:

```bash
curl http://localhost:8080/ca/delta-crl -o delta.crl
openssl crl -in delta.crl -inform DER -text -noout
```

Delta CRLs contain the `deltaCRLIndicator` critical extension (RFC 5280 §5.2.4). The base CRL snapshot is stored in `ca/certificates.db` (table `crl_base`) and updated each time a delta CRL is generated.

---

## Audit Log

All certificate lifecycle events are logged to `ca/audit.db`:

```bash
# View recent events via API
curl http://localhost:8080/api/audit | python3 -m json.tool

# Query directly
sqlite3 ca/audit.db "SELECT ts, event, detail, ip FROM audit ORDER BY id DESC LIMIT 20"
```

Events recorded: `startup`, `shutdown`, `issue`, `issue_sub_ca`, `revoke`, `config_patch`.

---

## Rate Limiting

Per-IP token-bucket rate limiter on all certificate enrolment endpoints:

```bash
# Check your current rate limit status
curl http://localhost:8080/api/rate-limit

# Enable with --rate-limit N (requests per minute per IP)
python pki_server.py --rate-limit 20 ...
```

Exceeding the limit returns `HTTP 429 Too Many Requests` with `Retry-After: 60`.

---

## Web Dashboard

A browser-based management UI running on a dedicated port (no TLS required — serve behind a reverse proxy in production):

```bash
python pki_server.py --web-port 8090 ...
# Open http://localhost:8090
```

Pages:

| Page | Path | Features |
|---|---|---|
| Dashboard | `/` | Stats (total/active/revoked/expired), CA info, endpoint URLs |
| Certificates | `/certs` | Searchable inventory, PEM/P12 download, one-click revoke |
| Revocation | `/revocation` | CRL/OCSP URLs, revoke-by-serial form with reason |
| Sub-CA | `/sub-ca` | Issue intermediate CA certificates |
| Config | `/config-ui` | Live config viewer + validity period editor |
| Audit Log | `/audit` | Last 100 audit events |
| API Docs | `/api-docs` | Quick-reference endpoint table |

---

---

## Ansible CA Import Role

Distributes the CA certificate to client machines across all major trust stores.

### Quick start

```bash
cd ca_import

# Install system trust store only
ansible-playbook ca_import.yml \
  -e ca_import_fetch_url=http://pki.internal:8080/ca/cert.pem

# Full workstation setup (all stores)
ansible-playbook ca_import.yml \
  -e ca_import_fetch_url=http://pki.internal:8080/ca/cert.pem \
  -e ca_import_java=true \
  -e ca_import_python=true \
  -e ca_import_curl=true \
  -e ca_import_nss=true

# Remove CA from all stores
ansible-playbook ca_import.yml \
  -e ca_import_fetch_url=http://pki.internal:8080/ca/cert.pem \
  -e ca_import_remove=true

# Only verify existing trust (no changes)
ansible-playbook ca_import.yml --tags verify
```

### Supported trust stores

| Store | Platform | Flag |
|---|---|---|
| System (OS) | Debian, Ubuntu, RHEL, Fedora, macOS | `ca_import_system: true` (default) |
| Java cacerts | Any (requires `keytool`) | `ca_import_java: true` |
| Python certifi | Any | `ca_import_python: true` |
| curl / libcurl | Any | `ca_import_curl: true` |
| Mozilla NSS | Any (Firefox, Chromium) | `ca_import_nss: true` |

### Key role variables

```yaml
ca_import_fetch_url:   "http://pki.internal:8080/ca/cert.pem"
ca_import_name:        "pypki-ca"
ca_import_label:       "PyPKI Internal CA"
ca_import_system:      true
ca_import_java:        false
ca_import_python:      false
ca_import_curl:        false
ca_import_nss:         false
ca_import_remove:      false
```

Supply the CA cert three ways — fetch from server, copy a local file, or inline PEM (suitable for HashiCorp Vault integration):

```yaml
# Vault example
ca_import_pem_content: "{{ lookup('hashi_vault', 'secret/pypki/ca_pem') }}"
```

---

## Internationalized Names (RFC 9549 / RFC 9598)

PyPKI automatically handles internationalized domain names and email addresses in
certificate Subject Alternative Names and Subject DN, with no extra configuration needed.

### DNS SANs — U-label to A-label (RFC 9549 §4.1)

All Unicode (U-label) DNS values are silently converted to their ACE (A-label) form
using Python's built-in IDNA codec before being stored in `dNSName` GeneralName values.
Wildcard labels (`*`) are preserved unchanged.

```python
# These are all equivalent — the U-label is normalised automatically
ca.issue_certificate("CN=service", key.public_key(),
                     san_dns=["münchen.de", "sub.münchen.de", "*.example.com"])
# Stored as: xn--mnchen-3ya.de  /  sub.xn--mnchen-3ya.de  /  *.example.com
```

### Email SANs — two-path routing (RFC 9549 §4.2 / RFC 9598)

| Condition | Encoding | Example |
|---|---|---|
| ASCII local-part, ASCII host | `rfc822Name` unchanged | `alice@example.com` |
| ASCII local-part, IDN host | `rfc822Name` with A-label host | `alice@münchen.de` → `alice@xn--mnchen-3ya.de` |
| Non-ASCII local-part | `SmtpUTF8Mailbox` `otherName` (OID `1.3.6.1.5.5.7.8.9`) | `müller@example.com` |

```python
ca.issue_certificate("CN=email", key.public_key(),
                     san_emails=[
                         "alice@example.com",      # → rfc822Name as-is
                         "bob@münchen.de",          # → rfc822Name (A-label host)
                         "müller@example.com",      # → SmtpUTF8Mailbox otherName
                     ])
```

### Domain components in Subject DN (RFC 6818 §5 / RFC 9549 §4)

`DC=` attributes in the subject string are IDNA-encoded per RFC 6818 §5:

```python
ca.issue_certificate("CN=svc,DC=münchen,DC=de", key.public_key())
# Subject: CN=svc, DC=xn--mnchen-3ya, DC=de
```

### Verify with OpenSSL

```bash
openssl x509 -in cert.pem -noout -text | grep DNS
# DNS:xn--mnchen-3ya.de

openssl x509 -in cert.pem -noout -text | grep "othername"
# othername: 1.3.6.1.5.5.7.8.9::müller@example.com
```

---

## Certificate Policies (RFC 5280 §4.2.1.4 / RFC 6818)

The `certificate_policies` parameter adds a `CertificatePolicies` extension to issued
certificates. This is required for CAs that participate in policy hierarchies (government
PKI, corporate PKI, CA/Browser Forum compliance assertions).

### Per-request

```python
ca.issue_certificate(
    "CN=service.example.com",
    key.public_key(),
    profile="tls_server",
    san_dns=["service.example.com"],
    certificate_policies=[
        {
            "oid": "2.23.140.1.2.1",                     # CA/B Forum DV
            "cps_uri": "https://pki.example.com/cps",    # CPS URI qualifier
            "notice_text": "Domain-validated certificate",# UserNotice qualifier
        },
        {
            "oid": "1.3.6.1.4.1.99999.1.1",              # custom OID
        },
    ],
)
```

### Per-profile default

```python
from pki_server import CertProfile, OID_POLICY_DV

CertProfile.PROFILES["tls_server"]["certificate_policies"] = [
    {"oid": OID_POLICY_DV.dotted_string,
     "cps_uri": "https://pki.example.com/cps"}
]
```

### Well-known OID constants

| Constant | OID | Policy |
|---|---|---|
| `OID_POLICY_DV` | `2.23.140.1.2.1` | CA/B Forum Domain Validated |
| `OID_POLICY_OV` | `2.23.140.1.2.2` | CA/B Forum Organisation Validated |
| `OID_POLICY_IV` | `2.23.140.1.2.3` | CA/B Forum Individual Validated |
| `OID_POLICY_EV` | `2.23.140.1.1` | CA/B Forum Extended Validation |
| `OID_ANY_POLICY` | `2.5.29.32.0` | anyPolicy |
| `OID_QT_CPS` | `1.3.6.1.5.5.7.2.1` | id-qt-cps (CPS URI qualifier type) |
| `OID_QT_UNOTICE` | `1.3.6.1.5.5.7.2.2` | id-qt-unotice (UserNotice qualifier type) |

### Verify with OpenSSL

```bash
openssl x509 -in cert.pem -noout -text | grep -A10 "Certificate Policies"
# Certificate Policies:
#   Policy: 2.23.140.1.2.1
#     CPS: https://pki.example.com/cps
#     User Notice:
#       Explicit Text: Domain-validated certificate
```

---

## Testing

PyPKI ships a comprehensive test suite covering RFC compliance, all public APIs,
and integration behaviour.

```bash
# Run all 178 tests
python -m unittest test_pki_server -v

# Run only RFC compliance tests
python -m unittest test_pki_server.TestRFC5280CertStructure -v
python -m unittest test_pki_server.TestRFC5280Extensions -v
python -m unittest test_pki_server.TestRFC5280CRL -v
python -m unittest test_pki_server.TestRFC9608NoRevAvail -v
python -m unittest test_pki_server.TestRFC9549IDNA -v
python -m unittest test_pki_server.TestCertificatePolicies -v

# Run HTTP API integration tests
python -m unittest test_pki_server.TestHTTPAPI -v

# Or with pytest (if installed)
pytest test_pki_server.py -v -k rfc5280
pytest test_pki_server.py -v -k rfc9608
pytest test_pki_server.py -v -k rfc9549
pytest test_pki_server.py -v -k policies
```

### Test classes

| Class | Tests | Coverage |
|---|---|---|
| `TestRFC5280CertStructure` | 9 | §4.1 — version, serial, signature, issuer, validity encoding, subject |
| `TestRFC5280Extensions` | 9 | §4.2 — AKI/SKI match, KeyUsage critical, BasicConstraints, SAN, AIA, CDP |
| `TestRFC5280CRL` | 11 | §5 — issuer, thisUpdate, nextUpdate, signature, revoked/good entries, delta CRL |
| `TestRFC9608NoRevAvail` | 9 | noRevAvail present, non-critical, NULL value, CDP/AIA suppressed, CA exempt |
| `TestCertificateProfiles` | 13 | All 8 profiles: EKU, KeyUsage, BasicConstraints, ocsp-nocheck, noRevAvail |
| `TestSubCAIssuance` | 7 | path_length=0, 4096-bit key, issuer chain, signature verification |
| `TestPKCS12Export` | 6 | Export, cert + CA chain present, no private key, password-protected |
| `TestCSRValidation` | 6 | Valid pass, missing CN, no SAN for tls_server, invalid FQDN, weak key, bad sig |
| `TestAuditLog` | 7 | Record, ordering, limit, ISO 8601 timestamps, DB persistence |
| `TestRateLimiter` | 6 | Token bucket, per-IP independence, thread safety |
| `TestCertificateAuthority` | 15 | All public methods, SAN types, validity_days, persistence across restart |
| `TestServerConfig` | 6 | Defaults, patch, disk write, reload |
| `TestHTTPAPI` | 16 | All endpoints live-tested: health, CRL, delta-CRL, revoke, sub-CA, P12, rate-limit, audit |
| `TestOCSPParsing` | 4 | Module structure, server starts, signing cert extensions |
| `TestCMPMessageStructure` | 6 | Handler instantiation, garbage rejection, message builder, pvno constants |
| `TestACMERFC9608Integration` | 5 | Profile selection, noRevAvail end-to-end, ACME module attrs |
| `TestESTModule` | 3 | Module importable, required operations, csrattrs DER output |
| `TestModuleStructure` | 5 | All exported symbols, all 8 profiles, noRevAvail OID |
| `TestRFC9549IDNA` | 13 | DNS U-label→A-label, wildcard preserved, ASCII email, IDN-host email A-label, SmtpUTF8Mailbox OID/tag/payload, mixed list, DC attribute IDNA |
| `TestCertificatePolicies` | 17 | Not added by default, single/multi OID, non-critical, CPS URI, UserNotice text, UTF-8 round-trip, both qualifiers, CA/B Forum OID constants, bad-oid skipped, empty list, profile default, explicit override |

### Dependencies

Tests use only the Python standard library (`unittest`, `http.client`, `tempfile`, `threading`)
plus `cryptography` (already required). No additional test framework is needed.

---

---

## CA directory layout

After first run, the `./ca` directory contains:

```
ca/
├── ca.key              Private key for the root CA (keep secret)
├── ca.crt              Root CA certificate (distribute to clients)
├── ca.crl              Certificate Revocation List
├── certificates.db     SQLite store of all issued certificates
├── acme.db             SQLite store of ACME accounts, orders, challenges
├── scep.db             SQLite store of SCEP enrolment transactions
├── audit.db            Structured audit log (all issuance + revocation events)
├── ocsp.key / ocsp.crt OCSP signing key and certificate (auto-issued, 30-day)
├── crl_base            Delta CRL base snapshots stored in certificates.db

Project root:
├── test_pki_server.py  Unit + RFC compliance test suite (178 tests)
├── est/                EST TLS cert auto-issued here (if no --est-tls-cert)
├── config.json         Live server configuration (hot-reloaded)
├── server.crt          Auto-issued TLS server certificate
└── server.key          TLS server private key
```

> **Security note:** `ca.key` and `server.key` are stored unencrypted. In production, replace with an HSM or KMS-backed key store and restrict filesystem permissions accordingly.

---

## RFC 9608 — No Revocation Available

RFC 9608 defines `id-ce-noRevAvail` (OID `2.5.29.56`), a non-critical certificate
extension that signals the CA will never publish revocation information for a cert.
PyPKI implements the full §4 requirements:

| Requirement | Implementation |
|---|---|
| Extension MUST be non-critical | ✅ Always set `critical=False` |
| Extension value MUST be ASN.1 NULL | ✅ Value = `05 00` |
| MUST NOT appear in CA certificates | ✅ Forced off for all CA/sub-CA certs |
| MUST NOT coexist with CDP extension | ✅ CDP suppressed when `noRevAvail` is set |
| MUST NOT coexist with AIA OCSP extension | ✅ AIA OCSP suppressed when `noRevAvail` is set |

### Trigger methods

**1. `short_lived` profile** — explicitly requests the extension:
```bash
curl -X POST http://localhost:8080/api/sub-ca  # uses sub_ca profile — no noRevAvail
```
```python
ca.issue_certificate("CN=device", key.public_key(), profile="short_lived", validity_days=3)
```

**2. ACME short-lived threshold** — automatic for ACME certs:
```bash
# Certs with validity <= 7 days get noRevAvail automatically
python pki_server.py --acme-port 8888 --acme-cert-days 3 --acme-short-lived-threshold 7
```

**3. Explicit parameter** — override on any profile:
```python
ca.issue_certificate("CN=no-revocation", key.public_key(),
                      no_rev_avail=True, profile="tls_server")
```

### Verify with OpenSSL
```bash
openssl x509 -in short-lived.crt -text -noout | grep -A2 "2.5.29.56"
# X509v3 Unknown Extension 2.5.29.56:
#   ..
```

---

## RFC Compliance Notes

### Implemented RFC updates to RFC 5280

| RFC | Title | Status |
|---|---|---|
| **RFC 6818** | General Clarifications to RFC 5280 | ✅ `explicitText` uses UTF8String; self-signed root exempt from AKI |
| **RFC 9608** | No Revocation Available Extension | ✅ Full §4 compliance (see above) |
| **RFC 8398 / RFC 9598** | Internationalized Email Addresses | ✅ ASCII-local + IDN host → `rfc822Name` (A-label); non-ASCII local → `SmtpUTF8Mailbox` `otherName` (OID `1.3.6.1.5.5.7.8.9`) |
| **RFC 8399 / RFC 9549** | IDN in DNS SANs and Subject DN | ✅ U-labels auto-converted to A-labels in `dNSName` and `domainComponent`; wildcards preserved |
| **RFC 9618** | Updates to X.509 Policy Validation | N/A — policy-tree algorithm is a relying-party concern; `cryptography`/`ssl` handle this |
| **RFC 5280 §4.2.1.4** | Certificate Policies extension | ✅ `CertificatePolicies` with CPS URI and/or `UserNotice` qualifiers (RFC 6818 UTF8String) |

### Always-present RFC 5280 extensions

Every issued certificate includes:

| Extension | OID | Critical |
|---|---|---|
| BasicConstraints | 2.5.29.19 | ✅ Yes |
| SubjectKeyIdentifier | 2.5.29.14 | No |
| AuthorityKeyIdentifier | 2.5.29.35 | No |
| KeyUsage | 2.5.29.15 | ✅ Yes |

---

---

## Protocol compliance

| Standard | Description | Status |
|---|---|---|
| RFC 4210 | Certificate Management Protocol v2 | ✅ Full |
| RFC 4211 | CRMF — Certificate Request Message Format | ✅ Full |
| RFC 6712 | CMP over HTTP | ✅ Full |
| RFC 9483 | Lightweight CMP Profile (ALPN `cmpc`) | ✅ ALPN |
| RFC 8555 | ACME — Automatic Certificate Management | ✅ Full |
| RFC 8737 | ACME `tls-alpn-01` challenge | ✅ Full |
| RFC 8894 | SCEP — Simple Certificate Enrolment Protocol | ✅ Full |
| RFC 9480 | CMP Updates — CMPv3 features | ✅ Full |
| RFC 9811 | CMP well-known URI paths | ✅ Full |
| RFC 7030 | EST — Enrollment over Secure Transport | ✅ Full |
| RFC 7301 | TLS ALPN Extension | ✅ Full |
| RFC 6960 | OCSP — Online Certificate Status Protocol | ✅ Full |
| RFC 5019 | Lightweight OCSP Profile (GET binding) | ✅ Full |
| RFC 7292 | PKCS#12 — Personal Information Exchange | ✅ Export only |
| RFC 9608 | No Revocation Available Extension | ✅ Full |
| RFC 6818 | General Clarifications to RFC 5280 | ✅ Applicable provisions |
| RFC 8399/9549 | IDN in DNS SANs, domainComponent | ✅ Full IDNA U-label → A-label |
| RFC 8398/9598 | Internationalized email addresses | ✅ `rfc822Name` A-label + `SmtpUTF8Mailbox` |
| RFC 7638 | JWK Thumbprint | ✅ Full |
| RFC 5280 | X.509 Certificates and CRL profile | ✅ Full |

---

## License

MIT — see [LICENSE](LICENSE).
