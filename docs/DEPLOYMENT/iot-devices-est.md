# Deployment: IoT Devices via EST (RFC 7030)

This guide deploys PyPKI as the certificate enrollment endpoint for fleets of IoT devices that speak EST. EST (Enrollment over Secure Transport) is the right protocol for embedded devices that have a TLS stack but no DNS / HTTP infrastructure flexibility — it's a tight, well-defined protocol designed for exactly this case.

PyPKI's EST implementation supports `simpleenroll` (initial enrollment), `simplereenroll` (renewal), `cacerts` (chain distribution), and `csrattrs` (server-driven CSR attribute hints). Critically, **CSR Subject Alternative Names are passed through to the issued certificate** — a fix that shipped in PyPKI's Tier 1 work after a latent bug was found that silently dropped them.

> **When EST is the right choice.** Industrial controllers, network equipment, smart-home hubs, IoT gateways, anything running an embedded TLS library with EST support (mbedTLS, wolfSSL, OpenSSL with EST extensions, Cisco IOS, etc.). Cisco's secure on-board enrollment uses EST natively. EST avoids the operational complexity of running a DNS-01 ACME challenge from a thermostat.
>
> **When EST is NOT the right choice.** Anything Kubernetes (cert-manager doesn't speak EST — see `docs/DEPLOYMENT/kubernetes-cert-manager.md`). Anything with a public web fingerprint that can do HTTP-01 ACME. Web-only deployments (use ACME). General-purpose servers with admin access (use CMP via `pypki` CLI or the REST API).

---

## Table of Contents

1. [EST Protocol Overview](#1-est-protocol-overview)
2. [Architecture](#2-architecture)
3. [Step 1 — Configure PyPKI EST Endpoint](#3-step-1--configure-pypki-est-endpoint)
4. [Step 2 — Initial Device Provisioning](#4-step-2--initial-device-provisioning)
5. [Step 3 — Device-Side Enrollment](#5-step-3--device-side-enrollment)
6. [Step 4 — Renewal (`simplereenroll`)](#6-step-4--renewal-simplereenroll)
7. [Authentication Modes](#7-authentication-modes)
8. [Subject Alternative Names](#8-subject-alternative-names)
9. [Operational Notes](#9-operational-notes)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. EST Protocol Overview

EST is a small REST-over-HTTPS protocol defined in RFC 7030. The endpoints PyPKI implements:

| Endpoint | Method | Purpose |
|---|---|---|
| `/.well-known/est/cacerts` | GET | Returns the CA chain in PKCS#7 format. Devices fetch this to populate their trust store on first contact. |
| `/.well-known/est/simpleenroll` | POST | Submit a PKCS#10 CSR; receive a signed cert in PKCS#7. Used for initial enrollment. |
| `/.well-known/est/simplereenroll` | POST | Same as `simpleenroll` but authenticated by the existing cert. Used for renewal. |
| `/.well-known/est/csrattrs` | GET | Returns CSR attribute hints — what extensions and SANs the CA wants in the CSR. Optional but useful. |

All endpoints are HTTPS-only. The `simpleenroll` endpoint is typically authenticated by a one-shot HTTP Basic auth credential or a manufacturer-installed device cert; `simplereenroll` is authenticated by the cert from the previous enrollment.

The protocol is **deliberately minimal**: no DNS, no challenges, no nonces, no rate-limit dance. Just CSR in, cert out. This is what makes it suitable for devices with constrained resources.

---

## 2. Architecture

```
                         ┌──────────────────────────────┐
                         │  PyPKI                       │
                         │                              │
                         │  EST handler at:             │
                         │    /.well-known/est/...      │
   ┌──────────────┐      │                              │
   │ IoT device 1 │ ───► │  Authenticates the device,   │
   ├──────────────┤      │  validates CSR (RFC 2986),   │
   │ IoT device 2 │ ───► │  passes SANs through to leaf │
   ├──────────────┤      │  cert (Tier 1 fix), signs.   │
   │     ...      │ ───► │                              │
   ├──────────────┤      │  Audit-logs every issuance.  │
   │ IoT device N │ ───► │                              │
   └──────────────┘      └──────────────────────────────┘
                                       │
                                       ▼
                              CA private key,
                              certificates.db,
                              audit.db
```

A typical fleet has hundreds to tens of thousands of devices, each enrolling once at first boot and re-enrolling every few months. PyPKI handles enrollment volumes in this range comfortably on Shape A (SQLite). For very large fleets (>100k devices with frequent re-enrollment), Shape B (Postgres) is the right call.

---

## 3. Step 1 — Configure PyPKI EST Endpoint

Enable EST at startup. The default prefix is `/.well-known/est`, which matches RFC 7030 §3.1:

```bash
pypki --ca-dir /var/lib/pypki/ca \
      --tls-cert-self-signed \
      --est-prefix /.well-known/est \
      --est-auth-mode basic \
      --est-basic-realm "Device Enrollment" \
      --listen-port 443
```

Verify the `cacerts` endpoint:

```bash
curl -k https://pki.example.com/.well-known/est/cacerts \
  -H "Accept: application/pkcs7-mime" \
  --output cacerts.p7
openssl pkcs7 -inform DER -in cacerts.p7 -print_certs
```

Should print your CA cert (and any intermediates if you're in two-tier mode). This is what a device fetches on first contact to populate its trust store. If your CA is issued by a parent CA, the chain comes back complete here — that's the intermediate-CA handling that PyPKI does automatically when `<ca_dir>/ca-chain.pem` is present.

---

## 4. Step 2 — Initial Device Provisioning

Each device needs **one piece of bootstrap state** before it can talk to PyPKI: a way to authenticate its first enrollment. There are three common patterns:

### Pattern A — Per-device shared secret

The device manufacturer / provisioning system bakes a unique HTTP Basic password into each device, and writes the same password into PyPKI's `est-auth.json` file (or equivalent). The device uses HTTP Basic on first `simpleenroll`.

This is the simplest pattern. Used in Cisco's stock EST flow, in many HVAC/building-control deployments.

Trade-off: PyPKI now stores N device secrets. Compromise of `est-auth.json` is a fleet-wide problem.

### Pattern B — Manufacturer-installed bootstrap cert

The device ships with a cert signed by the manufacturer's CA. PyPKI is configured to accept that manufacturer CA as a `simpleenroll` client cert authority. The device uses mTLS to authenticate.

Stronger than shared secrets, but requires either:
- Trusting the device manufacturer's CA, or
- Having a documented out-of-band mechanism for the manufacturer to register its CA with PyPKI's trust store.

This is the IEEE 802.1AR (IDevID) pattern — increasingly common in industrial IoT. Cisco IOS devices ship with IDevIDs and use them for first enrollment.

### Pattern C — Bootstrap-time human attestation

A technician on-site enters a one-shot enrollment token into the device's local UI; the token is also configured in PyPKI as a single-use credential. Used in older industrial deployments and in privileged IoT (medical devices, etc.) where the human-in-the-loop is intentional.

PyPKI supports patterns A and B today out of the box. Pattern C requires writing a small auth shim in front of PyPKI — straightforward but device-specific.

---

## 5. Step 3 — Device-Side Enrollment

Most IoT EST clients are part of the device's firmware — Cisco's IOS XE EST client, mbedTLS-based clients, OpenWrt's `est` package, etc. The flow looks the same regardless of the client implementation:

```
1. Device generates a keypair (often in a TPM or secure element).
2. Device builds a PKCS#10 CSR with:
     - subject       CN=<device serial>, O=<org>
     - subjectAltName  DNS:<device-fqdn>, IP:<device-ip>, URI:<spiffe-id>
     - extensions    keyUsage = digitalSignature, keyEncipherment
                     extendedKeyUsage = clientAuth (or serverAuth, both)
3. Device POSTs the CSR (base64 DER) to .well-known/est/simpleenroll,
   authenticated per the chosen mode.
4. PyPKI validates the CSR, applies the configured profile, signs.
5. PyPKI returns a PKCS#7 SignedData containing the leaf cert.
6. Device installs the cert + chain.
```

Test the flow with `openssl` and `curl` from a regular host first:

```bash
# Generate a test keypair and CSR
openssl req -newkey rsa:2048 -nodes -keyout test.key \
  -subj "/CN=test-device-001/O=Example Corp" \
  -addext "subjectAltName = DNS:test-device-001.iot.example.com" \
  -out test.csr

# Convert to base64-DER (no PEM headers)
openssl req -in test.csr -outform DER | base64 > test.csr.b64

# Submit
curl -k -u "device001:secret" \
  https://pki.example.com/.well-known/est/simpleenroll \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  --data @test.csr.b64 \
  --output test-cert.p7

# Inspect the result
openssl pkcs7 -inform DER -in test-cert.p7 -print_certs -text | head -40
```

You should see your CSR's CN and the SANs you specified back in the issued cert's `X509v3 Subject Alternative Name` extension. **If the SAN section is empty or different from what you submitted, PyPKI is on a version before the EST SAN pass-through fix shipped — upgrade.** The bug silently dropped client SANs and signed certs without them.

---

## 6. Step 4 — Renewal (`simplereenroll`)

Renewal works exactly like initial enrollment except authentication is via the existing cert (mTLS), not the bootstrap credential. The device:

1. Detects its current cert is approaching expiry (typically at 50–80% of validity).
2. Generates a new keypair (or re-uses, depending on the device's policy).
3. Builds a new PKCS#10 CSR with the same subject + SANs.
4. POSTs to `simplereenroll` over mTLS, presenting the current cert as the client cert.
5. Receives the new cert in PKCS#7.
6. Installs the new cert and key, transitions, retires the old.

Devices typically retain the old cert for a brief overlap window so any in-flight TLS sessions don't break mid-rotation.

PyPKI's `simplereenroll` accepts the same CSR format as `simpleenroll`. The authentication difference is handled transparently — point the client at the right URL.

---

## 7. Authentication Modes

PyPKI supports the following EST authentication modes:

| Mode | `simpleenroll` | `simplereenroll` | `cacerts` |
|---|---|---|---|
| **HTTP Basic** | Username + password from `est-auth.json` | Same | No auth (per RFC 7030 §4.1.1) |
| **mTLS (manufacturer cert)** | Client cert chained to a configured CA | Same | No auth |
| **Bearer token** | `Authorization: Bearer <token>` against `est-auth-tokens.json` | Same | No auth |

Configure via:

```bash
--est-auth-mode {basic|mtls|bearer|any}
--est-auth-file /etc/pypki/est-auth.json   # for basic/bearer modes
--est-mtls-ca   /etc/pypki/manufacturer-ca.pem  # for mtls mode
```

`--est-auth-mode any` accepts ANY of the configured modes — useful when migrating a fleet from one mode to another.

For high-volume fleets, **bearer tokens are the right call** — easier to rotate than per-device passwords, easier to revoke than client certs, and the device just needs to store a 32-byte string.

---

## 8. Subject Alternative Names

This is where PyPKI's EST implementation has a fix you specifically need to know about. Earlier versions of PyPKI silently dropped client-supplied SANs on `simpleenroll` — every enrolled cert came out with only the CN, no SAN. **This was a bug**, fixed in the Tier 1 work.

In current PyPKI, the EST handler extracts `DNSName`, `RFC822Name`, and `IPAddress` SANs from the incoming CSR's `subjectAltName` extension and passes them through to `issue_certificate(..., san_dns=..., san_emails=..., san_ips=...)`. The issued cert ends up with the SAN extension the client asked for.

URI SANs (used for SPIFFE IDs in service meshes) require an additional `san_uris` parameter on `issue_certificate` that's tracked as a follow-up. If your devices rely on URI SANs (most don't — those are workload-mesh patterns, not IoT patterns), check that against the current PyPKI version before deploying.

You can confirm the SAN handling by enrolling a test cert with a known SAN and comparing:

```bash
# Build a CSR with a specific SAN
openssl req -newkey rsa:2048 -nodes -keyout san-test.key \
  -subj "/CN=san-test" \
  -addext "subjectAltName = DNS:expected-1.example.com, DNS:expected-2.example.com, IP:10.0.0.1" \
  -out san-test.csr

# Enroll
openssl req -in san-test.csr -outform DER | base64 > san-test.b64
curl -k -u "..." https://pki.example.com/.well-known/est/simpleenroll \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  --data @san-test.b64 --output san-test.p7

# Inspect
openssl pkcs7 -inform DER -in san-test.p7 -print_certs -text \
  | grep -A 2 "Subject Alternative Name"
```

Expected output: all three entries (`DNS:expected-1.example.com, DNS:expected-2.example.com, IP Address:10.0.0.1`) present in the issued cert. If only the CN is present and the SAN section is absent, you're on a pre-fix PyPKI — upgrade.

---

## 9. Operational Notes

### Why not ACME for IoT?

ACME is a great protocol for hosts that can serve HTTP-01 challenges or run DNS-01 against a controllable zone. IoT devices typically can do neither — they're behind NAT, don't run a public web server, and don't have control of a DNS zone. EST sidesteps both requirements.

If your IoT devices DO have public HTTP endpoints (rare), ACME is fine. Most don't.

### Why not SCEP for IoT?

SCEP works and is widely deployed in older industrial / network gear. PyPKI supports it. But SCEP has known weaknesses (PSK-style enrollment passwords, no built-in renewal, no chain handling on enrollment) that EST was designed to fix. New deployments: prefer EST. Existing SCEP deployments: keep them on SCEP if migrating is expensive; the security delta isn't huge in PyPKI's typical homelab/SMB threat model.

### Throughput

Each `simpleenroll` is approximately:
- One CSR signature verification (RFC 4211 / RFC 2986)
- One CA private-key signing operation (~1ms on modern x86)
- One database write (audit + cert table)
- One PKCS#7 wrap-and-sign

Expect ~100-500 enrollments/sec on Shape A (SQLite) with default config. The serial-number allocation is the bottleneck under heavy concurrent load (`BEGIN IMMEDIATE` serializes writers in SQLite). If you're enrolling thousands of devices in a flash-deploy event, batch them across an hour or move to Shape B.

### Audit log volume

Every enrollment is one audit log row. A 10k-device fleet that re-enrolls every 30 days = ~333 enrollments/day = ~120k rows/year. Not a big deal. A 100k-device fleet with weekly re-enrollment = ~14k/day = ~5M rows/year. Plan for log rotation or move audit to Postgres.

### Cert validity

Default PyPKI cert validity is 1 year. For IoT, 90-180 days is a more typical sweet spot:
- Short enough that key compromise has bounded impact
- Long enough that renewal isn't constant chatter on the wire
- Long enough to survive periods of device disconnection

Configure per-profile:

```json
{
  "profiles": {
    "iot-device": {
      "validity_days": 180,
      "ekus": ["clientAuth"],
      "default_san_strategy": "from_csr"
    }
  }
}
```

---

## 10. Troubleshooting

**`cacerts` returns 401.**
RFC 7030 §4.1.1 says `cacerts` MUST be available without authentication. PyPKI does this correctly by default; if you're seeing 401, you likely have an HTTP-layer auth filter (nginx auth_basic, Cloudflare access policy) in front of PyPKI — exempt the `cacerts` path.

**`simpleenroll` returns 415 "Unsupported Media Type".**
The client isn't setting `Content-Type: application/pkcs10`. Check your EST client's HTTP setup. Some embedded EST clients use `application/x-pem-file` by mistake; the spec is strict about `application/pkcs10`.

**`simpleenroll` returns 200 but the response is HTML.**
You hit the wrong path. Common mistake: `/.well-known/est/simpleenroll` (correct) vs `/est/simpleenroll` (wrong, depending on `--est-prefix`). Check the prefix PyPKI was started with.

**Issued cert lacks SANs that were in the CSR.**
You're on a pre-Tier 1 PyPKI. Upgrade. The fix is in `est_server.py:_handle_simpleenroll`.

**`simplereenroll` rejects with "client cert not provided".**
mTLS isn't configured at the TLS terminator (PyPKI itself, or nginx in front, or load balancer). Confirm `ssl_verify_client on` (nginx) or `--require-client-cert` (PyPKI) is set for the `simplereenroll` path. The same path serves both `simpleenroll` and `simplereenroll`; the difference is whether mTLS is required, which depends on the protocol direction.

**Devices report "trust anchor expired".**
Your CA cert is approaching expiry, or already expired. Generate a new root, re-issue the chain, distribute to devices via the next `cacerts` fetch. Devices that no longer trust the old root won't be able to talk to PyPKI to fetch the new one — plan the transition with overlapping validity.

**Throughput drops to single-digit enrollments/sec at scale.**
Almost always SQLite write contention. Switch to Postgres (Shape B). See `docs/STORAGE.md` §6.

**Audit log shows enrollment events but device claims it didn't get a cert.**
TLS connection probably terminated mid-response. Check your reverse-proxy timeouts; some load balancers default to 30s, which is fine for `simpleenroll` but can cut off slow EST clients on flaky links. Set `proxy_read_timeout 60s` (nginx) or equivalent.

---

## See also

- `docs/CPS.md` §§3.2-3.4 — what subscriber identification means in EST context.
- `docs/THREAT_MODEL.md` §4 — attacker capabilities against the enrollment endpoint.
- `docs/DEPLOYMENT/offline-root-online-subca.md` — recommended pattern for any IoT fleet large enough to matter.
- `docs/STORAGE.md` — choosing SQLite vs Postgres for fleet sizes.
- RFC 7030 — Enrollment over Secure Transport.
- RFC 2986 — PKCS#10 (the CSR format).
- IEEE 802.1AR — IDevID, the bootstrap-cert pattern referenced above.
