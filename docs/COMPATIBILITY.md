# PyPKI Compatibility Matrix

This document records which client tools and library versions PyPKI has been tested against, and the known interoperability quirks.

**This is a working document.** Versions listed as "tested" have an actual test run behind them; versions listed as "expected to work" are extrapolation from the protocol RFC compliance and have not been verified end-to-end. **Do not assume a version works in production without your own validation.**

Last updated: _to be set per release_
PyPKI version: _to be set per release_

---

## Runtime

| Component | Minimum | Tested | Notes |
|---|---|---|---|
| Python | 3.12 | 3.12.3 | `match` statements, `Self` type, modern `typing` features |
| OpenSSL (via `cryptography`) | 3.0 | 3.0.x, 3.2.x | `cryptography` library wraps OpenSSL; minimum tied to library version |
| `cryptography` | 41.0 | 42.0.x, 43.0.x | RFC 8410 Ed25519 support requires ≥ 41.0 |
| SQLite | 3.35 | 3.40+ | `RETURNING` clause used by DAL |
| PostgreSQL (optional, via DAL) | 13 | 14, 15, 16 | Required only if `--db-url postgresql://` is used |
| psycopg | 3.1 | 3.1.x, 3.2.x | psycopg2 is NOT supported (in maintenance mode) |

---

## ACME clients (RFC 8555)

| Client | Version | Status | Notes |
|---|---|---|---|
| acme.sh | 3.0.7 | Tested | http-01, dns-01 with custom hooks (see `pihole-acme-dns01.md`); EAB not yet tested |
| certbot | 2.6.0 | Tested | Manual + auto modes |
| lego (Go) | 4.14.x | Tested | Use as a library or CLI; works against PyPKI's directory |
| dehydrated | 0.7.x | Expected to work | Standard RFC 8555 client; not in CI |
| cert-manager (k8s) | 1.13, 1.14 | Tested | Via the `ACME` issuer; account creation, http-01, dns-01 all work |
| Caddy auto-HTTPS | 2.7.x | Expected to work | Caddy uses lego internally |

**Known quirks:**
- ACME accounts created with one client can be reused by another only if the JWK matches (per RFC 8555). PyPKI honors this.
- PyPKI does not yet implement External Account Binding (EAB, RFC 8555 §7.3.4) — Tier 5.5 future work. Clients that require EAB cannot enroll.
- ACME ARI (RFC 9773 renewal indication) is not implemented.

---

## CMP clients (RFC 4210, RFC 9480 / RFC 9483 Lightweight CMP Profile)

| Client | Version | Status | Notes |
|---|---|---|---|
| OpenSSL `cmp` (≥3.0) | 3.0.x, 3.2.x | Tested | `openssl cmp -cmd ir -server …` works for ir/cr/kur/rr |
| EJBCA CMP | 7.x, 8.x | Tested | Strict RFC 4210 §5.1.3 protection check passes (PyPKI ships RFC 4210 §5.1.3 protection as of recent codebase) |
| strongSwan pki | 5.9+ | Tested | IPsec gateway enrollment via CMP |
| GenericCMPClient (CISCO) | 1.0+ | Expected to work | Used in industrial PKI; not in CI |

**Known quirks:**
- Before the RFC 4210 §5.1.3 fix, strict EJBCA configurations would reject PyPKI responses for missing `[0] PKIProtection`. **All strict clients now work** as of the protection fix.
- POPO verification is enforced (RFC 4211 §4 case 2). Clients that don't include POPO with their CRMF are rejected with `badPOP` failInfo. Use `openssl cmp` ≥3.0 (which generates POPO correctly) rather than older versions.
- CMPv3 (RFC 9480) framing is supported; PyPKI auto-detects pvno=2 vs 3.

---

## SCEP clients (RFC 8894)

| Client | Version | Status | Notes |
|---|---|---|---|
| sscep | 0.10.0 | Tested | Linux command-line SCEP client |
| jscep (Java) | 2.5.x | Tested | Used by IoT device SDKs |
| Apple iOS SCEP enrollment | iOS 16+, 17+ | Tested | Via configuration profile (`.mobileconfig`) |
| Microsoft NDES | Windows Server 2019+ | Expected to work | Standard SCEP; not yet in CI |
| Cisco IOS / strongSwan SCEP | 16+ / 5.9+ | Tested | Network device enrollment |

**Known quirks:**
- PyPKI requires the SCEP transaction's SHA-256 messageDigest by default. Older clients sending SHA-1 should be upgraded; SHA-1 is not enabled by default in PyPKI.
- One-Time Password (OTP) authentication is supported but the OTP store must be operator-managed (Tier 5.8 — proper OTP lifecycle is future work).

---

## EST clients (RFC 7030)

| Client | Version | Status | Notes |
|---|---|---|---|
| libest | 3.x | Expected to work | Cisco's reference EST library |
| `est-client` (PyPKI test harness) | bundled | Tested | Used internally for CI |
| OpenSSL EST plugin | 3.2+ | Expected to work | Reference EST client |
| cert-manager EST issuer | none stable | Not recommended | cert-manager's EST support is via external-issuer plugins; brittleness varies |

**Known quirks:**
- CSR Subject Alternative Names are properly forwarded to issuance (the EST `_handle_simpleenroll` SAN-pass-through fix). Older PyPKI builds silently dropped all SANs from incoming CSRs — verify your build is recent.
- URI-SAN (SPIFFE) pass-through is **not yet implemented** — needs `san_uris` parameter in `issue_certificate`. Use CMP for SPIFFE identity issuance until this lands.
- HTTP Basic auth is supported. mTLS bootstrap (`/.well-known/est/simplereenroll`) is supported only if the requester presents an existing valid PyPKI-issued cert.

---

## Service mesh / Kubernetes

| Tool | Version | Status | Notes |
|---|---|---|---|
| cert-manager (CA issuer) | 1.13, 1.14 | Tested | Sub-CA bootstrapped from PyPKI; see `kubernetes-cert-manager.md` |
| cert-manager-istio-csr | 0.7+ | Tested | Istio control plane requesting from cert-manager |
| Istio | 1.20+ | Tested | Workload mTLS via cert-manager-istio-csr |
| Linkerd | 2.14+ | Expected to work | Via trust-manager + cert-manager |
| SPIRE | 1.8+ | Expected to work | Federation with PyPKI via SPIFFE Federation API |
| trust-manager | 0.6+ | Tested | Bundle distribution |

---

## OCSP / CRL clients

| Client | Status | Notes |
|---|---|---|
| OpenSSL `ocsp` | Tested | `openssl ocsp -url …` works against PyPKI's OCSP responder |
| Java cert-path validator (default) | Tested | OCSP and CRL fetch both work; AIA pointer honored |
| Browsers (Firefox, Chrome) | Tested | OCSP stapling via reverse proxy; direct OCSP queries also supported |
| Go `crypto/x509` | Tested | Standard library validation honors AIA + CDP from PyPKI certs |
| Windows CryptoAPI | Tested | OCSP nonce extension processed correctly per RFC 8954 |

**Known quirks:**
- PyPKI emits OCSP responses with `nextUpdate` set 5 minutes in the future by default. Clients that aggressively re-query (faster than that interval) hit the cache, which is the intended behavior.
- With `--ocsp-require-nonce`, clients that never include a nonce extension are rejected with `unauthorized`. Most modern clients DO include a nonce; this only affects very old clients.
- The CRL includes both `cRLNumber` (RFC 6818 §1.2) and `authorityKeyIdentifier` (RFC 5280 §5.2.1). Validators that check these will correctly verify; validators that don't are not violating the spec but they ARE missing useful information.

---

## Reverse proxies in front of PyPKI

| Proxy | Tested | Notes |
|---|---|---|
| nginx | 1.22, 1.24 | Default deployment companion; see `homelab-single-node.md` |
| Caddy | 2.7.x | Works; auto-HTTPS handles its own TLS, PyPKI is the upstream |
| HAProxy | 2.6+, 2.8+ | Works; care with `ssl_passthrough` for CMP/SCEP that need raw bodies |
| Traefik | 2.10+, 3.0+ | Works |
| Cloudflare Tunnel | n/a | Use only with explicit auth in front; CF doesn't authenticate per-request by default |

---

## Operating systems

| OS | Tested | Notes |
|---|---|---|
| Debian 12 (Bookworm) | Yes | Recommended host OS for homelab + small-team |
| Ubuntu 22.04 LTS | Yes | Drop-in replacement for Debian 12 |
| Ubuntu 24.04 LTS | Yes | Recommended for new deployments |
| Fedora 39+ | Yes | Works; SELinux denials may need policy adjustments for `/etc/dnsmasq.d/` writes (in the Pi-hole hook scenario) |
| Alpine 3.18+ | Partial | Works in Docker but musl-vs-glibc cryptography quirks have surfaced in the past — pin a known-good `cryptography` wheel |
| RHEL/Rocky 9 | Expected to work | Not in CI |
| OpenWrt | Partial | Used as ACME client only, not as PyPKI host |
| Windows | Not supported | PyPKI uses Unix-only paths (`/etc/`, PAM, `os.fork`-style HTTP server, etc.) |

---

## Authenticode / TSA (RFC 3161)

PyPKI does **not** operate a Time-Stamp Authority. For Authenticode, eIDAS, and other time-stamped signing, integrate an external TSA:

- DigiCert Quovadis TSA (commercial)
- FreeTSA (free, slow)
- Self-hosted: `openssl ts` based responders

Tier 2 future work includes shipping a built-in RFC 3161 TSA in PyPKI.

---

## Reporting interop issues

If you hit a compatibility problem, please file an issue with:

1. PyPKI version and `python --version`
2. Client tool name and version (`acme.sh --version`, `openssl version`, etc.)
3. Exact command line that failed
4. Wire capture or full server log of the failed exchange (with secrets redacted)

The TODO list of "expected to work" entries above is also where contributions are welcome — running CI against a new client and converting "expected to work" to "tested" is the most useful single thing you can do here.

---

## References

- [CPS.md](CPS.md) — Certification Practice Statement
- [THREAT_MODEL.md](THREAT_MODEL.md) — adversary model
- [DEPLOYMENT/](DEPLOYMENT/) — per-deployment guides
