# PyPKI Threat Model

**Document version:** 1.0
**Audience:** PyPKI operators evaluating whether a deployment fits their risk profile, and developers contributing security-sensitive changes.

This document defines the trust boundary, the trusted computing base (TCB), what an attacker who compromises each component can do, what they can't, and the controls that bound the blast radius.

It is deliberately concrete. Vague threat models produce vague defenses; specific ones produce checklists you can actually audit against.

---

## 1. Trusted Computing Base (TCB)

The TCB is the set of components that, if compromised, allow the attacker to forge certificates trusted by relying parties in the operator's domain. **Anything in the TCB is a single point of trust failure.** Anything not in the TCB can be compromised without the attacker forging certs.

### Inside the TCB

| Component | Why it's in the TCB |
|---|---|
| **CA private key** (`<ca_dir>/ca.key`) | Signing key for all certificates. Compromise = unlimited cert forgery. |
| **CA passphrase** | Protects `ca.key` at rest. Compromise + filesystem read = key compromise. |
| **The host running PyPKI** | Holds the decrypted CA key in memory while the process is running. |
| **The OS kernel and initramfs of that host** | Kernel-level access reads process memory, defeating in-memory key protection. |
| **The hypervisor or cloud control plane**, if PyPKI runs in a VM | Live memory snapshots, guest introspection, console access. |
| **Backup media containing `ca.key`** | If unencrypted or weakly encrypted, equivalent to having the live key. |
| **Code that handles signing** (`pki_server.py`, `cmp_server.py`, `est_server.py`, `scep_server.py`, `acme_server.py`, `ipsec_server.py`, `web_ui.py`, `dispatcher_server.py`) | A code-execution bug here = cert forgery without needing the key file. |
| **The Python and OpenSSL versions installed on the host** | Crypto-library bugs are crypto bugs; supply chain compromise is key compromise. |
| **The CA's `certificates.db`** as a write target | Forging an INSERT here lets an attacker register a fake cert as legitimately issued, manipulating later revocation/audit answers. |

### Outside the TCB (compromise-survivable)

| Component | Why compromise is survivable |
|---|---|
| **OCSP responder host** | Holds a delegated OCSP signing cert with `id-pkix-ocsp-nocheck`, `extKeyUsage=ocspSigning`. An attacker who steals it can sign fake OCSP responses but cannot sign new certificates. Mitigation: rotate the OCSP signer (short validity, e.g. 7 days). |
| **CRL distribution endpoint** (HTTP server alone) | Serves a static signed file; tampering is detected by the AKI/cRLNumber check on the relying party. |
| **Web UI session cookies** | A stolen session can issue or revoke certs only through the API; rate-limited and audited. The CA key is not exposed via the Web UI. |
| **Audit log** | Tamper-evident only if backed up immediately offsite. Compromise of the audit DB hurts forensics, not issuance integrity. |
| **`acme.db`, `scep.db`** | Compromise leaks pending state but not the CA key. ACME/SCEP enrollment authentication is independent of the CA key file. |
| **Reverse proxy (nginx, traefik)** | Sits in front of PyPKI; a compromised proxy can inject responses but cannot sign certs. |
| **PAM password store** | Web UI authentication; compromise gives operator-equivalent access to the Web UI but not direct key access. |
| **Subscriber private keys** | Compromise affects only that one subscriber; revocation contains the blast radius. |

The line between "inside" and "outside" the TCB matters. **Investments in defense-in-depth should focus on the inside line.** Outside-the-line components benefit from defenses but losing them is recoverable.

---

## 2. Adversary Model

We consider three adversary classes, ordered from least to most capable.

### 2.1 Network adversary

**Capabilities:** Can read, drop, replay, and modify network traffic between subscribers and PyPKI, between relying parties and the OCSP/CRL endpoints, and between PyPKI and any backend (Postgres, etc.). Cannot run code on the PyPKI host.

**Goals:** Forge certificates, impersonate legitimate subscribers, downgrade revocation responses, replay stale OCSP responses to hide compromise.

**What this adversary CAN do against current PyPKI:**
- Replay cached OCSP responses up to their `nextUpdate` window. *Mitigation:* set short OCSP validity (default 300 seconds via `--ocsp-cache-seconds`); use OCSP nonce in critical paths. RFC 8954 nonce strict mode (`--ocsp-require-nonce`) closes most replay windows.
- Block CRL fetches and force relying parties to fall back to cached or no-revocation-checking. *Mitigation:* relying-party policy must require fresh revocation status on critical paths.
- DoS the responder. *Mitigation:* rate limiting (built-in `RateLimiter` class) + upstream reverse proxy hardening.

**What this adversary CANNOT do:**
- Forge certificates without breaking the CA's signature algorithm.
- Bypass CMP signature protection (RFC 4210 §5.1.3 — closed in this codebase).
- Impersonate a CRMF requester whose POPO they don't have (RFC 4211 §4 — closed).

### 2.2 Authenticated subscriber adversary

**Capabilities:** Has legitimate enrollment credentials (a valid CMP shared secret, an ACME account key, a SCEP OTP, a PAM user account, a REST API key). Network adversary capabilities apply too.

**Goals:** Issue a certificate they're not entitled to (wrong subject, wrong SAN, wider name scope than authorized), escalate privilege, persist after revocation.

**What this adversary CAN do:**
- Issue certificates within their profile's permitted scope. *Bounded by* `CertProfile.allowed_san_dns_patterns` and similar profile checks at issuance time.
- Submit a CRMF requesting a name they don't own. *Mitigation:* operator-configured naming policy in the relevant profile; `validate_csr` / `validate_crmf` rejects non-conformant requests; nameConstraints on the issuing CA further bound what's possible if the operator sets them.
- Replay a captured certConf message. *Mitigation:* CMP transaction IDs are nonces; replay yields a no-op.
- DoS the issuance endpoint. *Mitigation:* rate limiting per credential.

**What this adversary CANNOT do:**
- Issue a certificate matching a name forbidden by the profile.
- Escalate to operator privileges through the issuance API.
- Read or modify the CA private key.
- Read other subscribers' archived keys (operators using the optional key archive feature should ensure profile-level access checks).

### 2.3 Host-compromise adversary

**Capabilities:** Has root or equivalent code execution on the host running PyPKI. May have arrived via an OS vulnerability, a supply-chain compromise of a dependency, an insider attack, or a stolen SSH key.

**Goals:** Steal the CA private key, forge unlimited certificates, persist undetected.

**What this adversary CAN do:**
- Read `<ca_dir>/ca.key`. With the passphrase (or by reading process memory), decrypt and exfiltrate the CA key.
- Read process memory directly to get the in-memory decrypted CA key.
- Modify any database, log, or audit trail before exfiltration.
- Issue arbitrary certificates by interacting with the running PyPKI process or by directly invoking signing APIs.

**What this adversary cannot do without further effort:**
- Forge certificates AFTER the operator notices and rotates the CA. The audit log on a *separate* host (multi-node Postgres audit DB via `--audit-db-url`) gives the operator a chance to detect and respond.
- Forge certificates that pass relying-party AKI checks AFTER the CA cert is replaced and the new chain is deployed.

This adversary is the worst case for PyPKI. The mitigations are operational, not software:
- Run PyPKI on a dedicated host. No general-purpose user accounts, no other services.
- Disk encryption at rest with a key not held on the host (e.g., remote unlock at boot).
- Off-host audit log (`--audit-db-url postgresql://...`) so a host-compromise adversary cannot tamper with their own tracks.
- Regular re-imaging of the host from a known-good source.
- HSM/PKCS#11 support (Tier 5.1 future work) eliminates the in-memory key risk by keeping the key in a separate device. Until that ships, the in-memory key is a real exposure.

---

## 3. Per-component compromise scenarios

For each component, we describe: **what the attacker gets**, **what the attacker still can't do**, and **what controls bound the damage**.

### 3.1 Web UI session token compromise

**Attacker gets:** The ability to authenticate to the Web UI as the compromised operator, with full Web UI privileges.

**Still can't:** Read the CA private key file (no API endpoint exposes it). Bypass rate limiting on issuance. Tamper with the audit log post-hoc (the log is append-only and best-practice goes to a separate DB).

**Controls:**
- Session cookies are HttpOnly and SameSite=Strict.
- CSRF tokens on every state-changing form.
- Brute-force lockout on PAM authentication (5 failures → 15 min lockout).
- Sessions expire after 8 hours of inactivity.
- All issuance and revocation events are audit-logged with `event=issue` / `event=revoke` and the requester's session identity.

**Recovery:** Invalidate all sessions (delete the session DB), force operators to re-authenticate, review audit log for unauthorized actions during the compromise window, revoke certificates issued by the attacker.

### 3.2 OCSP signer key compromise

**Attacker gets:** The ability to sign arbitrary OCSP responses claiming any cert is `good`, `revoked`, or `unknown`.

**Still can't:** Sign new certificates. Modify the actual revocation status in `certificates.db`. Make the CRL lie (CRL is signed by the CA key, not the OCSP signer).

**Controls:**
- The OCSP signer cert has `id-pkix-ocsp-nocheck`, so relying parties don't need to revoke it via OCSP — they just stop trusting it when its short validity expires.
- Default OCSP signer validity is 7 days. Operators can shorten to 24 hours for sensitive deployments.
- The OCSP signer is auto-rotated if it's within 24 hours of expiry.
- The OCSP signer cert is issued from the CA key but not the same key, so its compromise does NOT compromise the CA.

**Recovery:** Revoke the OCSP signer certificate (the CA can do this; the OCSP signer cert is itself in the CA's `certificates.db`). Issue a new OCSP signer with a fresh key. Within one cache cycle (default 300s), all relying parties stop trusting the old OCSP responses.

### 3.3 CA private key compromise

**Attacker gets:** The ability to forge any certificate that chains to this CA.

**Still can't:** Forge certs that chain to a *different* CA. Forge certs after the operator deploys a new CA cert and relying parties re-anchor trust.

**Controls:**
- Disk encryption at rest (LUKS).
- File-level encryption with operator-controlled passphrase (`PYPKI_CA_PASSPHRASE`).
- Audit log records every issuance event; an attacker forging certs offline avoids the audit log, but a sudden surge of certs they later try to use IN BAND will surface in monitoring.
- For deployments that need to rule out this scenario altogether: HSM/PKCS#11 (Tier 5.1) and offline root with online sub-CA (`docs/DEPLOYMENT/offline-root-online-subca.md`).

**Recovery:** This is the worst case. Procedure:
1. Take the CA offline immediately.
2. Notify all subscribers and relying parties out-of-band that certificates issued by this CA are no longer trustworthy.
3. Stand up a new CA with a new key.
4. Distribute the new CA cert to relying parties.
5. Re-issue subscriber certs from the new CA.
6. Publish a final CRL from the old CA revoking all extant certificates as advisory.
7. Treat the entire old issuer as distrusted regardless of CRL.

PyPKI ships no automated tooling for this. **It is a process gap operators must close themselves.** For deployments where this is unacceptable, the only software-level mitigation is HSM-backed keys.

### 3.4 `certificates.db` write access (without code execution)

**Attacker gets:** Ability to mutate the CA's view of issued certs.

**Still can't:** Sign certificates (no key access). Make a relying party trust a cert that PyPKI didn't sign — relying parties verify against the CA cert, not against `certificates.db`.

**What this DOES enable:**
- Hiding the existence of legitimately-issued certs from `recent` audit views and the Web UI listings.
- Marking certs as `revoked=1` without the CA signing a fresh CRL — but this only affects PyPKI's internal view; the next CRL generation overwrites this with the real signed CRL.
- Forging a `key_archive` row to show or hide that a key was archived.

**Controls:**
- The CA dir is owned by the PyPKI service user; no other process should have write access.
- Database-level integrity is not cryptographically protected today; integrity depends on filesystem ACLs.
- For multi-node deployments using Postgres, database-level access controls (`pg_hba.conf`, role-based GRANTs) provide stronger separation.

**Recovery:** Restore from backup, audit the DB diff, decide whether any certs need revocation.

### 3.5 `audit.db` compromise (read or write)

**Attacker gets:** Read access exposes the full history of issuance and revocation events with timestamps. Write access lets the attacker delete evidence of their own actions.

**Still can't:** Affect issuance integrity. The audit DB is observation, not enforcement.

**Controls:**
- Audit DB SHOULD be on a separate filesystem from the CA DB.
- Audit DB SHOULD be on a separate host for high-stakes deployments (`--audit-db-url postgresql://logserver/pypki_audit`).
- Audit log entries SHOULD be replicated to a SIEM in near-real-time.

**Recovery:** Restore from backup, cross-reference with SIEM if available, accept that some audit data may be irrecoverably lost.

### 3.6 REST API key compromise

**Attacker gets:** API-level access to the PyPKI server, including issuance and revocation.

**Still can't:** Read the CA key file (no endpoint exposes it). Bypass profile-level naming-policy checks. Read other API keys' issuance history beyond their own audit attribution.

**Controls:**
- API keys are stored in `pypki.auth.json` and validated on every request.
- Each key is associated with a profile; profile-level restrictions apply.
- All API operations are audit-logged with the key identifier.

**Recovery:** Revoke the API key (delete it from `pypki.auth.json`), audit issuance during the compromise window, revoke any certs the attacker issued.

### 3.7 Subscriber private key compromise

**Attacker gets:** The ability to impersonate that one subscriber until the cert expires or is revoked.

**Still can't:** Affect any other subscriber. Issue new certs.

**Controls:**
- Standard X.509 revocation: subscriber requests revocation via CMP `rr` or out-of-band, operator revokes via Web UI / API, CRL and OCSP propagate the change.
- Short cert lifetimes bound the maximum exposure window.

**Recovery:** Revoke the cert. Issue a new cert with a fresh key.

---

## 4. Defense-in-depth controls implemented today

| Control | Where | Defends against |
|---|---|---|
| CA key passphrase encryption | `pki_server.py:CertificateAuthority._load_or_create_ca_key` | Cold-disk attacks (stolen backup, decommissioned drive) |
| CA passphrase from env var (not CLI) | `PYPKI_CA_PASSPHRASE` | Process listing exposure (`ps auxe`) |
| API key authentication | `pypki.auth.json` | Unauthenticated cert issuance |
| PAM-based Web UI auth | `pki_server.py:PAMAuthenticator` | Web UI as an unauthenticated bypass |
| PAM brute-force lockout | `pki_server.py:_pam_lockout` | Online password guessing |
| CSRF protection | `web_ui.py:_check_csrf` | Cross-origin request forgery |
| HTML escaping | All Web UI responses | Stored / reflected XSS |
| Rate limiting | `pki_server.py:RateLimiter` | DoS, brute force across endpoints |
| CMP response signature protection (RFC 4210 §5.1.3) | `cmp_server.py:CMPv2Handler._protected_response` | Strict CMP clients accepting tampered responses |
| CRMF POPO verification (RFC 4211 §4) | `cmp_server.py:CMPv2ASN1.verify_popo` | Issuance for third-party public keys |
| CRL `cRLNumber` + AKI (RFC 6818) | `pki_server.py:CertificateAuthority._next_crl_number` | CRL substitution attacks |
| OCSP nonce length enforcement (RFC 8954) | `ocsp_server.py:OCSPRequestParser.parse` | Non-spec malformed nonces |
| Audit log on every CA action | `pki_server.py:AuditLog` | Undetected unauthorized issuance |
| Atomic serial allocation | `pki_server.py:_next_serial` | Serial reuse race |
| `BEGIN IMMEDIATE` on CRL number | `pki_server.py:_next_crl_number` | CRL number reuse |
| `nameConstraints` on sub-CAs | `pki_server.py:issue_sub_ca` | Wide-scope sub-CA misissuance |

---

## 5. Known gaps (not yet mitigated)

| Gap | Severity | Mitigation track |
|---|---|---|
| CA key in process memory while running | Medium | Tier 5.1: HSM/PKCS#11 |
| No multi-person control on issuance | Low (homelab) → High (enterprise) | Tier 5.4: RA workflow |
| No automated CA-key-compromise response | High | Future-work |
| No cross-signing or smooth CA rollover | Medium | Tier 5.6 |
| Audit log not cryptographically chained (tamper-evident only via filesystem ACLs) | Low (homelab) → Medium (enterprise) | Future-work |
| 7 internal-key-write sites still emit PKCS#1 / SEC1 (cosmetic; not client-facing) | Low | Follow-up RFC 5958 cleanup pass |
| Pre-existing test `TestOCSPParsing::test_ocsp_server_starts_and_responds` uses old positional signature; broken since the dispatcher refactor | Negligible | Test rewrite |

This list is intentionally complete. Operators who need to close any of these gaps should treat the corresponding track as a deployment prerequisite, not a future enhancement.

---

## 6. References

- RFC 5280 — X.509 PKI certificate and CRL profile
- RFC 4210, RFC 9480 — CMP / Lightweight CMP Profile
- RFC 4211 — CRMF
- RFC 6960, RFC 8954 — OCSP and nonce profile
- NIST SP 800-57 — Key management lifecycle guidance
- BSI TR-03145 — Secure CA operations (German federal guidance, generally applicable)
- `docs/CPS.md` — Certification Practice Statement
- `docs/DEPLOYMENT/*.md` — per-deployment specifics
