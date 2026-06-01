# PyPKI Threat Model

**Document version:** 2.0
**Last reviewed:** 2026-06-01 (Tier 6 walkback — covers all Tier 5 surfaces)
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

---

## 3b. Post-Tier-5 surface walkback

The following surfaces were added after the original Tier-4 threat model. Each is tabletop'd here per the 6.3 spec format.

### 3b.1 RA approval workflow

**Trust boundary:** Requester → RA approver → CA operator. RA approvers can approve or deny pending requests but cannot issue certificates directly.

**Asset:** Issuance authority — the ability to cause the CA to sign a certificate.

**Attackers:**
- Compromised requester: submits a request with a misleading subject or SAN, hoping an inattentive RA approves it.
- Compromised RA approver: approves requests they should deny; cannot forge the CA signature.
- Colluding requester + RA approver: both controlled by the same attacker — dual-party control is defeated.

**Threats:**
- *Spoofing*: requester claims a subject name they don't own. RA approval is the control; the RA must verify out-of-band.
- *Elevation of privilege*: RA approver attempts to approve a request outside their designated profile or tenant. Currently bounded by profile-level checks in `pki_server.py:issue_certificate()`.
- *Repudiation*: RA denies having approved a cert. Mitigated by audit log.

**Existing mitigations:**
- `pki_server.py:_handle_ra_approve` records `audit: ra_approve` with the approver identity before calling `issue_certificate()`.
- `audit` table captures the approver's session token; `web_ui.py:_api_ra_approve` logs approver identity.
- Profile constraints (`CertProfile.allowed_san_dns_patterns`) apply after RA approval — RA cannot override profile policy.

**Residual risk:**
- No dual-control: one RA can unilaterally approve. Accepted for current deployment profiles; operator runbooks should require two approvers for high-value profiles.
- RA approver identity is session-bound, not cryptographically signed. An attacker who steals the RA session cookie can approve requests.

**Tests:** `TestWebUIRAQueue` (approval, denial, audit logging)

---

### 3b.2 ACME External Account Binding (EAB)

**Trust boundary:** ACME server (PyPKI) ↔ ACME client (certbot, acme.sh, etc.) via HMAC-bound account key.

**Asset:** ACME enrollment authorization — the right to obtain a certificate for a domain.

**Attackers:**
- Attacker with network access who has observed the HMAC key in transit.
- Attacker who compromises the system that distributed the HMAC key.

**Threats:**
- *Spoofing*: attacker creates an ACME account using a stolen EAB HMAC key, enrolls for domains they don't control.
- *Replay*: captured EAB binding request replayed to a different ACME server.
- *Enumeration*: attacker brute-forces short EAB key IDs to find valid keys.

**Existing mitigations:**
- EAB keys are 32-byte random (`secrets.token_bytes(32)`); brute-force is infeasible.
- EAB key IDs are random UUIDs; enumeration is infeasible.
- EAB `externalAccountBinding` JWS is bound to the account key via HMAC-SHA256 — a key stolen after binding is useless to a different account.
- Each EAB key is single-use: once bound to an account, it cannot be reused (`acme.db:eab_keys.used=1`).
- Rate limiting applies to account creation.

**Residual risk:**
- EAB HMAC keys are stored in plaintext in `acme.db`. An attacker with DB read access can extract and use un-consumed keys. Accepted: DB access is already a serious compromise (§3.4 scope).
- Distribution channel for EAB keys to legitimate clients is out-of-scope for PyPKI; operators must secure it.

**Tests:** `TestACMEEAB` (binding validation, single-use enforcement, HMAC verification)

---

### 3b.3 ACME per-account rate limiting

**Trust boundary:** ACME server ↔ authenticated ACME account.

**Asset:** Issuance capacity — preventing one account from consuming all CA resources or disrupting others.

**Attackers:**
- Authenticated ACME account holder who submits orders in a tight loop.
- Attacker who has compromised an ACME account key and weaponizes it for DoS.

**Threats:**
- *DoS*: flooding the order endpoint causes issuance queue exhaustion for other accounts.
- *Account enumeration via rate-limit responses*: rate-limit error leaks which accounts are active.

**Existing mitigations:**
- `RateLimiter` class in `pki_server.py` applies per-IP and per-credential limits to all issuance endpoints including ACME.
- ACME rate-limit responses return `urn:ietf:params:acme:error:rateLimited` without revealing account enumeration data.

**Residual risk:**
- Per-account (not just per-IP) rate limiting is not yet implemented; shared-IP deployments (NAT, proxies) are less well protected. Accepted for current traffic profile; revisit when multi-tenancy ships.

**Tests:** `TestRateLimiter`, `TestACMERateLimit`

---

### 3b.4 Cross-signing

**Trust boundary:** CA operator ↔ external CA or sub-CA requesting a cross-signature from PyPKI's CA.

**Asset:** Trust path — an attacker-controlled CA cross-signed by a legitimate CA can sign arbitrary certs trusted by relying parties.

**Attackers:**
- Attacker who submits a CSR with a misleading Subject, causing PyPKI to cross-sign an attacker-controlled CA.
- Insider who uses the cross-sign API without proper out-of-band verification.

**Threats:**
- *Misissuance*: PyPKI cross-signs a CA cert without verifying the subject name matches the legitimate CA.
- *Chain confusion*: cross-signed cert has wider name constraints than the original CA, expanding the trust scope.

**Existing mitigations:**
- Cross-signing is a privileged operator action requiring an authenticated admin session.
- The cross-signed CSR is validated for basic structure before signing.
- All cross-sign events are audit-logged with the operator identity and CSR subject.
- `nameConstraints` on the cross-signed CA can be set by the operator to bound scope.

**Residual risk:**
- No automated out-of-band verification of the CSR subject is possible. This is inherently a policy/process control. Operators MUST verify the CSR subject independently before clicking approve.
- Cross-signing a compromised CA cert cannot be undone without revoking the cross-signed cert and re-distributing the updated CRL. Accepted.

**Tests:** `TestCrossSign` (structure validation, audit logging, name constraints)

---

### 3b.5 Paired ML-DSA + classical issuance (RFC 9763)

**Trust boundary:** CA ↔ relying party chain validator.

**Asset:** Certificate validity — relying parties trust both the classical and ML-DSA certs in the pair.

**Attackers:**
- Attacker who obtains only the classical cert and attempts to use it without the ML-DSA counterpart.
- Attacker who causes a rollback to classical-only validation, bypassing PQC requirements.

**Threats:**
- *Downgrade*: relying party that accepts either cert individually without checking the `RelatedCertificate` extension can be tricked with a classical-only cert from an algorithm-agile CA.
- *Revocation inconsistency*: classical cert is revoked but ML-DSA cert is not (or vice versa), leaving one path usable.

**Existing mitigations:**
- `RelatedCertificate` extension (RFC 9763 §4) links paired certs bidirectionally.
- Both certs in a pair share the same serial allocation logic; revocation must be applied to both (operator procedure, not automated).
- Audit log records both issuance events with a shared `pair_id` tag in the detail field.

**Residual risk:**
- Revocation of a paired cert does NOT auto-revoke its counterpart. This is a known gap. Operators must revoke both manually. Documented in `docs/DR.md`.
- Relying-party enforcement of `RelatedCertificate` is not mandated by RFC 9763; classical-only relying parties remain unaware of the pairing. Accepted: the extension is advisory.

**Tests:** `TestRFC9763PairedCerts` (bidirectional extension, serial assignment, audit)

---

### 3b.6 CT pre-cert submission

**Trust boundary:** PyPKI ↔ CT log server.

**Asset:** Certificate transparency — every issued cert should appear in at least one CT log before being returned to the subscriber.

**Attackers:**
- Hostile CT log: returns a fake SCT that does not actually commit the pre-cert.
- CT log unavailability: blocks issuance if PyPKI requires an SCT.

**Threats:**
- *SCT forgery*: log returns a syntactically valid but cryptographically invalid SCT. Relying parties with STH verification would reject the cert.
- *Log misbehaviour*: log commits the pre-cert to a split view, hiding it from auditors.
- *Availability-based DoS*: CT log goes offline; if PyPKI requires an SCT before issuance, the CA is DoS'd.

**Existing mitigations:**
- SCT injection is opt-in (`--ct-log-url`). When not configured, no CT submission occurs and no SCT is embedded.
- SCT is verified for structural correctness (length, version) before embedding.
- CT log unavailability is treated as a non-fatal warning unless `--ct-require-sct` is set.
- All CT submission outcomes are audit-logged.

**Residual risk:**
- PyPKI does not verify SCT cryptographic signatures (requires the log's public key and is a verification concern for relying parties, not the CA). Accepted.
- Split-view attacks are a systemic CT ecosystem problem, not solvable at the CA layer. Accepted.

**Tests:** `TestCTPrecert` (SCT injection, structural validation, fallback on log unavailability)

---

### 3b.7 Lifecycle webhooks

**Trust boundary:** PyPKI ↔ external webhook receiver.

**Asset:** Webhook integrity — receivers can act on lifecycle events without being spoofed.

**Attackers:**
- Attacker who controls the network path between PyPKI and the webhook receiver.
- Attacker who injects a fake webhook URL into config (requires CA operator access).
- Compromised webhook receiver that is used as an SSRF pivot.

**Threats:**
- *SSRF*: webhook URL can be configured to point at internal services; PyPKI will POST to them on every cert event.
- *Replay*: a captured webhook request replayed to the receiver after the event occurred.
- *Spoofing*: attacker crafts a webhook POST that looks like it came from PyPKI.

**Existing mitigations:**
- Webhook receiver URL is operator-configured; requires CA operator access to change.
- Webhook payload includes a timestamp and event ID; receivers should reject replays outside a time window.
- `--webhook-secret` HMAC-SHA256 signs every outbound webhook; receivers SHOULD verify the signature.
- Webhook delivery is non-blocking: a slow or failing receiver does not block issuance.
- All webhook delivery attempts (success/failure) are audit-logged.

**Residual risk:**
- SSRF: no URL allow-listing is implemented. An attacker with CA operator access could point the webhook at `http://169.254.169.254/` (AWS IMDS). Accepted: CA operator access already implies full system compromise. Documented: operators should restrict outbound network from the CA host.
- Receivers that don't implement HMAC verification are unprotected against spoofing. Accepted: receiver hardening is out-of-scope.

**Tests:** `TestWebhooks` (delivery, HMAC signing, non-blocking failure, audit logging)

---

### 3b.8 HSM / PKCS#11 backend

**Trust boundary:** PyPKI ↔ HSM device.

**Asset:** CA private key — stored in the HSM, inaccessible to software.

**Attackers:**
- Attacker with physical access to the HSM.
- Attacker who compromises the PKCS#11 PIN (software side).
- Attacker who severs the HSM connection during signing.

**Threats:**
- *PIN exposure*: PKCS#11 PIN logged or visible in process listing.
- *Key extraction*: HSM configured with `CKA_EXTRACTABLE=TRUE` allows software key export.
- *Session hijack*: PKCS#11 session handle captured and replayed by another process.
- *Denial of signing*: HSM yanked during `C_Sign`; in-flight signing fails.

**Existing mitigations:**
- PKCS#11 PIN is read from `PYPKI_HSM_PIN` environment variable, never from CLI args.
- `hsm_backend.py` never logs the PIN value; only logs slot/token identifiers.
- Key is loaded with `CKA_EXTRACTABLE=FALSE` by default.
- HSM disconnect during signing raises `pkcs11.exceptions.DeviceError`; `issue_certificate()` propagates the exception (no partial cert is returned). The audit log entry is not written for failed signings.
- Advisory lock `"serial-allocation"` is still held during the HSM sign operation, preventing serial reuse if a second request races.

**Residual risk:**
- Physical HSM access is outside PyPKI's threat model. Operators must secure the device physically.
- PKCS#11 session handle leaks between threads are a risk if `hsm_backend.py:get_session()` is called from multiple threads simultaneously. Current implementation uses a thread-local session; review required if thread pool is enlarged.

**Tests:** `TestHSMBackend` (PIN not logged, key not extractable, disconnect handling)

---

### 3b.9 Postgres dual-backend

**Trust boundary:** PyPKI ↔ Postgres server.

**Asset:** Certificate state — serials, revocation status, audit log.

**Attackers:**
- Attacker with read access to the Postgres replica.
- Attacker who causes a Postgres failover during issuance.

**Threats:**
- *Replica lag at OCSP query time*: OCSP query hits a replica that hasn't yet replicated the latest revocation; returns stale `good` response.
- *Advisory lock failure on failover*: `advisory_lock("serial-allocation")` held on the primary is lost when the standby promotes; two processes may allocate the same serial.
- *Credential theft*: Postgres connection string in config contains the DB password.

**Existing mitigations:**
- Postgres connection string is passed via `--db-url` (config file, not CLI) or `PYPKI_DB_URL` environment variable.
- OCSP responses are pre-generated and signed at issuance time; a stale replica is only a risk for live on-demand OCSP. Operators should configure OCSP to use the primary for live responses.
- Advisory locks are session-scoped in Postgres; a failover releases all locks held by the old primary session. `_next_serial()` will re-acquire the lock on reconnect.
- TLS to Postgres is required by the connection string (`sslmode=require` enforced in docs).

**Residual risk:**
- Short window during Postgres failover where serial uniqueness could be violated if two PyPKI instances both lose and re-acquire the lock concurrently. The probability is very low but not zero. Mitigation: use a 20-byte random serial (RFC 5280 default); collision probability is negligible.
- Replica-lag OCSP is a real gap for on-demand OCSP deployments. Operators must ensure OCSP reads from the primary or accept the window. Documented in `docs/DEPLOYMENT/postgres.md`.

**Tests:** `TestPostgresBackend` (serial uniqueness under concurrent issuance, connection retry)

---

### 3b.10 Pre-generated OCSP responses

**Trust boundary:** CA ↔ OCSP cache on disk ↔ OCSP responder.

**Asset:** Revocation currency — OCSP responses must reflect actual revocation state.

**Attackers:**
- Attacker who can write to the pre-generated OCSP cache directory.
- Attacker who revokes a cert and expects the OCSP response to update immediately.

**Threats:**
- *Stale good*: a cert is revoked between pre-gen runs; relying parties querying cached responses see `good` for a revoked cert.
- *Cache tampering*: attacker replaces a valid pre-generated response with a forged `good` response.
- *Response reuse*: old pre-generated response replayed after the `nextUpdate` time.

**Existing mitigations:**
- Pre-generated responses are DER-signed by the OCSP signer key; tampering produces an invalid signature detectable by relying parties.
- Pre-gen responses have a `nextUpdate` field; well-behaved relying parties reject responses past `nextUpdate`.
- The cache is regenerated on a configurable schedule (default: every 300 seconds, same as `--ocsp-cache-seconds`); the stale window is bounded.
- On-demand live signing is available for environments where the stale window is unacceptable (`--ocsp-live-signing`).

**Residual risk:**
- Maximum stale window = pre-gen interval (default 300s). For revocations in the first few seconds of the interval, the stale window can approach the full interval. Accepted for most deployments; high-security operators should use live signing.
- The cache directory must be writable by PyPKI and readable by the OCSP responder. Filesystem ACL misconfiguration is a risk. Documented in `docs/DEPLOYMENT/ocsp.md`.

**Tests:** `TestOCSPPregeneration` (response signature, nextUpdate, stale revocation window)

---

### 3b.11 SCEP one-time challenges (OTC)

**Trust boundary:** SCEP server ↔ SCEP client (device).

**Asset:** Enrollment authorization — only devices with a valid OTC should be able to enroll.

**Attackers:**
- Attacker who intercepts the OTC in transit.
- Attacker who brute-forces short OTCs.
- Attacker who replays a used OTC.

**Threats:**
- *OTC interception*: if the channel delivering the OTC to the device is unencrypted, an attacker can capture and use it first.
- *Brute force*: short OTCs (e.g., 4-digit PINs) are guessable in O(10^4) attempts.
- *Replay*: used OTC replayed before the TTL expires.

**Existing mitigations:**
- OTCs are 32-character hex strings (128 bits of entropy); brute-force is infeasible.
- Each OTC is single-use: once consumed in a successful enrollment, `scep.db` marks it `used=1`.
- OTCs have a configurable TTL (default 24 hours); expired OTCs are rejected.
- Failed OTC attempts are rate-limited per source IP.
- All OTC consumption events are audit-logged.

**Residual risk:**
- OTC delivery channel security is out-of-scope for PyPKI. Operators must secure the channel (e.g., use HTTPS to the management portal, not email/SMS in plaintext). Documented in `docs/DEPLOYMENT/scep.md`.
- OTCs are stored in `scep.db`. DB read access exposes unconsumed OTCs. Accepted: DB access is already a serious compromise level.

**Tests:** `TestSCEPOTC` (single-use, TTL expiry, rate limiting, replay rejection)

---

### 3b.12 Non-RSA CA key types (Ed25519, Ed448, ECDSA, ML-DSA)

**Trust boundary:** CA ↔ relying parties that must recognize the signature algorithm.

**Asset:** Certificate signatures — must be verifiable by relying parties.

**Attackers:**
- Attacker who exploits algorithm-specific implementation bugs in `pki_server.py` or `slh_dsa.py`.
- Relying party that doesn't support the CA's algorithm and falls back to a weaker trust anchor.

**Threats:**
- *Algorithm confusion*: a cert signed with one algorithm is presented as signed with another; OID mismatch in TBSCertificate vs. outer signature.
- *Implementation bug*: hand-rolled ML-DSA TBSCertificate DER has an encoding error that produces an invalid cert accepted only by PyPKI's own validator.
- *Downgrade*: relying party that supports both Ed25519 and RSA accepts an RSA cert for a subject the CA intended to protect with Ed25519.

**Existing mitigations:**
- `_sig_alg_der_for_key()` in `pki_server.py` maps key type to the correct algorithm OID; the same function is used for both TBSCertificate `signature` field and the outer `signatureAlgorithm` field. Mismatch is structurally impossible if the function is called correctly.
- ML-DSA certificate DER is built by `issue_ml_dsa_certificate()`; the test suite (`TestMLDSA`) verifies round-trip with `openssl verify` using the oqs-provider.
- SLH-DSA leaf certs (`slh_dsa.py`) hand-roll SPKI/PKCS#8 DER; tested against known-good DER encodings.
- All algorithm OID mappings have regression tests.

**Residual risk:**
- Algorithm agility for CA keys is enabled by operator configuration. Operators who switch CA key type mid-deployment must re-distribute the new CA cert. This is a process risk, not a code risk.
- ML-DSA is FIPS 204 finalized but still settling in the ecosystem. Cert profiles gated behind `--enable-mldsa` (default off in production).

**Tests:** `TestMLDSAX509`, `TestSLHDSAX509`, `TestCompositeMLDSA` (round-trip, OID correctness, interop)

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
| Hash-chained audit log | `audit_chain.py:append` | Undetected audit log tampering |
| HSM / PKCS#11 key backend | `hsm_backend.py:HSMBackend` | CA key extraction from process memory |
| RA dual-party approval workflow | `pki_server.py:_handle_ra_approve` | Unauthorized issuance via single approver |
| ACME EAB single-use enforcement | `acme_server.py:_validate_eab` | EAB key replay after account creation |
| SCEP OTC single-use + TTL | `scep_server.py:_validate_challenge` | OTC replay and brute-force |
| Webhook HMAC-SHA256 signing | `hooks.py:_fire_webhook` | Spoofed webhook delivery to receivers |
| Backup AES-256-GCM + scrypt | `backup.py:BackupEngine.encrypt` | Cold-disk backup compromise |
| Ed25519 manifest signing on backups | `backup.py:BackupEngine.sign` | Backup tampering before restore |
| Emergency halt gate | `pki_server.py:issue_certificate` | Issuance during recovery/investigation |

---

## 5. Known gaps (not yet mitigated)

Gaps marked ✓ have been closed in Tier 5 or Tier 6; they remain here so the resolution is documented.

| Gap | Severity | Status | Mitigation track |
|---|---|---|---|
| CA key in process memory while running | Medium | ✓ Closed (Tier 5) | `hsm_backend.py:HSMBackend` — PKCS#11 keeps key in device |
| No multi-person control on issuance | Low→High | ✓ Closed (Tier 5) | RA workflow (`pending_requests` table, `web_ui.py:_api_ra_approve`) |
| No cross-signing or smooth CA rollover | Medium | ✓ Closed (Tier 5) | `web_ui.py:_api_cross_sign`, `cross.signed` audit event |
| Audit log not cryptographically chained | Low→Medium | ✓ Closed (Tier 5) | `audit_chain.py` — hash-chained `chain_hash` column |
| Paired-cert revocation not atomic | Medium | Open | Revoking one cert does not auto-revoke its RFC 9763 counterpart. Operator must revoke both. Documented in `docs/DR.md`. |
| No automated CA-key-compromise response | High | Open | Requires out-of-band notification + manual ceremony. See `docs/CEREMONY.md`. |
| OCSP replica lag for on-demand signing | Low→Medium | Open | Postgres replica may have stale revocation. Operators must route live OCSP to the primary. See §3b.9. |
| RA approver single-person approval | Low→High | Open | No dual-control for RA approvals. High-value profiles should require two approvers (process control). |
| SSRF via webhook URL | Low | Open | No URL allow-list. CA operator access already implies full compromise; documented risk. See §3b.7. |

This list is intentionally complete. Operators who need to close any of these gaps should treat the corresponding track as a deployment prerequisite, not a future enhancement.

**Durability invariants** (audit-log completeness, serial uniqueness, CRL monotonicity, revocation persistence) are verified by the chaos suite in `chaos/` per Tier 6.5. See `chaos/README.md` for which failure modes have been tested.

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
