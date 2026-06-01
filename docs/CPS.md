# PyPKI Certification Practice Statement (CPS)

> Last reviewed: 2026-06-01 (commit 453e7ba)

**Document version:** 1.0
**Effective date:** _to be set per deployment_
**Policy OID:** `1.3.6.1.4.1.<PEN>.1.1` _(operator: replace `<PEN>` with your IANA-assigned Private Enterprise Number; see §1.2)_
**Target audience:** subscribers of certificates issued by a PyPKI instance, and relying parties who validate them
**Scope:** internal / homelab / small-enterprise deployments only — **NOT a publicly-trusted CA**

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Publication and Repository Responsibilities](#2-publication-and-repository-responsibilities)
3. [Identification and Authentication](#3-identification-and-authentication)
4. [Certificate Life-Cycle Operational Requirements](#4-certificate-life-cycle-operational-requirements)
5. [Facility, Management, and Operational Controls](#5-facility-management-and-operational-controls)
6. [Technical Security Controls](#6-technical-security-controls)
7. [Certificate, CRL, and OCSP Profiles](#7-certificate-crl-and-ocsp-profiles)
8. [Compliance Audit and Other Assessments](#8-compliance-audit-and-other-assessments)
9. [Other Business and Legal Matters](#9-other-business-and-legal-matters)

---

## 1. Introduction

### 1.1 Overview

This document is the Certification Practice Statement (CPS) for a PyPKI
deployment, in the format of RFC 3647 §6. It describes what a PyPKI
operator does (and does not do) when issuing, managing, and revoking
X.509 certificates.

PyPKI is an open-source, self-hosted PKI server implementing CMPv2/v3
(RFC 4210/9480), ACME (RFC 8555), SCEP, EST (RFC 7030), OCSP (RFC 6960),
and CRL distribution. It is **not** a publicly-trusted Certification
Authority. Certificates issued by a PyPKI instance are trustworthy only
within the trust domain configured by the operator (typically a single
home network, a Kubernetes cluster, an internal lab, or a single
organization).

This CPS is shipped as a template. Operators MUST customize it for
their deployment before shipping it to subscribers and relying parties.

### 1.2 Document Identification

The certificates issued under this CPS may carry a `CertificatePolicies`
extension whose `policyIdentifier` matches one of the OIDs registered by
the operator. PyPKI ships with a placeholder OID:

```
1.3.6.1.4.1.<PEN>.1.1
```

where `<PEN>` is the operator's IANA-assigned Private Enterprise Number.
PENs are free to register at <https://pen.iana.org/pen/PenApplication.page>;
the form takes a few minutes and approval typically takes a few days.

If the operator does not register a PEN, certificates SHOULD omit the
`CertificatePolicies` extension entirely rather than emit an unregistered
OID. PyPKI omits it by default; operators opt in with the `--cps-uri`
and `--cps-policy-oid` flags.

### 1.3 PKI Participants

| Role | Description |
|---|---|
| **Certification Authority (CA)** | The PyPKI server holding the private key that signs certificates. May be a single root, or a sub-CA chained from a root CA whose private key is stored offline (see [DEPLOYMENT/offline-root-online-subca.md](DEPLOYMENT/offline-root-online-subca.md)). |
| **Registration Authority (RA)** | Built into PyPKI. The same operator who controls the CA also controls the enrollment endpoints. An optional RA approval workflow (`--ra-require-approval`, `--ra-policy-file`) allows requests to be held for manual or policy-driven review before issuance. |
| **Subscribers** | Any entity (server, device, user, container, IoT node) that obtains a certificate from a PyPKI instance. |
| **Relying parties** | Any entity that validates a PyPKI-issued certificate to authenticate a subscriber. |
| **Repository operator** | The PyPKI operator. PyPKI publishes its CRL, OCSP responses, and CA chain over HTTP at endpoints documented in §2. |

### 1.4 Certificate Usage

PyPKI-issued certificates are appropriate for:

- mTLS between internal services (Kubernetes pod-to-pod, Service-A-to-Service-B)
- Service Mesh data plane (Istio, Linkerd) when chained from a PyPKI sub-CA
- IoT device identity (provisioned via SCEP or EST)
- IPsec gateway authentication
- Internal HTTPS endpoints not reachable from the public internet
- Code signing within the operator's trust domain (NOT publicly-trusted code signing)
- Email signing/encryption within the operator's trust domain

PyPKI-issued certificates are NOT appropriate for:

- Publicly-accessible HTTPS endpoints (use Let's Encrypt or a commercial CA)
- Publicly-distributed code signing (Authenticode, kernel modules, etc.)
- Identity assertions across organizational trust boundaries without an
  out-of-band trust root distribution mechanism
- Any context where browsers, OS root stores, or third-party software
  expect the issuer to chain to a publicly-trusted root

### 1.5 Policy Administration

The operator of a PyPKI instance is solely responsible for this CPS,
its content, and its enforcement. The PyPKI software project does not
operate any CA itself.

Contact information (operator MUST replace):

```
Name:    <Operator Name>
Email:   <operator@example.com>
Address: <Operator postal address, optional>
PGP key: <PGP fingerprint, optional>
```

### 1.6 Definitions and Acronyms

- **CA**: Certification Authority
- **CPS**: Certification Practice Statement (this document)
- **CRL**: Certificate Revocation List
- **CT**: Certificate Transparency (RFC 9162)
- **OCSP**: Online Certificate Status Protocol
- **PEN**: IANA Private Enterprise Number
- **RA**: Registration Authority
- **SAN**: Subject Alternative Name
- **SKI**: Subject Key Identifier
- **AKI**: Authority Key Identifier

---

## 2. Publication and Repository Responsibilities

### 2.1 Repositories

A PyPKI deployment publishes the following over HTTP from the same
host(s) as the issuance endpoints:

| Resource | Default path | Format | Refresh |
|---|---|---|---|
| CA certificate | `/ca.crt` | PEM | static |
| CA chain (if intermediate) | `/ca-chain.pem` | PEM | static |
| CRL (full) | `/crl.der` | DER (RFC 5280 + RFC 6818) | every revocation; daily refresh |
| Delta CRL | `/delta-crl.der` | DER | every 6 hours |
| OCSP responder | `/ocsp/<prefix>` | RFC 6960 | per-request, cached 300s |
| This CPS | `/cps.txt` (operator-served) | this Markdown document, rendered or as-is | per CPS version bump |

The exact paths depend on deployment configuration — see
`docs/DEPLOYMENT/*.md` for per-deployment specifics.

### 2.2 Publication Frequency

- The CA certificate is published once at deployment time and remains
  static until renewal.
- New CRLs are published on every revocation event (immediate) AND on a
  daily timer regardless of revocation activity. The `nextUpdate` field
  is set to 24 hours after `thisUpdate` for full CRLs.
- OCSP responses are pre-signed on demand and cached for 300 seconds by
  default (configurable via `--ocsp-cache-seconds`).
- Delta CRLs (RFC 5280 §5.2.4) are emitted every 6 hours when active.
- This CPS is published when the operator updates it. Subscribers SHOULD
  re-fetch on every issuance event.

### 2.3 Access Controls on Repositories

- The CA certificate, CRL, OCSP, and CPS are all read-only and
  unauthenticated by design — relying parties need to fetch them
  without credentials to do path validation.
- Issuance and revocation endpoints (CMP, ACME, SCEP, EST, REST API,
  Web UI) are authenticated. See §3 and §6.

---

## 3. Identification and Authentication

### 3.1 Naming

#### 3.1.1 Types of names

PyPKI accepts X.500 Distinguished Names with the following typical
attribute types: `CN` (Common Name), `O` (Organization), `OU`
(Organizational Unit), `C` (Country), `ST` (State), `L` (Locality),
`emailAddress`. Subject Alternative Names of type `dNSName`,
`iPAddress`, `rfc822Name`, and `uniformResourceIdentifier` are accepted.

#### 3.1.2 Need for names to be meaningful

Names SHOULD be unique within the operator's trust domain. PyPKI does
not enforce global subject DN uniqueness (the cert serial number is the
unique identifier).

#### 3.1.3 Anonymity / pseudonymity

Anonymous certificates are permitted within the operator's trust domain
(e.g., short-lived workload certs identified only by SPIFFE URI).
Operators SHOULD ensure their own audit log captures the requesting
identity even when the issued cert subject is anonymous.

#### 3.1.4 Rules for interpreting various name forms

- `CN`: free text, UTF-8, no length restriction beyond X.509 limits.
- DNS SANs: must be valid DNS names per RFC 5280 §4.2.1.6. Wildcards
  (`*.example.internal`) are permitted but the operator SHOULD audit
  their use.
- IP SANs: IPv4 and IPv6 literal addresses. Permitted in internal
  trust domains where DNS naming is unstable.
- URI SANs (SPIFFE): `spiffe://trust-domain/path` form, used for
  workload identities.

#### 3.1.5 Uniqueness of names

Not enforced beyond the X.509 serial number.

### 3.2 Initial Identity Validation

The operator is responsible for validating subscriber identity before
issuance. PyPKI provides the technical enrollment paths but does not
perform identity proofing — that is a process question, not a software
question. Typical operator practices:

- **Internal services**: enrollment via service-account-bound CMP shared
  secrets, or via mTLS to an existing trust root (cert-manager bootstrap)
- **IoT devices**: enrollment via SCEP one-time password (OTP) printed
  during device provisioning, or EST + bootstrap credential
- **User certs**: enrollment via Web UI authenticated against PAM
  (Linux user/password)
- **Web UI admin operations**: PAM authentication with brute-force
  lockout and session management (see `pki_server.py:PAMAuthenticator`)

### 3.3 Identification and Authentication for Re-key Requests

Re-key requests via CMP `kur` (Key Update Request) and ACME-renew use
the existing certificate's private key to sign the renewal request,
proving continuous possession (RFC 4210 §5.3.5, RFC 8555 §7.3.6).

### 3.4 Identification and Authentication for Revocation Requests

Revocation may be requested by:

- The operator, via the Web UI or REST API
- The certificate holder, via CMP `rr` (Revocation Request) signed with
  the cert's own key

PyPKI does NOT today support delegated revocation by a separate
revocation authority — that is a Tier 5.4 future-work item.

---

## 4. Certificate Life-Cycle Operational Requirements

### 4.1 Certificate Application

#### 4.1.1 Who can submit a certificate application

Any entity that can authenticate to the operator's enrollment endpoint.

#### 4.1.2 Enrollment process

PyPKI accepts CSRs (RFC 2986 PKCS#10) and CRMF (RFC 4211) requests via:

| Protocol | Endpoint | Authentication |
|---|---|---|
| CMPv2/v3 | `/cmp` (per RFC 9483 §3.6) | Shared-secret MAC, or signature with prior cert |
| ACME | `/acme/*` (RFC 8555) | Account key signature (JWS) |
| SCEP | `/scep` | One-Time Password (OTP) — operator-configurable |
| EST | `/.well-known/est/*` | HTTP Basic, or mTLS with bootstrap cert |
| Web UI | `/api/issue` and `/api/sign-csr` | PAM user session |
| REST API | `/api/*` | API key (operator-issued) |

### 4.2 Certificate Application Processing

#### 4.2.1 Performing identification and authentication functions

The operator's enrollment endpoint authenticates the requester before
the request reaches the issuance code path. PyPKI's enrollment handlers
will only invoke `CertificateAuthority.issue_certificate` after the
authentication layer has accepted the request.

#### 4.2.2 Approval or rejection of certificate applications

Approval is implicit — if the request authenticates and the CSR/CRMF
passes naming-policy validation (`CertProfile.allowed_san_dns_patterns`
etc.), the certificate is issued automatically. Manual approval queues
are a Tier 5.4 future-work item.

#### 4.2.3 Time to process certificate applications

Issuance is synchronous. Typical wall-clock time is well under one
second per certificate.

### 4.3 Certificate Issuance

CertificateAuthority.issue_certificate performs:

1. Allocates a fresh serial number (atomic, monotonic, persisted in
   `serial_counter` table)
2. Builds the X.509 v3 certificate with operator-configured profile
   defaults: validity period (default 365 days), hash algorithm
   (SHA-256), key usage, extended key usage, name constraints, AIA
   pointer, CDP pointer, AKI, SKI
3. Optionally adds `CertificatePolicies` if `--cps-uri` is configured
4. Optionally embeds Certificate Transparency SCTs if CT is configured
5. Signs with the CA private key
6. Writes the cert to `certificates.db` with subject, validity, profile
7. Writes an audit log entry (`event=issue`)

### 4.4 Certificate Acceptance

Upon receiving an issued certificate, the subscriber SHOULD:

- Verify the cert chains to the CA they authenticated against
- Verify the SAN matches the requested name(s)
- Confirm via CMP `certConf` (Certificate Confirmation) that the cert
  was the one expected — required when CMP `implicit_confirm` is off

### 4.5 Key Pair and Certificate Usage

Subscribers MUST use the certificate only for the purposes encoded in
its `keyUsage` and `extendedKeyUsage` extensions. Misuse outside the
encoded purposes is a violation of this CPS even if technically
possible.

### 4.6 Certificate Renewal

PyPKI supports renewal via CMP `kur` (RFC 4210 §5.3.5), ACME order with
the same identifiers, and Web UI / REST API. Renewal preserves subject
DN and SAN by default; the subscriber may submit a fresh CSR with
updated public key to perform a re-key.

PyPKI emits an `expires_soon` audit event for any certificate whose
`notAfter` is within 30 days. The operator may run the expiry monitor
on a cron or use the `pypki monitor-expiry` subcommand.

### 4.7 Certificate Re-key

Re-key is the same operation as renewal, with a fresh public key in the
new CSR. The previous certificate is NOT automatically revoked on
re-key — operators who require old certs to be revoked on re-key MUST
do so explicitly.

### 4.8 Certificate Modification

Certificate modification (changing subject, SAN, validity, etc. on an
existing serial) is not supported. The correct procedure is to issue a
new certificate and revoke the old one if needed.

### 4.9 Certificate Revocation and Suspension

#### 4.9.1 Circumstances for revocation

A certificate MUST be revoked if:

- The subscriber's private key is compromised or suspected compromised
- The subscriber is decommissioned, no longer authorized, or has left
  the organization
- The certificate was issued in error (wrong subject, wrong key, wrong
  validity)
- The subscriber requests revocation

A certificate MAY be revoked if:

- The subscriber's role or affiliation changes such that the cert no
  longer reflects current state
- The operator decides the cert is no longer needed

#### 4.9.2 Who can request revocation

- The operator, unconditionally
- The subscriber, for their own certificate (CMP `rr` or Web UI)

#### 4.9.3 Procedure for revocation request

CMP `rr` requests are validated using the existing certificate's
signature. Web UI requests require an authenticated operator session.
REST API revocation requires a valid API key.

#### 4.9.4 Revocation request grace period

None. Revocation requests are processed immediately on receipt.

#### 4.9.5 Time within which CA must process the revocation request

Synchronous — the certificate's revocation row is committed to the
database before the response is sent. CRL and OCSP cache invalidation
follow within seconds.

#### 4.9.6 Revocation checking requirement for relying parties

Relying parties SHOULD check revocation status via OCSP (preferred,
lower latency) or CRL on every certificate validation. PyPKI publishes
both. Stapled OCSP (RFC 6066) is recommended where the protocol allows
it; PyPKI exposes pre-signed OCSP responses suitable for stapling.

#### 4.9.7 CRL issuance frequency

- Full CRL: every revocation event AND every 24 hours
- Delta CRL: every 6 hours when enabled

#### 4.9.8 Maximum latency for CRLs

Within 24 hours. Most relying parties will see updates within seconds
to minutes via OCSP.

#### 4.9.9 On-line revocation/status checking availability

OCSP is available 24/7 from the same host(s) as the issuance endpoints.
Relying parties should expect OCSP availability matching the CA's
overall uptime SLO (operator-defined).

#### 4.9.10 On-line revocation checking requirements

OCSP requests SHOULD include a nonce extension (RFC 8954 §2.1, 1–32
bytes). PyPKI rejects nonces outside this length range with status
`malformed`. With `--ocsp-require-nonce`, requests without a nonce are
rejected with status `unauthorized`.

#### 4.9.11 Other forms of revocation advertisements available

None. CRL and OCSP only.

#### 4.9.12 Special requirements re key compromise

If the CA's own private key is compromised, every certificate issued
under it MUST be considered untrustworthy. The operator's response
playbook should include:

1. Offline the compromised CA immediately
2. Notify all subscribers and relying parties via out-of-band channels
3. Stand up a new CA with a new key pair
4. Cross-sign or otherwise migrate subscribers to the new CA
5. Publish a final CRL revoking all extant certificates under the
   compromised CA, but treat this as advisory — relying parties should
   distrust the entire issuer

PyPKI ships no automated tooling for CA key compromise response. This
is a process gap operators must close themselves.

#### 4.9.13–4.9.16 Suspension

Certificate suspension (`certificateHold`) is supported via reason code
6 in CRL entries. PyPKI accepts it but operators are RECOMMENDED to
revoke (`unspecified` or specific reason) rather than suspend, since
suspension semantics are inconsistently implemented in clients.

### 4.10 Certificate Status Services

OCSP and CRL as documented in §4.9.

### 4.11 End of Subscription

When a subscriber stops needing a certificate, they SHOULD request
revocation. If revocation is not requested, the certificate expires
naturally and is removed from the CRL after the next CRL update following
expiry (PyPKI behavior — expired-and-not-renewed certs may continue to
appear on CRL until the operator runs CRL pruning).

### 4.12 Key Escrow and Recovery

PyPKI supports an OPTIONAL key archival feature
(`CertificateAuthority.archive_key` / `key_archive` table) for cases
where the CA generates the subscriber's keypair server-side. Archived
keys are encrypted at rest with the CA passphrase.

PyPKI does NOT escrow keys generated by the subscriber and submitted in
a CSR. Any CSR-based enrollment leaves key control entirely with the
subscriber.

Operators who deploy key archival MUST disclose this to subscribers
clearly. Many subscribers will not want their private key archived;
this should be a per-subscriber opt-in, not an operator-side default.

---

## 5. Facility, Management, and Operational Controls

### 5.1 Physical Controls

The operator is responsible for the physical security of the host(s)
running PyPKI. Recommended baseline:

- Host runs in a locked room or rack, or in a private cloud account
- Disk encryption at rest (LUKS, dm-crypt, cloud KMS-backed disk)
- No casual physical access by personnel outside the operator role

Operators with stricter requirements should consult §6.2.7 (HSM/PKCS#11
support — Tier 5.1 future work).

### 5.2 Procedural Controls

PyPKI runs as a single-operator system today. Multi-operator role
separation (issuance officer, revocation officer, audit officer) is
NOT enforced by the software — the operator MUST implement it via
process.

For homelab and small-team deployments, single-operator is acceptable.
For larger deployments, a Tier 5.4 RA workflow is needed for proper
role separation.

### 5.3 Personnel Controls

The operator is responsible for personnel security. PyPKI's audit log
captures all issuance and revocation events with timestamps and
requester identity, enabling after-the-fact review.

### 5.4 Audit Logging Procedures

PyPKI writes structured audit log entries (`audit.db`) for:

- Every certificate issuance (`event=issue`)
- Every certificate revocation (`event=revoke`)
- Every CA configuration change (`event=config_change`)
- Every authentication failure on Web UI / REST API (`event=auth_failure`)
- Every CRMF POPO failure (`event=popo_failed` / `event=popo_missing`)
- Every sub-CA issuance (`event=issue_sub_ca`)

Audit log entries include UTC timestamp, event type, detail string, and
requester IP. The audit DB can be kept on a separate filesystem from
the CA DB; for multi-node deployments, a shared Postgres backend is
supported via `--audit-db-url`.

Audit log retention is operator-controlled. PyPKI does not auto-prune.

### 5.5 Records Archival

In addition to the audit log, PyPKI retains:

- All issued certificates (DER, in `certificates` table) — never deleted
- All CRLs ever issued (in `crl_base` table) — kept for cross-checking
- Optionally, archived subscriber private keys (in `key_archive` table)

Backups of the CA directory (`<ca_dir>/`) MUST include `ca.key`,
`ca.crt`, `certificates.db`, `audit.db`, and the CA passphrase
(separately, encrypted). Loss of the CA passphrase means loss of the
CA — there is no recovery mechanism.

### 5.6 Key Changeover

The CA private key has a finite lifetime tied to the CA certificate's
`notAfter`. Operators SHOULD plan key changeover well in advance:

1. Generate a new CA key and certificate
2. Distribute the new CA cert to all relying parties
3. Cross-sign new-CA-cert with old-CA-key (and vice versa) if a smooth
   transition is required (Tier 5.6 future work — currently manual)
4. Issue new subscriber certificates from the new CA
5. Continue serving CRLs and OCSP for the old CA until the last
   subscriber cert expires

### 5.7 Compromise and Disaster Recovery

See §4.9.12 for CA key compromise. For non-key disasters:

- Hardware failure: restore from backup (CA dir + audit DB)
- Database corruption: restore from backup (PyPKI does NOT today
  support point-in-time recovery of issuance state — operators relying
  on Postgres can use Postgres PITR)
- Loss of CA passphrase: there is no recovery; the CA is lost

### 5.8 CA or RA Termination

When the operator terminates a PyPKI deployment:

1. Issue a final CRL covering all extant certificates
2. Publish the final CRL with `nextUpdate` set far in the future
3. Continue serving the CRL and OCSP as long as practical
4. Notify subscribers and relying parties out-of-band

---

## 6. Technical Security Controls

### 6.1 Key Pair Generation and Installation

CA key pair generation occurs on the host running PyPKI, using
`cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key`
(default RSA-4096) or operator-selected ECC curve. The key never leaves
the host's memory in cleartext under normal operation.

### 6.2 Private Key Protection and Cryptographic Module Engineering Controls

#### 6.2.1 Cryptographic module standards and controls

PyPKI uses the Python `cryptography` library (which uses OpenSSL).
FIPS 140-2/3 module compliance depends on the underlying OpenSSL build
and is out of PyPKI's direct control.

#### 6.2.2 Private key (n out of m) multi-person control

NOT supported. Tier 5.1 (HSM/PKCS#11) and Tier 5.3 (offline root
ceremony tooling) are future-work items that would address this.

#### 6.2.3 Private key escrow

NOT applied to the CA private key.

#### 6.2.4 Private key backup

Backup of the CA key file is the operator's responsibility. The key is
encrypted at rest using a passphrase (configurable via
`PYPKI_CA_PASSPHRASE` environment variable or `--ca-passphrase`).

#### 6.2.5 Private key archival

NOT applied to the CA private key. Subscriber keys may be archived if
generated server-side (see §4.12).

#### 6.2.6 Private key transfer into or from a cryptographic module

The CA key is generated in-process and stored to disk encrypted. There
is no PKCS#11 module integration today (Tier 5.1 future work).

#### 6.2.7 Private key storage on cryptographic module

NOT supported today (HSM is Tier 5.1 future work). The CA key is
stored on the filesystem, encrypted with a passphrase.

#### 6.2.8 Method of activating private key

The operator provides the CA passphrase at startup via
`PYPKI_CA_PASSPHRASE` env var. The key is decrypted into memory and
held there for the lifetime of the process.

#### 6.2.9 Method of deactivating private key

Process termination clears the in-memory key. There is no soft
deactivation (suspend signing without restart).

#### 6.2.10 Method of destroying private key

Operator deletes `<ca_dir>/ca.key` and securely wipes the underlying
storage. PyPKI does not provide automated destruction tooling.

### 6.3 Other Aspects of Key Pair Management

#### 6.3.1 Public key archival

All issued public keys are kept in the `certificates` table indefinitely.

#### 6.3.2 Certificate operational periods and key pair usage periods

Default validity periods:

- CA cert: 10 years
- Sub-CA cert: 5 years (configurable per `issue_sub_ca` call)
- End-entity cert: 365 days (configurable per profile)

Operators MAY configure different defaults via profile rules.

### 6.4 Activation Data

The CA passphrase is the only activation datum. Operators SHOULD:

- Store it in a password manager separate from the host
- Never commit it to version control
- Rotate it on a schedule and on personnel changes

### 6.5 Computer Security Controls

PyPKI is a Python 3.12+ application. Computer security controls
(OS hardening, firewall, SELinux/AppArmor, container security) are the
operator's responsibility.

The Web UI implements: HTTP Basic / PAM authentication, brute-force
lockout, session management, CSRF tokens, HTML escaping (XSS
prevention), and TLS termination via either the built-in TLS server
or an upstream nginx reverse proxy.

### 6.6 Life Cycle Technical Controls

- PyPKI is open-source; operators can audit the source.
- The codebase is under active development; operators SHOULD pin to
  specific versions and read the CHANGELOG before upgrading.
- A test suite covering RFC compliance, security boundaries, and
  database consistency is shipped with the source.

### 6.7 Network Security Controls

The operator is responsible for network access controls. Recommended
baseline:

- The Web UI / REST API SHOULD NOT be exposed to the public internet
  unless behind an authenticating reverse proxy
- The CMP / ACME / SCEP / EST endpoints MAY be exposed if the
  authentication layer is sufficient (operator's call)
- The OCSP / CRL endpoints SHOULD be exposed publicly so relying
  parties can fetch them

### 6.8 Time-stamping

PyPKI does not operate an RFC 3161 time-stamping authority today
(Tier 2 future work). Where time-sensitive signatures are needed
(e.g., Authenticode), operators should integrate an external TSA.

---

## 7. Certificate, CRL, and OCSP Profiles

### 7.1 Certificate Profile

PyPKI emits X.509 v3 certificates conforming to RFC 5280. Standard
extensions:

- **basicConstraints**: critical; `cA:FALSE` for end-entities, `cA:TRUE`
  with `pathLenConstraint` for sub-CAs
- **keyUsage**: critical; `digitalSignature`, `keyEncipherment` for
  end-entities; `keyCertSign`, `cRLSign` for CAs
- **extendedKeyUsage**: non-critical; profile-dependent
  (e.g., `serverAuth`, `clientAuth`, `emailProtection`, `codeSigning`)
- **subjectAltName**: critical when subject DN is empty, non-critical
  otherwise; `dNSName`, `iPAddress`, `rfc822Name`,
  `uniformResourceIdentifier` accepted
- **subjectKeyIdentifier** (SKI): non-critical; SHA-1 of the public key
  BIT STRING (RFC 5280 §4.2.1.2 method 1)
- **authorityKeyIdentifier** (AKI): non-critical; matches the issuer's
  SKI
- **certificatePolicies**: non-critical; carries `cps_uri` and optional
  `UserNotice` qualifier when configured
- **cRLDistributionPoints**: non-critical; HTTP URL to the CRL
- **authorityInformationAccess**: non-critical; HTTP URL to the OCSP
  responder and the issuer's certificate
- **nameConstraints**: critical when set on a sub-CA;
  `permittedDNSNames`, `excludedDNSNames`, `permittedIPRanges`,
  `excludedIPRanges`, `permittedEmailAddresses`

Signature algorithm: `sha256WithRSAEncryption` for RSA-issued certs.
Other algorithms (RSA-PSS via RFC 4055, ECDSA via RFC 5480/5758,
Ed25519 via RFC 8410) are roadmap items.

### 7.2 CRL Profile

CRLs conform to RFC 5280 §5 with RFC 6818 errata applied. Required
extensions:

- **cRLNumber** (non-critical, RFC 5280 §5.2.3): monotonically
  increasing across all CRLs issued by this issuer, persisted in the
  `crl_number` table
- **authorityKeyIdentifier** (non-critical, RFC 5280 §5.2.1): matches
  the CA's SKI

For delta CRLs, additionally:

- **deltaCRLIndicator** (critical, RFC 5280 §5.2.4): points at the
  base CRL number this delta supplements

CRL entry extensions:

- **reasonCode**: when revocation reason is provided

### 7.3 OCSP Profile

OCSP responses conform to RFC 6960:

- Pre-signed by a delegated OCSP signing certificate (issued by the CA
  with `id-pkix-ocsp-nocheck`, `keyUsage=digitalSignature`,
  `extKeyUsage=ocspSigning`)
- Cached for 300 seconds by default (configurable via
  `--ocsp-cache-seconds`)
- Nonce extension processed per RFC 8954 (length 1–32 bytes); strict
  mode (`--ocsp-require-nonce`) rejects nonceless requests with
  `unauthorized` (status 6)
- `singleResponse` includes `certStatus` (`good`, `revoked`,
  `unknown`), `thisUpdate`, `nextUpdate`, and (for revoked)
  `revocationTime` and `revocationReason`

---

## 8. Compliance Audit and Other Assessments

PyPKI deployments are NOT audited under WebTrust, ETSI EN 319 411, or
any other public-CA audit scheme. This CPS is published in good faith
to document operator practices, not to qualify the CA for inclusion in
public root stores.

Operators in regulated industries (PCI, HIPAA, SOC 2) MAY use a PyPKI
deployment as part of their compliance posture, but the audit
relationship is between the operator and their auditor — not between
the auditor and the PyPKI software project.

Operators are encouraged to:

- Periodically review the audit log for anomalous issuance patterns
- Verify CRL and OCSP availability via external monitoring
- Test backup-and-restore procedures regularly
- Run the included test suite after every PyPKI version bump

---

## 9. Other Business and Legal Matters

### 9.1 Fees

The PyPKI software is open-source. The operator's fee structure (if
any) for issuing certificates is operator-defined and out of scope of
this CPS template.

### 9.2 Financial Responsibility

The operator assumes all financial responsibility for the operation of
the CA. The PyPKI software project provides no warranties or
indemnification.

### 9.3 Confidentiality of Business Information

Operator-defined.

### 9.4 Privacy of Personal Information

PyPKI's audit log captures requester IP addresses and may capture
subject DNs containing personal data (e.g., email addresses). Operators
processing personal data of EU/UK residents are subject to GDPR/UK GDPR
and MUST handle the audit log accordingly (data subject access,
retention limits, secure disposal).

### 9.5 Intellectual Property Rights

PyPKI is licensed under the terms shipped with the source (see
`LICENSE` in the repository root). Issued certificates are the
intellectual property of the subject, with whatever obligations the
operator imposes via §1.4 / §4.5.

### 9.6 Representations and Warranties

NONE. The PyPKI software project provides the software AS-IS. The
operator makes whatever representations they choose to make to their
own subscribers and relying parties.

### 9.7 Disclaimers of Warranties

PyPKI is provided AS-IS without warranty of any kind, express or
implied. See `LICENSE` for full terms.

### 9.8 Limitations of Liability

Per the LICENSE terms.

### 9.9 Indemnities

NONE provided by the PyPKI software project. Operator-defined for
operator's relationship with subscribers and relying parties.

### 9.10 Term and Termination

This CPS is effective from the date stated at the top of this document
until superseded by a new version or until the operator terminates the
CA per §5.8.

### 9.11 Individual Notices and Communications with Participants

Operator-defined channel (email, status page, etc.).

### 9.12 Amendments

The operator may amend this CPS at any time. Material amendments
SHOULD be communicated to subscribers and relying parties at least
30 days before they take effect.

### 9.13 Dispute Resolution Provisions

Operator-defined. The PyPKI software project does not act as an
arbiter.

### 9.14 Governing Law

Operator-defined.

### 9.15 Compliance with Applicable Law

The operator is responsible for compliance with all applicable laws in
their jurisdiction(s) — data protection (GDPR, CCPA), import/export of
cryptographic software, sector-specific regulations.

### 9.16 Miscellaneous Provisions

None.

### 9.17 Other Provisions

This CPS is shipped as a template. Any operator deploying PyPKI in a
context where a CPS is needed by their stakeholders MUST customize at
minimum:

- §1.2 (replace `<PEN>`)
- §1.5 (operator contact info)
- §2.1 (actual repository URLs)
- §5.5 (backup retention specifics)
- §6.4 (passphrase rotation policy)
- §9.4 (privacy policy specifics)
- §9.10–§9.15 (legal jurisdiction)

---

## Appendix A — Document History

| Version | Date | Changes |
|---|---|---|
| 1.0 | _to be set_ | Initial CPS based on RFC 3647 §6 outline. Shipped with PyPKI. |

## Appendix B — References

- RFC 3647 — Internet X.509 Public Key Infrastructure Certificate
  Policy and Certification Practices Framework
- RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and
  Certificate Revocation List (CRL) Profile
- RFC 6818 — Updates to RFC 5280
- RFC 4210 — CMPv2
- RFC 4211 — CRMF
- RFC 6960 — OCSP
- RFC 8954 — OCSP Nonce Extension Update
- RFC 8555 — ACME
- RFC 7030 — EST
- RFC 5958 — Asymmetric Key Package (PKCS#8)
