# Deployment: Offline Root + Online Sub-CA

> Last reviewed: 2026-06-01 (commit 453e7ba)

This is the standard pattern for security-conscious internal CAs. The root CA lives on a dedicated, normally-powered-down machine that only comes online for ceremonial events (issuing or rotating sub-CAs, rotating CRLs). All day-to-day issuance happens on a separate, online sub-CA. A compromise of the online sub-CA is **recoverable** because the root is not on the network.

It's the most-asked-about deployment shape for a reason: it cuts most of the practical attack surface to the bare minimum without sacrificing operational throughput.

> **When this is the right pattern.** Any deployment where (a) you need to issue more than a handful of certs per day, *and* (b) the cost of a CA compromise is much higher than the cost of running a slightly more complex CA. If only (a) holds, plain online single-node is fine. If only (b) holds, an offline-only CA with manual issuance via PKCS#10 may be simpler. The two-tier pattern shines when both are true — production internal PKI for any organization where a CA breach materially hurts.

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [Threat Model Reduction](#2-threat-model-reduction)
3. [Hardware and OS Choices](#3-hardware-and-os-choices)
4. [Step 1 — Provision the Offline Root](#4-step-1--provision-the-offline-root)
5. [Step 2 — Issue the Online Sub-CA](#5-step-2--issue-the-online-sub-ca)
6. [Step 3 — Set Up the Online Sub-CA Server](#6-step-3--set-up-the-online-sub-ca-server)
7. [Step 4 — Publish the Root CRL](#7-step-4--publish-the-root-crl)
8. [Ceremony Cadence](#8-ceremony-cadence)
9. [Sub-CA Compromise Response](#9-sub-ca-compromise-response)
10. [Root Compromise Response](#10-root-compromise-response)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Architecture

```
   ┌────────────────────────────────────┐
   │  Offline root machine              │
   │  Air-gapped, powered off normally  │
   │                                    │
   │  PyPKI in --offline-mode           │
   │  ca.key  (root private key)        │      USB-only data exchange
   │  ca.crt  (root cert, 10y)          │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
   │  certificates.db (sub-CA records)  │                              │
   │                                    │                              │
   └────────────────────────────────────┘                              ▼
                                                          ┌──────────────────────────┐
                                                          │  Online sub-CA server    │
                                                          │  Always on, public-ish   │
                                                          │                          │
                                                          │  PyPKI normal mode       │
                                                          │  subca.key  (sub-CA key) │
                                                          │  subca.crt  (sub-CA, 3y) │
                                                          │  ca-chain.pem (root+sub) │
                                                          │  certificates.db (leaves)│
                                                          │                          │
                                                          │  Issues end-entity certs │
                                                          │  via CMP/ACME/EST/SCEP   │
                                                          └──────────────────────────┘
                                                                        │
                                                                        ▼
                                                                 Workloads, devices,
                                                                 VPN endpoints, etc.
```

**Trust chain in every issued cert:**

```
Root CA            (offline; signs the sub-CA, then sleeps)
   │
   └─► Sub-CA      (online; issues all leaves)
          │
          └─► Leaf cert  (workload, server, person, device)
```

The root cert lives in every relying party's trust store. The sub-CA cert is delivered to relying parties as part of the chain (in `extraCerts` for CMP, in `Authorization` headers for some ACME profiles, etc.). Properly-implemented verifiers handle this transparently.

---

## 2. Threat Model Reduction

| Attack | Single online CA | Offline root + online sub-CA |
|---|---|---|
| **Network compromise of the CA host** | Root key exposed → game over, all certs ever issued become forgeable from the operator's perspective | Sub-CA key exposed → sub-CA revoked from offline root, new sub-CA issued, leaves rotate. Root key never touched the network. |
| **Insider with shell access on CA host** | Same — root key in scope | Same — sub-CA key in scope, but blast radius and recovery cost are bounded |
| **Stolen backup of CA database** | Encrypted at rest, but the key file backup is the real target | Sub-CA backup compromise = same as live sub-CA compromise; root backup is on cold storage with separate access |
| **Compromise of a relying party's trust store** | Attacker can convince that one party of forged certs | Same. Trust-store hygiene is orthogonal. |
| **Lost root key** | New CA from scratch, all certs invalid | Same — but the root is on cold storage, much harder to lose than to compromise |

The recovery cost of a sub-CA compromise is **a sub-CA rotation**, which is a planned operation. The recovery cost of a root compromise is **a full PKI rebuild**, which is a project. Pushing the impact from "project" to "planned operation" is what this pattern buys.

---

## 3. Hardware and OS Choices

### Offline root machine

It only runs once or twice a year for ceremonies. Cheap is fine; reliable storage is essential.

- **Form factor:** any laptop or small-form-factor PC. Used hardware is acceptable. Disk encryption on by default.
- **OS:** a minimal Linux distribution that you can verify the integrity of. Debian stable, Ubuntu LTS, Fedora, or your distro of choice. Boot from a known-good install medium, install only PyPKI's runtime dependencies, never connect to the internet after install except for one curated round of security updates pre-ceremony.
- **Storage:** the CA private key + database go on **two encrypted USB sticks**, kept in different physical locations. The machine's local disk is for OS only.
- **Network:** Ethernet cable disconnected at the machine's RJ45 port whenever the machine is awake. WiFi disabled in BIOS. Bluetooth disabled.
- **Keyboard/monitor:** local only. No KVM-over-IP, no remote console.

### Online sub-CA server

This is a normal Linux server. Treat it like any production HTTP service.

- **Form factor:** VM, container, or dedicated host. Multiple sub-CA instances behind a load balancer if HA matters (see `docs/STORAGE.md` Shape C).
- **OS:** server-grade distro, kept patched, no extraneous services.
- **Storage:** depends on chosen storage shape. SQLite for small, Postgres for HA. The sub-CA private key on encrypted disk; passphrase delivered at boot via systemd-creds, an HSM, or operator-typed input.
- **Network:** firewalled to the protocols PyPKI actually serves (typically 443 for the Web UI / REST, plus the CMP / ACME / EST / SCEP / OCSP prefixes per your config).

---

## 4. Step 1 — Provision the Offline Root

Boot the offline machine. Install PyPKI exactly once:

```bash
# Install Python and dependencies from your distro's package manager.
# Install cryptography from the same distro source (apt, dnf, etc.) — do NOT pip install from the internet.
sudo apt install python3 python3-cryptography

# Copy PyPKI source from a trusted USB stick (verified hash).
sudo mkdir -p /opt/pypki
sudo cp -r pypki-source/* /opt/pypki/
```

Generate the root CA. Use a strong passphrase, write it down on paper, store it in a physical safe. Two operators, dual control:

```bash
# As the operator user
mkdir -p ~/root-ca
cd ~/root-ca

python3 /opt/pypki/pki_server.py \
    --ca-dir ./ca-root \
    --ca-cn "Example Corp Root CA" \
    --ca-org "Example Corp" \
    --ca-days 3650 \
    --ca-key-size 4096 \
    --offline-mode \
    --no-network-bind \
    --init-only
```

(`--offline-mode` and `--init-only` are conceptual flags here; in current PyPKI you achieve the same effect by running `pypki` once to generate the CA keypair, then exiting cleanly. The CA dir at `./ca-root/` now contains `ca.key` (passphrase-protected) and `ca.crt`.)

Verify the root cert:

```bash
openssl x509 -in ca-root/ca.crt -noout -text | head -30
# Confirm:
#   Subject:    CN = Example Corp Root CA, O = Example Corp
#   Issuer:     CN = Example Corp Root CA, O = Example Corp   (self-signed)
#   Validity:   ~10 years
#   Public Key: 4096-bit RSA
#   Extensions: BasicConstraints CA:TRUE (no path-length)
#               KeyUsage  keyCertSign, cRLSign
#               SubjectKeyIdentifier present
```

Back up the root CA dir to **two separate USB sticks**, both encrypted with LUKS or VeraCrypt:

```bash
# USB stick 1
cp -r ca-root /media/operator/root-ca-backup-1/$(date +%Y%m%d)/
sync

# USB stick 2 (different person, different physical location)
cp -r ca-root /media/operator/root-ca-backup-2/$(date +%Y%m%d)/
sync
```

Power off the machine. Lock the USB sticks in physically separated safes.

---

## 5. Step 2 — Issue the Online Sub-CA

This is the first **ceremony**. Schedule it for a calm time of day, two operators present, recording on. The whole thing should take 30 minutes.

On the offline machine (boot it up, decrypt the USB stick, copy the CA dir to local working storage):

```bash
mkdir -p /tmp/ceremony && cd /tmp/ceremony
cp -r /media/operator/root-ca-backup-1/<latest>/ca-root .

python3 /opt/pypki/pki_server.py --ca-dir ./ca-root \
    --emit-subca \
    --subca-cn "Example Corp Issuing Sub-CA 2025" \
    --subca-org "Example Corp" \
    --subca-days 1095 \
    --subca-path-length 0 \
    --subca-permitted-dns "example.com,internal.example.com" \
    --subca-permitted-emails "example.com" \
    --subca-key-size 4096 \
    --output ./subca-output
```

(Again, `--emit-subca` is conceptual; in current PyPKI you run the full server with the root CA, hit `/api/issue-sub-ca` once via localhost, save the output, then shut it back down. Future versions will offer a one-shot CLI subcommand.)

The output:

```
subca-output/
├── subca.crt              # The sub-CA cert (signed by the offline root)
├── subca.key              # The sub-CA private key, PKCS#8, passphrase-protected
└── ca-chain.pem           # Root cert + sub-CA cert in order, for distribution
```

**Critical:**

- `--subca-path-length 0` means this sub-CA may issue end-entity certs but **not** further sub-CAs. Limits compromise blast radius.
- `--subca-permitted-dns` and `--subca-permitted-emails` constrain the sub-CA to the namespaces it's actually authorized for. A compromised sub-CA with permitted-dns `example.com` cannot mint a `google.com` cert that any RFC 5280-compliant verifier will accept.
- `--subca-days 1095` (3 years) is much shorter than the root's 10 years. Sub-CAs rotate; roots almost don't.

Copy the output to a fresh USB stick. **Keep the root CA dir untouched on the laptop's local working storage** — you'll need it for the CRL generation step below.

---

## 6. Step 3 — Set Up the Online Sub-CA Server

On the online server, set up PyPKI with the sub-CA cert+key + the root chain:

```bash
sudo mkdir -p /etc/pypki
sudo cp /media/usb-fresh/subca-output/subca.crt   /etc/pypki/ca.crt
sudo cp /media/usb-fresh/subca-output/subca.key   /etc/pypki/ca.key
sudo cp /media/usb-fresh/subca-output/ca-chain.pem /etc/pypki/ca-chain.pem
sudo chown -R pypki:pypki /etc/pypki
sudo chmod 0600 /etc/pypki/ca.key
```

PyPKI auto-detects the chain at `<ca_dir>/ca-chain.pem` and switches into intermediate-CA mode: TLS handshakes serve the full chain, EST `/cacerts` serves the full chain, SCEP `GetCACert` returns a p7c containing both, CMP `GetCACerts` lists both, PKCS#12 bundles include the root.

Start PyPKI normally:

```bash
sudo systemctl start pypki
sudo systemctl status pypki
```

Verify the chain on the wire:

```bash
echo | openssl s_client -showcerts -connect pki.example.com:443 2>&1 | \
  openssl crl2pkcs7 -nocrl -certfile /dev/stdin | openssl pkcs7 -print_certs
# Should print TWO certs: the sub-CA, then the root.
```

The online sub-CA can now issue certs via every PyPKI protocol — CMP, ACME, EST, SCEP, OCSP, REST — exactly as a single-tier CA would. Relying parties verify against the root cert in their trust store; the chain to the leaf goes through the sub-CA.

---

## 7. Step 4 — Publish the Root CRL

The root CA only ever has one or two entries in its CRL — the original sub-CA, and the previous one if you've rotated. But it MUST be published so relying parties know whether the sub-CA itself is revoked.

On the offline machine (still in the working dir from §5), generate the root CRL:

```bash
python3 /opt/pypki/pki_server.py --ca-dir ./ca-root --emit-crl \
    --crl-validity-days 365 \
    --output ./root-crl.der
```

Copy `root-crl.der` to a USB stick. On the online sub-CA server (or a separate web host), publish it at the URL referenced in the root cert's `crlDistributionPoints` extension:

```bash
sudo cp /media/usb-fresh/root-crl.der /var/www/pki/root-crl.der
```

Renew this CRL annually. The root CRL is the only artifact you'll touch on the offline machine more often than once every few years.

For OCSP support of the root, use a **delegated OCSP responder** — a separate cert signed by the root with `id-kp-OCSPSigning` EKU, hosted on the online sub-CA server. PyPKI sets this up automatically when the root cert specifies an OCSP URL. (The OCSP delegation pattern preserves the offline-root property: the responder cert is signed once, then runs forever on the online server.)

---

## 8. Ceremony Cadence

- **Sub-CA rotation: every 2-3 years** (when the active sub-CA has 6 months of validity left). Issue a new sub-CA with overlapping validity. Migrate clients gradually; the old sub-CA stays valid until its expiry. Detailed steps in `docs/DEPLOYMENT/kubernetes-cert-manager.md` §7 (the cert-manager flow generalizes).

- **Root CRL refresh: annually.** Re-emit, re-publish.

- **Root key passphrase rotation: every few years.** The passphrase protects the on-disk key against an attacker who steals one of the USB backup copies. PyPKI re-encrypts on demand (`--rotate-ca-passphrase`).

- **Root cert renewal: at year 9 of a 10-year root.** This is the big ceremony — generate a new root keypair, re-issue all sub-CAs from the new root, distribute the new root cert to every relying party's trust store. Plan for 6+ months of overlap.

---

## 9. Sub-CA Compromise Response

If the online sub-CA host is compromised:

1. **Don't panic.** This is exactly the scenario this architecture was set up for.
2. **Take the host offline immediately.** Block at the firewall.
3. **Boot the offline root machine.** Issue a CRL entry for the compromised sub-CA serial:
   ```bash
   python3 /opt/pypki/pki_server.py --ca-dir ./ca-root \
       --revoke <compromised-subca-serial> \
       --reason keyCompromise
   python3 /opt/pypki/pki_server.py --ca-dir ./ca-root --emit-crl
   ```
4. **Publish the new root CRL.** Relying parties checking the chain will now reject any leaf that traces through the compromised sub-CA.
5. **Issue a fresh sub-CA** to a clean replacement host. (§§5-6 above, repeated.)
6. **Forensically image the compromised host.** Don't reboot it.
7. **Inventory leaf certs** issued from the compromised sub-CA. Any cert issued AFTER the compromise window is potentially attacker-controlled. Issuance gaps in the audit log are signals.
8. **Rotate leaves urgently.** Most clients will pick up new certs within their next cert-manager / acme.sh / EST renewal cycle. Force-rotate critical certs by hand.
9. **Postmortem.** What got the attacker in? Did it use a key that should've been HSM-backed? Was the host's monitoring not catching the indicators? Fix it before reissuing.

The whole sequence is a long day, not a multi-week project. **That's the win the offline root pattern buys.**

---

## 10. Root Compromise Response

If the **root** is compromised — the USB stick was stolen, the offline machine was tampered with, the safe was opened — the situation is materially worse:

1. The root cert is in every relying party's trust store. Replacing it is a coordination problem.
2. Every cert ever issued from this CA chain is potentially forgeable.
3. There is no in-band remediation: you cannot revoke the root from the root, and no other CA exists above it.

The response:

1. **Take everything offline.** Sub-CA included.
2. **Notify operators.** This is an incident, not a ceremony.
3. **Begin the trust-store rotation.** New root, new sub-CAs, new chains. Distribute the new root cert via every channel you have (config management, SCCM, JAMF, manual installs, etc.).
4. **Out-of-band notify relying parties** that the old root is no longer trustworthy. The exact channels depend on your environment — email blast, internal status page, on-call escalation.
5. **Decommission the old chain entirely.** Don't try to "patch" it.

This is the failure mode the offline-root pattern is designed to prevent. **If you find yourself doing this, the air-gap was not actually airtight.** Audit how.

---

## 11. Troubleshooting

**`openssl s_client` shows only the sub-CA cert, not the root.**
The sub-CA host doesn't have `ca-chain.pem` in place, or PyPKI can't read it. Check `<ca_dir>/ca-chain.pem` exists and is readable by the PyPKI user. Restart PyPKI.

**Relying parties verify leaf certs but reject the root CRL.**
The root cert's `crlDistributionPoints` URL doesn't match where you published the CRL, or the CRL is expired (annual refresh missed). Verify the URL in `openssl x509 -in ca.crt -noout -text` and check the actual published CRL.

**"unable to get local issuer certificate" on a relying party.**
The relying party's trust store doesn't have the root cert. Add it; this is the trust-distribution step. The sub-CA cert does NOT belong in any trust store — only the root does.

**Sub-CA reaches its `permitted-dns` boundary and refuses to issue.**
The constraint did exactly what it was supposed to. Either the request is wrong (correct it), or the constraint was set too tightly (rotate the sub-CA with broader constraints — a planned operation, not an emergency).

**Sub-CA expiry approaching with no rotation in flight.**
Schedule the rotation NOW. A sub-CA expiring with valid leaves still in the wild causes mass cert-validation failures. PyPKI does not auto-renew sub-CAs (deliberate — sub-CA renewal is an offline ceremony, not a runtime action).

---

## See also

- `docs/CPS.md` §§4-5 — what each ceremony actually entails as policy, not just procedure.
- `docs/THREAT_MODEL.md` §3 — what's gained and what's not by going to two-tier.
- `docs/DEPLOYMENT/homelab-single-node.md` — when the threat-model gain isn't worth the operational cost (most homelab cases).
- `docs/STORAGE.md` — the online sub-CA's storage backend choices once it's running.
- RFC 5280 §4.2.1.10 — Name Constraints (the spec that makes `permitted-dns` enforceable).
