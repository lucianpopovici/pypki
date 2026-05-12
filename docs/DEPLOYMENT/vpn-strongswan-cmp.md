# Deployment: strongSwan IPsec VPN with CMP Enrollment

This guide enrolls [strongSwan](https://www.strongswan.org/) IPsec gateways and roadwarrior clients against PyPKI using **CMPv2 over HTTP** (RFC 4210). The result: certs that auto-renew, fully audited issuance, and standard X.509 revocation when a peer's key is compromised.

> **Why CMP instead of pasting in a CSR?** CMPv2 is the protocol IPsec gear actually understands. strongSwan ships [`pki --est`](https://wiki.strongswan.org/projects/strongswan/wiki/pki) and [`pki --cmp`](https://docs.strongswan.org/docs/5.9/pki/pkiCmp.html), Cisco IOS gateways speak it, IBM Hardware Crypto Cards speak it. PSK-based IPsec is fine for a homelab where you have three peers; once you have a dozen, certificate-based auth with proper enrollment is the only configuration that scales.

> **Two enrollment patterns covered here.**
> 1. **`pki --cmp` from strongSwan's command-line tools** for one-shot enrollment, useful for gateway certs you'll renew manually every couple of years.
> 2. **`charon` plugin auto-renewal** so client/roadwarrior certs renew themselves before expiry without operator action.

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [Prerequisites](#2-prerequisites)
3. [Decide on the IPsec PKI Profile](#3-decide-on-the-ipsec-pki-profile)
4. [Enroll the Gateway with `pki --cmp`](#4-enroll-the-gateway-with-pki---cmp)
5. [Configure strongSwan to Use the Cert](#5-configure-strongswan-to-use-the-cert)
6. [Auto-Renewal with `charon-cmd` and Hooks](#6-auto-renewal-with-charon-cmd-and-hooks)
7. [Roadwarrior Clients (Auto-Enrolled)](#7-roadwarrior-clients-auto-enrolled)
8. [Revocation and CRL/OCSP Distribution](#8-revocation-and-crlocsp-distribution)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Architecture

```
                                    ┌──────────────────────┐
                                    │       PyPKI          │
                                    │   - Root CA          │
                                    │   - CMP server       │
                                    │   - OCSP responder   │
                                    │   - CRL endpoint     │
                                    └─────────┬────────────┘
                                              │  CMPv2 over HTTP
                                              │  (port 443/8443)
                       ┌──────────────────────┼──────────────────────┐
                       │                      │                      │
              ┌────────▼────────┐    ┌────────▼────────┐    ┌────────▼────────┐
              │  Gateway A      │    │  Gateway B      │    │  Roadwarrior    │
              │  strongSwan     │    │  strongSwan     │    │  strongSwan +   │
              │  (site-to-site) │    │  (site-to-site) │    │  charon-cmd     │
              └────────┬────────┘    └────────┬────────┘    └─────────────────┘
                       │                      │
                       └────── IPsec ESP ─────┘
                              (auth via certs,
                               not PSK)
```

Every IPsec peer holds a cert issued by PyPKI. mTLS-style mutual authentication on tunnel setup. CRL/OCSP-based revocation propagates within minutes when a peer is compromised or decommissioned.

---

## 2. Prerequisites

- **PyPKI** running with CMP enabled (`--cmp-prefix /cmp`, default).
- **strongSwan** installed on every peer. Version 5.9+ recommended (older versions ship a less complete `pki --cmp`).
- **CMP shared secret** generated per-peer for initial enrollment. PyPKI's CMP supports both PBM (password-based MAC, RFC 4210 §5.1.3.1) and signature-based protection. For first-time enrollment, PBM is what you'll use.
- **PyPKI admin API access** for provisioning CMP shared secrets.

Generate a CMP shared secret per peer:

```bash
export PYPKI_URL="https://pki.example.com"
export PYPKI_ADMIN_KEY="..."

GATEWAY_NAME="vpn-gw-nyc"
SECRET="$(openssl rand -base64 32)"

curl -X POST "$PYPKI_URL/api/cmp/shared-secrets" \
    -H "Authorization: Bearer $PYPKI_ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d @- <<EOF
{
  "reference": "$GATEWAY_NAME",
  "secret": "$SECRET",
  "allowed_subject": "CN=$GATEWAY_NAME, O=Example Corp, OU=VPN",
  "allowed_san_dns": ["$GATEWAY_NAME.example.com"],
  "max_uses": 1,
  "expires_in_hours": 24
}
EOF
```

Constraints worth noting:
- **`max_uses: 1`** means the shared secret is single-use — it'll work for the initial enrollment and then be invalidated. Subsequent renewals use the issued cert as the auth method.
- **`expires_in_hours: 24`** caps the window where the secret is usable. Print it on the gateway console during a maintenance window, then it's gone.
- **`allowed_subject`** and **`allowed_san_dns`** are policy bindings — PyPKI rejects CMP requests under this secret that ask for a different identity. This is the part that matters for security; without it, a leaked shared secret could enroll any subject.

Hand `$SECRET` to the gateway operator over a secure channel (signed message, sealed envelope, in-person, etc.). It's not as sensitive as the eventual private key, but it's not nothing.

---

## 3. Decide on the IPsec PKI Profile

Pick one before issuing certs. Mixing profiles within the same VPN deployment causes subtle failures that look like network problems.

| Decision | Recommendation | Why |
|---|---|---|
| **Key algorithm** | ECDSA P-256 | Smaller, faster, broadly supported. RSA-2048 fine if you have legacy peers. |
| **Validity** | 1 year for gateways, 90 days for roadwarriors | Gateways are stable, change rarely. Roadwarriors come and go. |
| **Subject DN** | `CN=<peer-fqdn>, O=<org>, OU=VPN` | The `CN` is the peer's FQDN. strongSwan matches on it during tunnel setup. |
| **SAN** | `DNS:<peer-fqdn>` (gateways), `email:user@example.com` (roadwarriors) | Roadwarriors authenticate as users, not as hosts. |
| **EKU** | `id-kp-serverAuth` + `id-kp-clientAuth` for site-to-site, just `id-kp-clientAuth` for roadwarriors | strongSwan respects EKU; old IKEv1 equipment may not. |
| **CRL / OCSP** | Both, with HTTP-only URLs | strongSwan resolves these automatically from the cert's `cRLDistributionPoints` / `authorityInfoAccess` extensions. |

PyPKI applies a default profile of `tls_server` to every issued cert. For IPsec-specific defaults, define a profile:

```bash
curl -X POST "$PYPKI_URL/api/profiles" \
    -H "Authorization: Bearer $PYPKI_ADMIN_KEY" \
    -d '{
      "name": "ipsec",
      "validity_days": 365,
      "key_algorithm": "ecdsa-p256",
      "extended_key_usage": ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"],
      "include_crl_dp": true,
      "include_aia": true
    }'
```

Reference the profile from CMP requests (covered in §4 below).

---

## 4. Enroll the Gateway with `pki --cmp`

On the strongSwan gateway:

```bash
# Generate the keypair locally — the private key NEVER leaves this host.
pki --gen --type ecdsa --size 256 --outform pem > /etc/swanctl/private/vpn-gw-nyc.key
chmod 0600 /etc/swanctl/private/vpn-gw-nyc.key

# Run pki --cmp to obtain a cert.
# The shared secret was generated in §2.
pki --cmp \
    --url "https://pki.example.com/cmp" \
    --reference "vpn-gw-nyc" \
    --secret "<the-shared-secret-from-section-2>" \
    --type ir \
    --in /etc/swanctl/private/vpn-gw-nyc.key \
    --dn "CN=vpn-gw-nyc, O=Example Corp, OU=VPN" \
    --san "vpn-gw-nyc.example.com" \
    --profile "ipsec" \
    --outform pem \
    > /etc/swanctl/x509/vpn-gw-nyc.crt
```

Flag-by-flag:

| Flag | What it does |
|---|---|
| `--url` | PyPKI's CMP endpoint. Note `https://` — strongSwan validates the TLS cert of the CMP server itself, so `pki.example.com`'s TLS cert must already be in the gateway's trust store. |
| `--reference` / `--secret` | The PBM auth pair from §2. |
| `--type ir` | "Initialization Request" — the CMPv2 message type for first-time enrollment. Subsequent renewals use `--type kur` (Key Update Request). |
| `--in` | Local private key (we generated it above; the public key is extracted and put in the CSR). |
| `--dn` | Subject DN. Must match the `allowed_subject` from §2. |
| `--san` | SubjectAltName. Must match `allowed_san_dns` from §2. |
| `--profile` | PyPKI profile name to use. |

**Failure modes worth knowing:**

- **"PBM verification failed"** → wrong shared secret, or the secret was already used (`max_uses` reached).
- **"subject DN not allowed"** → the `--dn` didn't match the `allowed_subject` policy on the shared secret.
- **"CMP server cert not trusted"** → `pki.example.com`'s TLS cert isn't in the gateway's CA bundle. Either install the PyPKI root cert system-wide or use `--cacert` on the `pki --cmp` invocation.

After success, you have `/etc/swanctl/x509/vpn-gw-nyc.crt`. Inspect it:

```bash
pki --print --in /etc/swanctl/x509/vpn-gw-nyc.crt
# Or:
openssl x509 -in /etc/swanctl/x509/vpn-gw-nyc.crt -text -noout
```

The cert should have:
- Subject: `CN=vpn-gw-nyc, O=Example Corp, OU=VPN`
- SAN: `DNS:vpn-gw-nyc.example.com`
- Extended Key Usage: `TLS Web Server Authentication, TLS Web Client Authentication`
- CRL Distribution Points: `URI:http://pki.example.com/crl/...`
- Authority Information Access: `OCSP - URI:http://pki.example.com/ocsp`

If any of these are missing, the profile in §3 wasn't applied — recheck the `--profile ipsec` flag and the profile definition.

---

## 5. Configure strongSwan to Use the Cert

Drop the PyPKI root and the new gateway cert into strongSwan's trust paths:

```bash
# PyPKI root → trust anchor for incoming peer certs.
curl https://pki.example.com/api/ca-cert -o /etc/swanctl/x509ca/pypki-root.crt

# The new gateway cert (already done above):
ls -la /etc/swanctl/x509/vpn-gw-nyc.crt
ls -la /etc/swanctl/private/vpn-gw-nyc.key
```

Now write a `swanctl.conf` connection that uses cert auth:

```conf
# /etc/swanctl/conf.d/site-to-site-nyc.conf
connections {
  nyc-to-sfo {
    version = 2
    proposals = aes256-sha256-x25519
    local_addrs = vpn-gw-nyc.example.com
    remote_addrs = vpn-gw-sfo.example.com

    local {
      auth = pubkey
      certs = vpn-gw-nyc.crt
      id = "CN=vpn-gw-nyc, O=Example Corp, OU=VPN"
    }
    remote {
      auth = pubkey
      id = "CN=vpn-gw-sfo, O=Example Corp, OU=VPN"
    }

    children {
      nyc-sfo {
        local_ts = 10.10.0.0/16
        remote_ts = 10.20.0.0/16
        esp_proposals = aes256-sha256
        start_action = trap
        close_action = trap
      }
    }
  }
}
```

```bash
swanctl --load-all
swanctl --initiate --child nyc-sfo
swanctl --list-sas
```

The `--list-sas` output should show an `ESTABLISHED` security association. If not, `journalctl -u strongswan` will tell you why — the most common cause is the remote peer's cert not chaining to the same PyPKI root.

---

## 6. Auto-Renewal with `charon-cmd` and Hooks

A 365-day cert that you have to manually rotate every year is a 365-day cert that you'll forget to rotate one year. Build auto-renewal in from the start.

The pattern: a cron job (or systemd timer) runs ~30 days before expiry, calls `pki --cmp --type kur` with the *existing cert as auth* (not the now-invalid shared secret), and writes the new cert in place. strongSwan reloads on the next configuration sync.

```bash
# /usr/local/bin/pypki-renew-vpn-cert.sh
#!/bin/bash
set -euo pipefail

CERT="/etc/swanctl/x509/vpn-gw-nyc.crt"
KEY="/etc/swanctl/private/vpn-gw-nyc.key"
CMP_URL="https://pki.example.com/cmp"
DN="CN=vpn-gw-nyc, O=Example Corp, OU=VPN"
SAN="vpn-gw-nyc.example.com"

# Check days remaining. Renew if under 30.
DAYS_LEFT=$(( ( $(date -d "$(openssl x509 -enddate -noout -in "$CERT" | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
if [[ $DAYS_LEFT -gt 30 ]]; then
    logger "pypki-renew: $CERT has $DAYS_LEFT days remaining, no action"
    exit 0
fi

logger "pypki-renew: renewing $CERT ($DAYS_LEFT days remaining)"

# Generate a NEW keypair. We rotate the key on every renewal.
NEW_KEY="$(mktemp)"
NEW_CERT="$(mktemp)"
trap "rm -f $NEW_KEY $NEW_CERT" EXIT

pki --gen --type ecdsa --size 256 --outform pem > "$NEW_KEY"

# Use the EXISTING cert + key to authenticate the renewal request.
# This is signature-based CMP protection (RFC 4210 §5.1.3.3),
# replacing the PBM secret used for initial enrollment.
pki --cmp \
    --url "$CMP_URL" \
    --type kur \
    --cert "$CERT" \
    --key "$KEY" \
    --in "$NEW_KEY" \
    --dn "$DN" \
    --san "$SAN" \
    --outform pem \
    > "$NEW_CERT"

# Atomic swap. strongSwan watches for changes via inotify (or via swanctl --reload-creds).
mv "$NEW_KEY" "$KEY"
mv "$NEW_CERT" "$CERT"
chmod 0600 "$KEY"
chmod 0644 "$CERT"

# Tell strongSwan to reload.
swanctl --reload-creds

logger "pypki-renew: renewal of $CERT successful"
```

```bash
# Run daily.
echo "0 3 * * * root /usr/local/bin/pypki-renew-vpn-cert.sh" > /etc/cron.d/pypki-renew
```

**Key rotation on every renewal** is a deliberate choice. RFC 4210 allows reusing the key (`--type cr` instead of `kur`), but rotating means a stolen private key becomes worthless after the next renewal cycle. The cost is essentially zero — `pki --gen` is fast, and ECDSA keys are tiny.

---

## 7. Roadwarrior Clients (Auto-Enrolled)

Roadwarriors are the harder case: laptops/phones connecting from variable networks, often with users who shouldn't be running CMP commands themselves. Two patterns:

**Pattern 1: Pre-seed the cert during user provisioning.**
Same flow as §4 — the IT admin runs `pki --cmp` once on the user's behalf during laptop setup, the cert lives on the laptop for a year, the user re-provisions when the cert expires. Simple, works, doesn't auto-renew.

**Pattern 2: Bootstrap with a short-lived shared secret + auto-renewal.**
The IT admin generates a 24-hour PBM secret per user (§2), the user runs an enrollment script once on the laptop (which calls `pki --cmp --type ir`), and the script also installs the renewal cron job (§6). After the first 24 hours, the laptop is in the auto-renewal loop and never needs IT involvement again.

Pattern 2 reference script:

```bash
# /usr/local/bin/pypki-roadwarrior-enroll.sh — one-time bootstrap
#!/bin/bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <user-email> <bootstrap-secret>"
    exit 1
fi
USER_EMAIL="$1"
SECRET="$2"

CERT="/etc/swanctl/x509/${USER_EMAIL}.crt"
KEY="/etc/swanctl/private/${USER_EMAIL}.key"

mkdir -p /etc/swanctl/x509 /etc/swanctl/private
pki --gen --type ecdsa --size 256 --outform pem > "$KEY"
chmod 0600 "$KEY"

pki --cmp \
    --url "https://pki.example.com/cmp" \
    --reference "$USER_EMAIL" \
    --secret "$SECRET" \
    --type ir \
    --in "$KEY" \
    --dn "CN=$USER_EMAIL, O=Example Corp, OU=Roadwarrior" \
    --san "email:$USER_EMAIL" \
    --profile "ipsec" \
    --outform pem \
    > "$CERT"

# Install the renewal cron from §6, parameterized for this user's cert.
sed "s/vpn-gw-nyc/$USER_EMAIL/g" /usr/local/share/pypki/renew-template.sh \
    > "/usr/local/bin/pypki-renew-${USER_EMAIL}.sh"
chmod 0755 "/usr/local/bin/pypki-renew-${USER_EMAIL}.sh"
echo "0 3 * * * root /usr/local/bin/pypki-renew-${USER_EMAIL}.sh" \
    > "/etc/cron.d/pypki-renew-${USER_EMAIL}"

echo "Enrollment complete. Cert at $CERT, valid until $(openssl x509 -enddate -noout -in $CERT | cut -d= -f2)."
```

The user runs this once with their bootstrap secret. After that, the renewal cron keeps things current indefinitely.

---

## 8. Revocation and CRL/OCSP Distribution

When a peer is decommissioned, lost, or compromised, revoke the cert via PyPKI's API:

```bash
SERIAL="$(openssl x509 -in vpn-gw-nyc.crt -serial -noout | cut -d= -f2)"

curl -X POST "$PYPKI_URL/api/revoke" \
    -H "Authorization: Bearer $PYPKI_ADMIN_KEY" \
    -d "{\"serial\": \"$SERIAL\", \"reason\": \"keyCompromise\"}"
```

Reasons that matter for IPsec:
- `keyCompromise` — the peer's private key was exposed. **Revoke immediately**, do not delay.
- `cessationOfOperation` — the peer was retired but the key was destroyed cleanly. Less urgent.
- `superseded` — the peer was re-enrolled with a fresh cert. The new cert is valid; the old serial is for housekeeping.

strongSwan's `charon` daemon refreshes CRLs based on the `nextUpdate` field of the CRL it has cached. PyPKI defaults to a 24-hour CRL validity window. If you need faster revocation propagation:

- **Reduce CRL validity** to 1 hour: configure PyPKI with `--crl-validity 1h` (forces all peers to refetch hourly).
- **Use OCSP** for sub-minute propagation: strongSwan checks OCSP per IPsec rekey when the cert has an `authorityInfoAccess` extension pointing to the responder.
- **Force cache flush on all peers**: `swanctl --flush-certs` on each peer (operationally heavy; use only during a planned cutover).

For most VPN deployments, 24-hour CRL + OCSP is the right balance. Anything tighter pushes load onto PyPKI without much practical security gain.

---

## 9. Troubleshooting

**`pki --cmp` returns "EE certificate verification failed".**
The CMP server's TLS cert isn't trusted. If PyPKI is using a cert signed by itself, install the PyPKI root in the gateway's CA bundle (`/etc/ssl/certs/`) before running `pki --cmp`. Or pass `--cacert /path/to/pypki-root.crt`.

**Tunnel comes up but immediately tears down with "no peer config found".**
The peer's `id` in `swanctl.conf` doesn't exactly match the cert's subject DN. strongSwan does string-equality matching on the DN. Check both ends:
```bash
swanctl --list-conns | grep -A 20 nyc-to-sfo
openssl x509 -in vpn-gw-nyc.crt -subject -noout
```
The `id = "..."` in `swanctl.conf` and the cert's subject must match exactly, including attribute order.

**`pki --cmp --type kur` fails with "no shared secret configured".**
You're trying to do a renewal but `pki` doesn't see the existing cert — typically a path issue. Pass `--cert` AND `--key` explicitly even if they're in the default locations.

**Renewal script ran but strongSwan still serves the old cert.**
strongSwan caches certs in memory. `swanctl --reload-creds` (in the renewal script) tells it to refresh. If that's not enough, `swanctl --flush-certs` followed by `--reload-creds` is the heavier hammer.

**OCSP requests from strongSwan fail with "OCSP responder not reachable".**
strongSwan resolves the OCSP URL from the cert's `authorityInfoAccess` extension. If that URL is `https://pki.example.com/ocsp` but the gateway can't reach `pki.example.com` (e.g., the gateway is in an isolated network), you've got an architecture problem. Either:
- Make the OCSP responder reachable from the gateway's network (often via the VPN tunnel itself, which creates a chicken-and-egg problem on tunnel establishment).
- Disable OCSP in the strongSwan config and rely on CRL only: `revocation { ocsp = no }`.

**Auto-renewal works for months then suddenly fails.**
Check the date. If your gateway's clock is wrong, signature validation on CMP responses fails. CMP uses tight clock skew tolerances (default 5 minutes). Make sure NTP is configured and working.

**You've issued a thousand roadwarrior certs and the CRL is now huge.**
This is expected. CRL growth is proportional to revoked-and-not-yet-expired certs. Two mitigations:
- **Shorten cert validity** (90 days for roadwarriors, not 1 year). Expired certs drop off the CRL automatically.
- **Switch to OCSP-only**, configure strongSwan to ignore CRLs: `revocation { crl = no, ocsp = yes }`. OCSP is per-cert lookup, no list-of-everyone.

**You want to migrate from PSK-based IPsec to cert-based without downtime.**
Configure both auth methods on each peer: `local { auth = pubkey; auth = psk }`. strongSwan will accept either during the transition. Cut PSK over a maintenance window once all peers have certs.

---

## See also

- `docs/CPS.md` §3.2 — PyPKI's identity validation policy for CMP enrollment.
- `docs/CPS.md` §4.9 — revocation procedures.
- `docs/THREAT_MODEL.md` §3 — what an attacker who steals a VPN gateway's private key can do (and why short-lived certs matter).
- strongSwan CMP docs: https://docs.strongswan.org/docs/5.9/pki/pkiCmp.html
- strongSwan swanctl reference: https://docs.strongswan.org/docs/5.9/swanctl/swanctlConf.html
- RFC 4210 (CMPv2): https://www.rfc-editor.org/rfc/rfc4210
- RFC 4211 (CRMF): https://www.rfc-editor.org/rfc/rfc4211
