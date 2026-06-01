# Deployment: ACME dns-01 against Pi-hole

> Last reviewed: 2026-06-01 (commit 453e7ba)

This guide documents an unusual but functional setup: using a **Pi-hole** (dnsmasq-based) DNS server as the authoritative resolver for ACME `dns-01` challenges against PyPKI. It's the configuration that emerged from running this in a homelab, and it has properties that make it useful elsewhere too.

## Why this combination is interesting

- **Pi-hole runs dnsmasq under the hood.** dnsmasq doesn't have a dynamic-update API like BIND does. There's no built-in "TSIG-signed UPDATE" path for ACME clients to inject `_acme-challenge` records.
- **ACME `dns-01` requires those records to appear and disappear** as part of the challenge cycle.
- **The bridge** is a small SSH hook that writes a `/etc/dnsmasq.d/acme-challenge.conf` file and restarts dnsmasq. Crude, but reliable, no extra services, no network exposure beyond SSH that's already there.
- **No public-DNS exposure needed.** The Pi-hole serves only your internal network, and the PyPKI ACME server you're hitting is also internal. The challenge round-trip never touches the public DNS infrastructure.

This pattern works for any internal CA where you want ACME ergonomics (acme.sh / certbot / lego on the client side) without owning a real DNS server with an update API.

## Topology

```
┌────────────────┐                ┌─────────────────┐
│   ACME client  │                │     PyPKI       │
│   (acme.sh on  │  HTTPS POST    │  ACME endpoint  │
│   OpenWrt)     │ ─────────────▶ │  /acme/*        │
└──────┬─────────┘                └────────┬────────┘
       │                                   │
       │ 1. order created                  │ 2. challenge issued
       │                                   │   (token = abc123...)
       │                                   │
       │ 3. SSH hook to pi-hole            │
       ▼                                   │
┌────────────────┐                          │
│   Pi-hole      │                          │
│   (dnsmasq)    │                          │
│   writes       │                          │
│   acme-challenge.conf                    │
└──────┬─────────┘                          │
       │                                   │
       │ 4. _acme-challenge.example.       │ 5. dns-01 lookup against
       │    home.arpa = abc123...          │    pi-hole
       │                                   │
       │                                   │
       └───────────────────────────────────┘
```

## Prerequisites

- A Pi-hole instance running on your network (hereafter `pihole.home.arpa`)
- SSH key-based access from the ACME client host to the Pi-hole, as a user with passwordless `sudo` to write `/etc/dnsmasq.d/` and restart `dnsmasq`
- A running PyPKI deployment with `--acme-prefix /acme` enabled
- Your Pi-hole already serves your internal zone (e.g., `home.arpa`)

## Step 1 — Lock down the Pi-hole user

Create a dedicated user on the Pi-hole that the ACME client will SSH in as. Restrict it to only what the hook needs.

```bash
# On the Pi-hole host:
sudo useradd --system --shell /bin/bash --create-home acme-hook
sudo mkdir -p /home/acme-hook/.ssh
sudo chmod 700 /home/acme-hook/.ssh

# Paste the ACME client's public key:
sudo install -m 600 -o acme-hook -g acme-hook /dev/null /home/acme-hook/.ssh/authorized_keys
echo "ssh-ed25519 AAAA... acme-client@openwrt" | sudo tee /home/acme-hook/.ssh/authorized_keys

# Allow it passwordless sudo for ONLY the two commands needed:
sudo install -m 440 /dev/null /etc/sudoers.d/acme-hook
sudo tee /etc/sudoers.d/acme-hook <<'EOF'
acme-hook ALL=(root) NOPASSWD: /usr/bin/install -m 644 /tmp/acme-challenge.conf /etc/dnsmasq.d/acme-challenge.conf
acme-hook ALL=(root) NOPASSWD: /usr/bin/rm -f /etc/dnsmasq.d/acme-challenge.conf
acme-hook ALL=(root) NOPASSWD: /usr/sbin/service pihole-FTL restart
EOF
```

The principle is `NOPASSWD` on **specific full command lines**, not bare programs. `acme-hook` cannot SSH in and `sudo install` arbitrary files — only the exact paths above.

## Step 2 — Install the hook script on the ACME client

```bash
# On the ACME client host:
sudo install -m 750 -o root /dev/null /usr/local/bin/pihole-acme-hook
sudo tee /usr/local/bin/pihole-acme-hook <<'EOF'
#!/bin/sh
# Hook for acme.sh / certbot / lego dns-01 against Pi-hole.
#
# Usage:
#   pihole-acme-hook add    <fqdn> <token>
#   pihole-acme-hook remove <fqdn> <token>
#
# The FQDN is what acme.sh passes (e.g., _acme-challenge.example.home.arpa).
# Token is the challenge value to put in the TXT record.

set -eu

PIHOLE_HOST="pihole.home.arpa"
PIHOLE_USER="acme-hook"
SSH_KEY="/etc/acme/pihole-hook-key"

ACTION="$1"
FQDN="$2"
TOKEN="${3:-}"

case "$ACTION" in
  add)
    # Build the dnsmasq TXT record file remotely
    ssh -i "$SSH_KEY" "$PIHOLE_USER@$PIHOLE_HOST" \
        "echo 'txt-record=$FQDN,\"$TOKEN\"' > /tmp/acme-challenge.conf && \
         sudo install -m 644 /tmp/acme-challenge.conf /etc/dnsmasq.d/acme-challenge.conf && \
         sudo service pihole-FTL restart"
    ;;
  remove)
    ssh -i "$SSH_KEY" "$PIHOLE_USER@$PIHOLE_HOST" \
        "sudo rm -f /etc/dnsmasq.d/acme-challenge.conf && \
         sudo service pihole-FTL restart"
    ;;
  *)
    echo "Usage: $0 {add|remove} <fqdn> <token>" >&2
    exit 1
    ;;
esac

# Pi-hole DNS reload propagates to clients in seconds. Wait briefly.
sleep 5
EOF
sudo chmod 750 /usr/local/bin/pihole-acme-hook
```

Generate a key pair specifically for this hook (do not reuse your personal SSH key):

```bash
sudo ssh-keygen -t ed25519 -N '' -f /etc/acme/pihole-hook-key -C 'acme-client-pihole-hook'
sudo cat /etc/acme/pihole-hook-key.pub
# Paste this into /home/acme-hook/.ssh/authorized_keys on the Pi-hole.
```

## Step 3 — Wire up your ACME client

### With acme.sh

acme.sh's `dns_manual` mode is the lowest-friction starting point but it pauses for human input. For automation, use a proper hook plugin.

acme.sh ships a generic hook protocol in `--dns dns_<name>`. The simplest path is to write a thin `acme.sh`-compatible wrapper that invokes our `pihole-acme-hook`:

```bash
# /etc/acme.sh/dnsapi/dns_pihole.sh
#!/usr/bin/env bash

dns_pihole_add() {
    local fqdn="$1"
    local token="$2"
    /usr/local/bin/pihole-acme-hook add "$fqdn" "$token"
}

dns_pihole_rm() {
    local fqdn="$1"
    local token="$2"
    /usr/local/bin/pihole-acme-hook remove "$fqdn" "$token"
}
```

Then issue:

```bash
acme.sh --issue \
        --dns dns_pihole \
        --server https://pki.home.arpa/acme/directory \
        --domain example.home.arpa
```

### With certbot

certbot calls a hook script with environment variables `CERTBOT_DOMAIN`, `CERTBOT_VALIDATION`, `CERTBOT_TOKEN`:

```bash
# /etc/letsencrypt/auth-hook.sh
#!/bin/sh
exec /usr/local/bin/pihole-acme-hook add \
    "_acme-challenge.${CERTBOT_DOMAIN}" "${CERTBOT_VALIDATION}"
```

```bash
# /etc/letsencrypt/cleanup-hook.sh
#!/bin/sh
exec /usr/local/bin/pihole-acme-hook remove \
    "_acme-challenge.${CERTBOT_DOMAIN}" "${CERTBOT_VALIDATION}"
```

Then:

```bash
certbot certonly \
    --manual \
    --preferred-challenges=dns \
    --manual-auth-hook /etc/letsencrypt/auth-hook.sh \
    --manual-cleanup-hook /etc/letsencrypt/cleanup-hook.sh \
    --server https://pki.home.arpa/acme/directory \
    --no-eff-email --agree-tos --email admin@home.arpa \
    -d example.home.arpa
```

### With lego

lego has a generic `EXEC` provider:

```bash
EXEC_PATH=/usr/local/bin/pihole-acme-hook \
EXEC_PROPAGATION_TIMEOUT=30 \
lego --email admin@home.arpa \
     --server https://pki.home.arpa/acme/directory \
     --dns exec \
     --domains example.home.arpa \
     run
```

## Step 4 — Verify the round-trip

```bash
# Trigger a manual issuance and watch it work:
acme.sh --issue --dns dns_pihole \
        --server https://pki.home.arpa/acme/directory \
        --domain example.home.arpa --debug 2

# In another terminal, watch the Pi-hole's dnsmasq logs:
ssh acme-hook@pihole.home.arpa 'sudo journalctl -fu pihole-FTL'

# You should see the file appear, dnsmasq reload, and the challenge
# resolve to the expected token.

# Check from a third host that the TXT record really exists during the challenge:
dig @pihole.home.arpa _acme-challenge.example.home.arpa TXT
```

## What can go wrong (and how to debug)

**Challenge times out, dnsmasq says NXDOMAIN**

Likely the dnsmasq reload didn't take. Check `ls -la /etc/dnsmasq.d/acme-challenge.conf` on the Pi-hole — it should exist with the right contents during the challenge window. If it's missing, the SSH hook failed silently. Add `set -x` to the hook to debug.

**ACME server reports "DNS problem: NXDOMAIN" even though the record exists**

Check that PyPKI's ACME server can actually resolve via your Pi-hole. If your PyPKI host has its own resolver (systemd-resolved, etc.) configured to use a different DNS, the Pi-hole's record is invisible to it. Either:
- Point the PyPKI host's DNS at the Pi-hole, or
- Configure split-horizon: have the Pi-hole forward `_acme-challenge.*` records to itself authoritatively.

**Concurrent ACME orders trample each other's challenge files**

The hook above writes a single `acme-challenge.conf` file. Two simultaneous orders will overwrite each other's TXT record, and one will fail. For low-volume homelab use this is a non-issue. For higher volume, use append-mode + atomic deletion:

```bash
# add:
ssh acme-hook@pihole 'echo "txt-record=$FQDN,\"$TOKEN\"" >> /tmp/acme-challenge.conf && \
                       sudo install ... && sudo service pihole-FTL restart'

# remove:
ssh acme-hook@pihole 'sudo sed -i "\#txt-record=$FQDN.*$TOKEN#d" /etc/dnsmasq.d/acme-challenge.conf && \
                       sudo service pihole-FTL restart'
```

This requires careful escaping of special characters in the regex.

**Pi-hole web UI shows query log spam from the challenge**

Expected. Each challenge results in a few queries. Filter them in your dashboard or accept the noise.

**SSH key gets rotated, hook stops working silently**

Add a periodic check from your monitoring system that runs `pihole-acme-hook add test.home.arpa probe123 && pihole-acme-hook remove test.home.arpa probe123` and alerts on failure.

## Why not just use `dns_dnsmasq` if it exists?

acme.sh has a `dns_dnsmasq` plugin in some forks but it requires either:
- TSIG keys (dnsmasq doesn't support these natively), or
- A dnsmasq REST API plugin (extra service to maintain)

The SSH hook here is uglier but ships with zero extra services and no extra attack surface beyond the SSH that's already there.

## Why dns-01 and not http-01?

For internal certs, http-01 would require either:
- Every cert subject to run an HTTP server on port 80 (often impractical for IoT, mTLS-only services, etc.)
- A central HTTP responder per challenge with name-based routing

dns-01 is more flexible: any host that can SSH to the Pi-hole can prove ownership of any name in the zone, regardless of whether that name has an HTTP server.

## Security considerations

The hook lets anyone with the SSH private key write arbitrary `_acme-challenge.*` records to your internal DNS. That's by design — it IS what's needed to prove zone ownership. Bound the blast radius by:

1. **Restrict who has the SSH private key.** Ideally just the ACME client host.
2. **Consider per-zone authentication.** If you have multiple internal zones, run separate hook accounts per zone with separate keys, each scoped to write only its own zone's TXT records (requires a slightly more sophisticated hook).
3. **Audit `/var/log/auth.log` on the Pi-hole** for `acme-hook` SSH activity. Spike of unexpected logins → key compromise.
4. **Monitor for unexpected ACME orders against PyPKI.** PyPKI's audit log shows every issuance. If you see issuance for a name nobody asked for, that's the signal.

## References

- acme.sh: <https://github.com/acmesh-official/acme.sh>
- certbot: <https://certbot.eff.org>
- lego: <https://go-acme.github.io/lego/>
- RFC 8555 §8.4 — dns-01 challenge
- [CPS.md §3.2](../CPS.md#32-initial-identity-validation) — identity validation in PyPKI
