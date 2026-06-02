# PyPKI WireGuard PKI

<!-- Last reviewed: 2026-06-02 -->

PyPKI acts as a WireGuard identity registry: it mints Curve25519 keypairs,
tracks peer validity windows, and distributes server configurations. No
X.509 is involved — WireGuard uses its own Curve25519-based cryptography.

---

## Enabling

WireGuard features are available via the admin REST API (`/api/wg/*`) once
the web UI is running. No extra flag is needed.

---

## Registering a WireGuard server

Before enrolling peers, register at least one WireGuard server so PyPKI
knows where to point clients:

```bash
# Generate a server keypair with wg
wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub

curl -X POST https://pki.example.com/api/wg/servers \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "server_id":    "vpn-01",
    "public_key":   "<content of server.pub>",
    "endpoint":     "vpn.example.com:51820",
    "listen_port":  51820,
    "network_cidr": "10.10.0.0/24"
  }'
```

---

## Enrolling a peer (server-side keygen)

```bash
curl -X POST https://pki.example.com/api/wg/peers \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "peer_name":  "alice@laptop",
    "allowed_ips": ["10.10.0.5/32"],
    "profile":    "wg_user_vpn"
  }'
```

Response includes `private_key` (returned **once only**, never stored) and a
ready-to-paste `config` string for the client's `wg0.conf`.

## Enrolling a peer (CSR mode, preferred for production)

The device generates its own keypair and sends only the public key:

```bash
# On the device
wg genkey | tee device.key | wg pubkey > device.pub

# Submit to PyPKI
curl -X POST https://pki.example.com/api/wg/peers \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{
    \"peer_name\":   \"server-01\",
    \"public_key\":  \"$(cat device.pub)\",
    \"allowed_ips\": [\"10.10.0.10/32\"],
    \"profile\":     \"wg_user_vpn\"
  }"
```

---

## Server config distribution (pull mode)

Run `pypki-wg-sync` on each WireGuard server:

```bash
python3 /usr/local/lib/pypki/sync.py \
  --server-id vpn-01 \
  --pypki-url https://pki.example.com \
  --api-token <token> \
  --interface wg0 \
  --interval 60
```

The agent polls every 60 seconds, compares a SHA-256 hash of the config,
and applies changes with `wg syncconf` (no peer disconnections).

---

## Profiles

| Profile          | Max validity | IP pattern            | CSR required |
|------------------|--------------|-----------------------|-------------|
| `wg_user_vpn`    | 30 days      | `10.x.x.x/32`        | No          |
| `wg_site_to_site`| 1 year       | `10.x.x.x/8|16|24`   | Yes         |

---

## Admin CLI

```bash
# List active peers
pypki_admin wg-peer-list

# Revoke a peer
pypki_admin wg-peer-revoke wg-2026-0042
```
