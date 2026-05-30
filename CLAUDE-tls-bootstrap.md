# CLAUDE-tls-bootstrap.md — TLS Self-Bootstrap

Companion to `CLAUDE.md`. Follow all conventions there. Solves the
chicken-and-egg problem: PyPKI is the CA, but its own admin / ACME
endpoint needs a TLS certificate from a CA. Three documented
patterns, one preferred default, and a live-rotation command that
swaps certs without a restart.

---

## What this is

PyPKI's admin endpoint, REST API, and ACME directory all need to be
served over TLS. The cert for that endpoint has to come from somewhere.
Today operators piece it together manually: either drop in a self-signed
cert, or terminate TLS at nginx with a Let's Encrypt cert (Docker
Compose default), or provide their own.

This spec formalizes all three patterns and adds a bootstrap flow:

1. `pypki init` generates a 24-hour self-signed bootstrap cert so
   PyPKI can start.
2. PyPKI starts.
3. PyPKI issues itself a real cert from its own root via the
   internal API.
4. PyPKI rolls the live listener over to the new cert without
   dropping connections.

After bootstrap, the operator picks the long-term pattern.

---

## The three patterns

### Pattern A: self-signed by own CA (homelab default)

PyPKI issues its own admin cert. Operators trust PyPKI's root on their
admin clients (curl `--cacert`, browser trust store, OS trust store).

```
PyPKI root
  └── PyPKI admin/REST cert
```

Pros: zero external dependencies, fully self-contained.
Cons: every admin client needs the root installed; doesn't work for
publicly-reachable endpoints.

### Pattern B: Let's Encrypt via nginx (public-facing default)

nginx terminates TLS, fetches its own LE cert via certbot or acme.sh,
and proxies to PyPKI on a local port. PyPKI itself runs HTTP-only or
serves a self-signed cert that only nginx sees.

```
Internet
  └── nginx (LE cert)
        └── PyPKI on 127.0.0.1:8080
```

Pros: trusted by every browser out of the box.
Cons: extra moving part, LE rate limits, weird recursion (PyPKI is
also an ACME server).

### Pattern C: external CA

Operator provides cert + key from their existing CA. PyPKI loads them
and serves directly. Used when there's a corporate CA hierarchy PyPKI
should fit into.

```
Corporate root
  └── Corporate intermediate
        └── PyPKI admin cert (operator-provisioned)
```

Pros: integrates with existing trust.
Cons: rotation is operator-managed; PyPKI doesn't drive it.

---

## Bootstrap flow

When `--tls-mode self-bootstrap` (the default after init):

1. **Init time**: `pypki init` generates a self-signed cert at
   `/etc/pypki/tls/admin-bootstrap.crt`, valid 24 hours, ECDSA P-256,
   SAN = configured hostname.
2. **First start**: PyPKI binds the listener with the bootstrap cert.
   Logs a prominent warning that the cert is bootstrap-only.
3. **Self-enrollment**: within 30 seconds of `READY=1`, PyPKI calls
   its own internal API (`pki_server.py:issue_certificate()`) to
   issue a real cert from the configured CA. Profile:
   `pypki_self_tls` (new entry).
4. **Hot rotation**: `tls_manager.rotate(new_cert, new_key)` swaps
   the active TLS material on the listener. New connections use the
   new cert immediately; in-flight connections finish with the old
   cert until they close.
5. **Bootstrap material destroyed**: `admin-bootstrap.key` is
   zeroized and unlinked. The bootstrap cert is kept on disk for
   debugging but is no longer trusted.
6. **Ongoing**: a renewal timer triggers re-issuance at 1/3 lifetime,
   same hot rotation, no downtime.

If self-enrollment fails (e.g. DB unreachable), PyPKI keeps the
bootstrap cert and retries every 60 seconds. After 24 hours the
bootstrap cert expires and PyPKI fails its preflight check — the
operator must intervene. Loud failure beats silent insecurity.

---

## Profile: `pypki_self_tls`

New `CertProfile` entry near line 606 in `pki_server.py`:

```python
"pypki_self_tls": CertProfile(
    key_usage=KeyUsage(digital_signature=True, key_encipherment=True),
    extended_key_usages=[
        ExtendedKeyUsageOID.SERVER_AUTH,
        ExtendedKeyUsageOID.CLIENT_AUTH,    # mTLS admin can reuse same cert
    ],
    validity_days=90,                       # tight renewal cadence
    allowed_algorithms={"ecdsa-p256", "ecdsa-p384"},
    portal_self_revoke=False,               # only internal CLI revokes
    portal_self_renew=False,
),
```

Validity is deliberately short (90 days) to exercise the rotation path
in real deployments. If rotation is broken, operators discover it
quickly, not nine months later when the cert expires at 3 AM.

---

## Hot rotation

The listener has to swap TLS material without dropping connections.
Standard pattern in Python's `ssl.SSLContext` world:

```python
# tls_manager.py
class TLSManager:
    def __init__(self, cert_path: Path, key_path: Path):
        self._lock = threading.Lock()
        self._context = self._build_context(cert_path, key_path)
        self._active_paths = (cert_path, key_path)

    def _build_context(self, cert_path: Path, key_path: Path) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(SECURE_CIPHERS)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx

    def context(self) -> ssl.SSLContext:
        with self._lock:
            return self._context

    def rotate(self, cert_path: Path, key_path: Path) -> None:
        new_ctx = self._build_context(cert_path, key_path)
        with self._lock:
            old = self._context
            self._context = new_ctx
            self._active_paths = (cert_path, key_path)
        # The OS will keep old in-flight connections alive against the
        # old context; new accepts use the new context immediately.
        audit_log("tls_rotated", details={"new_serial": _serial_of(cert_path)})

    def check_and_rotate_if_needed(self) -> None:
        cert = _load(self._active_paths[0])
        remaining = (cert.not_valid_after_utc - datetime.now(UTC)).days
        if remaining < cert.validity_days / 3:
            self._renew_via_internal_api()
```

The HTTP server's `socket.accept()` loop calls `tls_manager.context()`
for every new connection and wraps the new socket with it. No need
to restart, no graceful-handoff dance.

Validate: after a rotation, a long-running ACME client polling every
30 seconds sees the new cert on its next poll without observing a
connection error.

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `tls_manager.py`  | New module: context build, rotation, periodic check          |
| `pki_server.py`   | Use `tls_manager` for the admin/API listener, schedule       |
|                   | self-enrollment after `READY=1`, new `pypki_self_tls` profile |
| `bootstrap/tls_setup.py` | Generate the 24h bootstrap cert at init time          |
| `pypki_admin.py`  | `tls-rotate`, `tls-status`, `tls-replace` (for Pattern C)    |
| `test_pypki_init.py` | `TestTLSBootstrap`, `TestTLSRotation`, `TestTLSSelfEnrollment` |
| `README.md`       | TLS section                                                  |
| `CHANGELOG.md`    | `### Added`, `### Security`                                  |
| `docs/TLS.md`     | Three patterns, when to choose each, rotation operations     |

### Listener integration

The HTTP server (current implementation) uses Python's `socketserver`
or similar. Inject `tls_manager` so every accept gets a fresh context:

```python
class HardenedTLSServer(http.server.ThreadingHTTPServer):
    def __init__(self, addr, handler, tls_manager: TLSManager):
        super().__init__(addr, handler, bind_and_activate=False)
        self.tls_manager = tls_manager
        self.server_bind()
        self.server_activate()

    def get_request(self):
        sock, addr = self.socket.accept()
        ctx = self.tls_manager.context()
        ssock = ctx.wrap_socket(sock, server_side=True)
        return ssock, addr
```

In-flight connections keep their bound context (Python's
`SSLSocket` is built off the context at wrap time). New connections
pick up the rotated context.

### Cipher suite policy

Apply the same posture as ACME directives — opinionated, but tunable:

```python
SECURE_CIPHERS = ":".join([
    # TLS 1.3 — preferred, no need to enumerate
    # TLS 1.2 fallback for clients that need it
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
])
# Resulting Qualys SSL Labs grade: A+ on a clean Ubuntu 24.04 box.
```

Disable session tickets unless explicitly enabled — long-lived
session tickets weaken forward secrecy in a single-server deployment.

### Pattern B integration

When `--tls-mode external-frontend`, PyPKI binds plaintext on
`127.0.0.1:8080` and `tls_manager` is a no-op. nginx in front
terminates TLS. The init wizard emits a working nginx config:

```nginx
# /etc/nginx/conf.d/pypki.conf
server {
    listen 443 ssl http2;
    server_name pki.example.com;

    ssl_certificate /etc/letsencrypt/live/pki.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pki.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:...;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
    }
}

server {
    listen 80;
    server_name pki.example.com;
    location /.well-known/acme-challenge/ {
        root /var/www/acme;
    }
    location / { return 301 https://$host$request_uri; }
}
```

When pattern B is selected, PyPKI's listener still must trust the
`X-Forwarded-*` headers — wire that through the request middleware
with an allowlist of trusted proxy IPs.

### Pattern C integration

`--tls-mode external-cert` reads paths from config:

```yaml
tls:
  mode: external-cert
  cert_path: /etc/pypki/tls/external.crt
  key_path: /etc/pypki/tls/external.key
  ca_bundle_path: /etc/pypki/tls/external-ca-bundle.pem
  reload_on_signal: SIGHUP             # operator's cron does the renewal
```

`tls_manager.rotate()` is invoked on SIGHUP. The operator's existing
renewal automation drops new files in place and signals PyPKI.

`pypki_admin.py tls-replace --cert <path> --key <path>` is the
equivalent for operators who'd rather use a CLI than send signals.

---

## CLI flags

```
--tls-mode self-bootstrap|external-frontend|external-cert
--tls-bootstrap-validity-hours 24
--tls-self-profile pypki_self_tls
--tls-self-renewal-fraction 0.333
--tls-self-renewal-jitter-seconds 600
--tls-trusted-proxy-cidrs 127.0.0.1/32,10.0.0.0/8
--tls-min-version 1.2|1.3
```

`pypki_admin.py`:

- `tls-rotate` — force self-enrollment immediately, useful after CA
  changes
- `tls-status` — print current cert chain, expiry, key algorithm,
  rotation history (last 10)
- `tls-replace --cert ... --key ...` — pattern C explicit replace

---

## Tests

```
class TestTLSBootstrap(unittest.TestCase):
    def test_bootstrap_cert_generated_24h(self): ...
    def test_bootstrap_cert_san_matches_configured_hostname(self): ...
    def test_bootstrap_cert_perms_0600(self): ...
    def test_bootstrap_key_zeroized_after_rotation(self): ...

class TestTLSSelfEnrollment(unittest.TestCase):
    def test_self_enrollment_within_30_seconds_of_ready(self): ...
    def test_self_issued_cert_is_pypki_self_tls_profile(self): ...
    def test_failed_self_enrollment_retries_every_60s(self): ...
    def test_failed_after_24h_preflight_fails(self): ...
    def test_bootstrap_warning_logged_prominently(self): ...

class TestTLSRotation(unittest.TestCase):
    def test_new_connection_uses_new_cert_immediately(self): ...
    def test_inflight_connection_keeps_old_cert(self): ...
    def test_rotation_audit_logged(self): ...
    def test_invalid_new_cert_rejected_keeps_old(self): ...
    def test_renewal_at_one_third_lifetime(self): ...

class TestTLSPatternIntegration(unittest.TestCase):
    def test_external_frontend_mode_serves_plaintext_on_loopback(self): ...
    def test_external_frontend_trusts_x_forwarded_headers_from_allowlist(self): ...
    def test_external_cert_mode_loads_provided_files(self): ...
    def test_external_cert_sighup_reloads(self): ...
    def test_tls_replace_command_rotates(self): ...
```

Integration: spin up PyPKI, start a long-lived TLS client, trigger
`tls-rotate`, confirm the client's existing connection survives and
its next request gets the new cert.

---

## Per-change checklist

- [ ] `tls_manager.py` — new module
- [ ] `pki_server.py` — listener integration, self-enrollment, profile
- [ ] `bootstrap/tls_setup.py` — bootstrap cert generation
- [ ] `pypki_admin.py` — `tls-rotate`, `tls-status`, `tls-replace`
- [ ] `test_pypki_init.py` — four test classes
- [ ] `examples/nginx/pypki.conf` — pattern B sample
- [ ] `README.md` — TLS section
- [ ] `CHANGELOG.md` — `### Added`, `### Security`
- [ ] `docs/TLS.md` — three patterns, when to choose each
- [ ] `pypki-flows.html` — bootstrap + rotation flow

Run `./run_tests.sh`. The rotation test against a live long-lived
client is the integration guarantee.

---

## Open questions

1. **OCSP stapling**: serve the admin cert with a stapled OCSP
   response so clients don't make a separate OCSP request. PyPKI
   has its own OCSP responder; stapling its admin cert's OCSP
   response is trivial. Add to `tls_manager` as a fetched-on-rotation
   field.

2. **Certificate Transparency for admin certs**: pattern A certs
   never see CT. Pattern B (LE) certs go to CT automatically. Pattern
   C depends on the upstream CA. Document the implication: PyPKI's
   admin endpoint is *not* publicly logged unless the operator chooses
   pattern B or a CT-logging external CA.

3. **mTLS admin (client-cert auth)**: the `pypki_self_tls` profile
   already permits `client_auth` EKU. A natural extension: PyPKI's
   admin endpoint requires a client cert from the same CA. Closes the
   "stolen session token" problem for high-stakes environments.
   Wire into `auth.py` as a fourth backend.

4. **DANE for the admin endpoint**: TLSA records in DNS pinning the
   admin cert's hash. Pairs well with pattern A (where there's no CT
   to verify against). Out of scope here, but worth a sketch in
   `docs/TLS.md` for the security-paranoid.

5. **PyPKI fronting itself with ACME**: a deployment could use
   pattern B but with PyPKI itself as the ACME server (not LE).
   Recursive but tractable: the admin endpoint's nginx-fronting cert
   comes from PyPKI's own ACME directory. Useful for fully air-gapped
   networks. Document as advanced.
