# CLAUDE-ari.md — ACME Renewal Information (RFC 9773)

Companion to `CLAUDE.md`. Follow all conventions in that file (no new pip
deps, stdlib + `cryptography`, `datetime.now(timezone.utc)`, audit-log every
state change, rate-limit new endpoints, write SQL with `?` placeholders, etc.).

---

## What ARI is

RFC 9773 (June 2025) adds a `renewalInfo` resource to ACME so the server can
hand clients a `suggestedWindow` (`start` + `end`, RFC 3339) and a
`Retry-After` polling interval. Two motivations:

1. **Load smoothing**: spread renewals so the CA doesn't see a thundering
   herd at `notAfter - 30d`.
2. **Mass-revocation coordination**: when the CA must revoke a population
   of certs on a deadline, it sets `suggestedWindow.end` to the past for
   affected certs and clients renew on next poll. Used in production by
   Let's Encrypt's Sep 2024 incident (133,613 certs).

ARI also extends `newOrder` with an optional `replaces` field. When the CA
issues against a `replaces`, it MUST revoke the predecessor (reason
`superseded`, RFC 5280 §5.3.1 code 4) and SHOULD exempt the request from
account rate limits.

---

## Wire surface

### Directory metadata

`GET /acme/directory` adds:

```
"renewalInfo": "https://pki.example/acme/renewal-info"
```

### Resource

```
GET /acme/renewal-info/{certId}
```

`certId` is `base64url(AKI keyIdentifier) "." base64url(serial bytes)` —
RFC 9773 §4.1. Both segments are unpadded base64url. The serial is the
DER INTEGER content octets (no leading sign byte unless RFC 5280 §4.1.2.2
requires it).

Response (200 OK):

```json
{
  "suggestedWindow": {
    "start": "2026-06-01T00:00:00Z",
    "end":   "2026-06-03T00:00:00Z"
  },
  "explanationURL": "https://pki.example/cps#renewal"
}
```

Headers: `Retry-After: <seconds>` and `Cache-Control: public, max-age=<seconds>`.
Match the two values; Let's Encrypt uses 21600 (6h) in steady state and drops
it during incidents.

404 on unknown `certId`. No auth required (RFC 9773 §4.2 — leaks no more than
CT logs already do).

### newOrder extension

`POST /acme/new-order` payload accepts:

```json
{
  "identifiers": [...],
  "replaces": "base64url(AKI).base64url(serial)"
}
```

Validation: the replaced cert MUST be issued by this CA, MUST belong to the
requesting account, MUST NOT already have been replaced by a different order
(idempotent retry is fine — same account, same identifiers).

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `acme_server.py`  | New `_handle_renewal_info()`, extend `_handle_new_order()`   |
| `pki_server.py`   | Revocation hook: on issue-with-replaces, revoke predecessor  |
| `db_migrations/acme/00X_ari.sql` | New schema (see below)                        |
| `test_pki_server.py` | `TestRFC9773ARI`, `TestRFC9773Replaces`                   |
| `README.md`       | Protocol compliance row, CLI flag docs                       |
| `CHANGELOG.md`    | `### Added`                                                  |
| `pypki-flows.html` | New ARI flow diagram                                        |

### Window calculation

Default: `start = notAfter - lifetime/3`, `end = start + lifetime/24`,
clamped to `[now, notAfter]`. Per-cert jitter via stable hash of serial
so a given cert always gets the same window across polls (clients cache).

```python
def suggested_window(cert: x509.Certificate) -> tuple[datetime, datetime]:
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    lifetime = na - nb
    jitter_seed = int.from_bytes(hashlib.sha256(cert.serial_number
                  .to_bytes(20, "big", signed=False)).digest()[:4], "big")
    jitter = timedelta(seconds=jitter_seed % int(lifetime.total_seconds() / 48))
    start = na - lifetime / 3 + jitter
    end   = start + lifetime / 24
    return max(start, datetime.now(timezone.utc)), min(end, na)
```

Override path: `acme_renewal_overrides` table (below) takes precedence and
is what mass-revocation tooling writes to.

### Schema

```sql
-- db_migrations/acme/00X_ari.sql
CREATE TABLE acme_renewal_overrides (
    cert_id      TEXT PRIMARY KEY,          -- base64url(AKI).base64url(serial)
    window_start TEXT NOT NULL,             -- ISO-8601
    window_end   TEXT NOT NULL,             -- ISO-8601
    retry_after  INTEGER NOT NULL DEFAULT 21600,
    explanation  TEXT,
    set_at       INTEGER NOT NULL,          -- unix seconds
    set_by       TEXT NOT NULL              -- admin user or "system"
);

CREATE TABLE acme_replacements (
    new_serial   TEXT NOT NULL,
    old_serial   TEXT NOT NULL,
    account_id   TEXT NOT NULL,
    replaced_at  INTEGER NOT NULL,
    PRIMARY KEY (new_serial),
    UNIQUE (old_serial)                     -- prevents double-replacement
);
CREATE INDEX idx_acme_repl_old ON acme_replacements(old_serial);
```

`acme_replacements.old_serial UNIQUE` is the lock that stops a client
chaining two newOrders to revoke the same predecessor twice. The DAL
upsert pattern is `INSERT ... ON CONFLICT (old_serial) DO NOTHING` and
the handler rejects with `alreadyReplaced` if no row inserted.

### Issuance flow with `replaces`

1. Validate authorizations as normal.
2. Lookup `replaces` cert via DAL; assert same account, same CA, not yet
   in `acme_replacements`.
3. Inside `advisory_lock("serial-allocation")`: allocate new serial, issue
   cert, insert into `certificates`, insert into `acme_replacements`,
   call `revoke()` on the predecessor with reason `superseded`.
4. Audit-log `cert_replaced` with both serials and `account_id`.
5. Fire lifecycle webhook `cert.replaced` via `hooks.py`.

The whole sequence is one DAL transaction. If the webhook fails the issue
still commits — webhooks are best-effort, see `hooks.py`.

### Rate-limit exemption

The existing token-bucket limiter in `acme_server.py` checks an exemption
predicate. Add: `request.has_replaces and replaces_valid_and_owned` →
skip bucket consumption. RFC 9773 §5 — exemption is SHOULD, not MUST,
but it's what every deployed CA does.

---

## CLI flags

```
--acme-ari-enabled                  # default: true once shipped
--acme-ari-default-retry-after 21600
--acme-ari-window-fraction 0.333    # start at notAfter - lifetime * this
--acme-ari-window-width-fraction 0.042  # window length as fraction of lifetime
```

Operator override is via `pypki_admin.py ari-set-window <cert-id>
--start <iso> --end <iso> [--retry-after <s>] [--explanation <url>]`,
plus `ari-bulk-shorten --filter <sql>` for incident response.

---

## Tests

```
class TestRFC9773ARI(unittest.TestCase):
    def test_directory_advertises_renewal_info(self): ...
    def test_certid_round_trip(self): ...
    def test_window_within_validity_period(self): ...
    def test_window_stable_for_same_serial(self): ...
    def test_unknown_certid_returns_404(self): ...
    def test_retry_after_header_present(self): ...
    def test_admin_override_takes_precedence(self): ...
    def test_bulk_shorten_sets_window_in_past(self): ...

class TestRFC9773Replaces(unittest.TestCase):
    def test_neworder_with_replaces_revokes_predecessor(self): ...
    def test_replaces_must_be_same_account(self): ...
    def test_replaces_must_be_same_ca(self): ...
    def test_replaced_cert_cannot_be_replaced_again(self): ...
    def test_replaces_exempts_rate_limit(self): ...
    def test_revocation_reason_is_superseded(self): ...
    def test_replacement_audit_log_contains_both_serials(self): ...
    def test_webhook_fires_on_replacement(self): ...
```

Interop: certbot ≥4.1, lego ≥4.18, simple-acme, win-acme all speak ARI.
Add a `tests/interop/test_ari_certbot.sh` smoke test that runs certbot
against a local PyPKI in a container.

---

## Per-change checklist

- [ ] `acme_server.py` — `_handle_renewal_info`, `_handle_new_order` extension, directory metadata
- [ ] `pki_server.py` — predecessor-revocation hook on `replaces`
- [ ] `db_migrations/acme/00X_ari.sql` — two new tables
- [ ] `pypki_admin.py` — `ari-set-window`, `ari-bulk-shorten`
- [ ] `hooks.py` — new `cert.replaced` event
- [ ] `test_pki_server.py` — `TestRFC9773ARI`, `TestRFC9773Replaces`
- [ ] `README.md` — Protocol compliance row, CLI flag docs, incident-response runbook section
- [ ] `CHANGELOG.md` — `### Added` entry under `## [Unreleased]`
- [ ] `pypki-flows.html` — ARI poll + replaces flow diagram
- [ ] `docs/INCIDENT_RESPONSE.md` — new doc covering bulk-shorten workflow

Run `./run_tests.sh` before presenting.

---

## Open questions

1. **`certId` for cross-signed certs**: a cert can have multiple valid AKIs.
   RFC 9773 §4.1 says use the AKI from the cert as issued. If we ship
   cross-signing variants of the same key, store both `certId` values
   and accept either at lookup. Add an index on `acme_replacements.old_serial`
   only — `certId` lookup goes via `certificates` table joined on serial.

2. **PostgreSQL vs SQLite override semantics**: `acme_renewal_overrides`
   writes during an incident may collide with normal window computation
   in caches. Mitigate: bump `Cache-Control: max-age` floor to a small
   value (e.g. 60s) so caches don't pin stale windows past an incident
   announcement.

3. **Metrics**: add Prometheus counters `acme_ari_polls_total{outcome}`
   and `acme_replacements_total`, plus histogram
   `acme_ari_window_remaining_seconds` so dashboards can flag clients
   that aren't honoring windows.
