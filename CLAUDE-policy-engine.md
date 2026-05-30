# CLAUDE-policy-engine.md — Policy-as-Code for Issuance Decisions

Companion to `CLAUDE.md`. Follow all conventions there. Formalizes the
issuance decision layer that currently lives scattered across
`CertProfile`, sub-CA name constraints, ACME EAB allowlists, and ad-hoc
webhook hooks. Produces a declarative, auditable, hot-reloadable policy
file evaluated per request.

---

## What this is

Today, "can this request be issued?" gets answered by several layers:

1. Authentication (PAM/OIDC).
2. Account-level rate limits.
3. `CertProfile` validation (allowed key types, EKUs).
4. Sub-CA `NameConstraints` enforcement.
5. Ad-hoc Python in `_handle_finalize`, `_handle_simpleenroll`, etc.

The first four are good. The fifth is where the audit story falls apart:
"Why did this cert get issued with this SAN?" gets answered with "go
read the code." A policy engine pulls (5) out into a single declarative
file that's diffable, reviewable, and recorded in the audit log
alongside the decision.

Goals:

- Pure stdlib evaluation. No Rego (heavy), no CEL, no Python eval of
  arbitrary code.
- Hot-reloadable: edit the file, send `SIGHUP`, take effect on next
  request.
- Every issuance audit log entry references the policy file's content
  hash and the rule that matched.
- Backwards-compatible: an empty policy file means "use legacy
  CertProfile-only behavior."

---

## Policy language

YAML rules. No control flow, no functions — just match/decide. The
absence of expressiveness is the feature: a reviewer can read the
whole file top to bottom.

```yaml
# /etc/pypki/policy.yaml
version: 1

# Default decision when no rule matches.
default: deny

rules:
  - name: "tls-server-internal"
    match:
      profile: tls_server
      requester:
        backend: oidc
        roles: [pki:operator, pki:admin]
      sans:
        all_match_regex: '\.internal\.example\.com$'
    decide: allow
    sets:
      validity_days_max: 90

  - name: "tls-server-public"
    match:
      profile: tls_server
      requester:
        backend: oidc
        roles: [pki:admin]
      sans:
        any_match_regex: '\.example\.com$'
        none_match_regex: '\.internal\.example\.com$'
    decide: allow
    requires:
      ct_log_submission: true
      ra_approval: true
    sets:
      validity_days_max: 397

  - name: "code-signing-restricted"
    match:
      profile: code_signing
    decide: require_ra
    sets:
      validity_days_max: 1095
      hsm_required: true

  - name: "deny-wildcard-tls-from-acme"
    match:
      profile: tls_server
      requester:
        backend: acme
      sans:
        any_match_regex: '^\*\.'
    decide: deny
    reason: "Wildcards via ACME require admin issuance"
```

### Match predicates

| Predicate                           | Meaning                                |
| ----------------------------------- | -------------------------------------- |
| `profile: <name>`                   | CertProfile name equals               |
| `profile_in: [<a>, <b>]`            | CertProfile in set                    |
| `requester.backend: <name>`         | Auth backend (`pam`, `oidc`, `acme`, `scep`, `est`, `cmp`) |
| `requester.roles: [<a>, <b>]`       | Session has any of these roles        |
| `requester.identity_regex: <re>`    | Identity matches regex                |
| `sans.all_match_regex: <re>`        | Every SAN matches                     |
| `sans.any_match_regex: <re>`        | At least one SAN matches              |
| `sans.none_match_regex: <re>`       | No SAN matches                        |
| `sans.count_max: N`                 | At most N SANs                        |
| `key.type_in: [...]`                | Key type in set                       |
| `key.size_min: N`                   | RSA modulus or curve bits             |
| `validity.requested_days_max: N`    | Requested validity bound              |
| `time.day_of_week_in: [...]`        | For maintenance windows               |
| `time.hour_range: [start, end]`     | UTC hour range                        |

Multiple predicates within `match` are AND-ed. The first matching rule
wins; no later rule overrides.

### Decisions

| Decision         | Meaning                                                |
| ---------------- | ------------------------------------------------------ |
| `allow`          | Issue                                                  |
| `deny`           | Reject                                                 |
| `require_ra`     | Park in RA workflow                                    |
| `require_dual_control` | Need a second admin approval                     |

`sets` clauses tighten the issuance (cap validity, force HSM, require
CT submission). They never relax — operator can't `set` a longer
validity than the profile allows; that's a config error caught at
load time.

### Evaluation order

```
request -> [authn] -> [rate limit] -> [profile validation]
        -> [policy.evaluate(request)]
        -> [sub-CA constraints]
        -> [issue]
```

The policy engine runs *after* profile validation: profile says "the
shape is valid"; policy says "this requester is allowed to ask for
this shape." Sub-CA constraints still apply afterward as a final
safety net.

---

## Implementation

### Files touched

| File                | Change                                                |
| ------------------- | ----------------------------------------------------- |
| `policy.py`         | New module: loader, validator, evaluator              |
| `pki_server.py`     | Call `policy.evaluate(...)` in every issuance path    |
| `acme_server.py`    | Pass request context into evaluator                   |
| `est_server.py`, `cmp_server.py`, `scep_server.py` | Same |
| `db_migrations/pki/00X_policy.sql` | Decision audit table                   |
| `test_pki_server.py` | `TestPolicyLoader`, `TestPolicyEvaluation`, `TestPolicyAudit` |
| `pypki_admin.py`    | `policy-validate`, `policy-test`, `policy-show`       |
| `README.md`         | New section + policy authoring guide                  |
| `CHANGELOG.md`      | `### Added`                                           |

### Loader and validator

```python
def load_policy(path: str) -> Policy:
    with open(path, "rb") as f:
        raw = f.read()
    content_hash = hashlib.sha256(raw).hexdigest()
    doc = yaml.safe_load(raw)            # yaml is stdlib via PyYAML — already a dep? verify
    _validate_schema(doc)
    rules = [Rule.from_dict(r) for r in doc.get("rules", [])]
    return Policy(content_hash=content_hash,
                  default=doc.get("default", "deny"),
                  rules=rules,
                  loaded_at=time.time())

def _validate_schema(doc):
    # Reject unknown top-level keys, unknown predicates, unknown decisions.
    # Reject sets clauses that would relax profile constraints.
    # Reject invalid regexes (compile them at load time).
    # Reject duplicate rule names.
    ...
```

If `PyYAML` isn't already a dep, write a minimal subset parser. YAML
is messy; the loader can restrict to a flat-map / list-of-maps subset
that's easy to parse with stdlib `re`. Document the subset.

### Evaluator

```python
def evaluate(req: IssuanceRequest, policy: Policy) -> Decision:
    for rule in policy.rules:
        if _matches(rule.match, req):
            audit_log("policy_match", policy_hash=policy.content_hash,
                      rule=rule.name, decision=rule.decide)
            return Decision(action=rule.decide, sets=rule.sets, rule=rule.name,
                            policy_hash=policy.content_hash)
    audit_log("policy_default", policy_hash=policy.content_hash,
              decision=policy.default)
    return Decision(action=policy.default, sets={}, rule=None,
                    policy_hash=policy.content_hash)
```

Evaluator is pure — no I/O, no clock reads other than the `time.*`
predicates (which are passed a fixed `now` from the request context).
That makes it deterministically testable and trivially fast (sub-microsecond
for hundreds of rules).

### Hot reload

`SIGHUP` triggers `policy.reload()`. If load fails (syntax error,
schema violation), keep the previous policy active and log an error.
Never serve requests with no policy when policy mode is enabled.

### Schema

```sql
-- db_migrations/pki/00X_policy.sql
CREATE TABLE policy_decisions (
    id              {{auto_pk}},
    request_id      TEXT NOT NULL,        -- correlates to audit_log
    policy_hash     TEXT NOT NULL,        -- sha256 of the policy file
    rule_name       TEXT,                 -- NULL when default matched
    decision        TEXT NOT NULL,        -- allow | deny | require_ra | ...
    decided_at      INTEGER NOT NULL,
    requester       TEXT,
    profile         TEXT,
    sans_summary    TEXT                  -- truncated, for grep-ability
);
CREATE INDEX idx_policy_decisions_hash ON policy_decisions(policy_hash);
CREATE INDEX idx_policy_decisions_time ON policy_decisions(decided_at);

CREATE TABLE policy_versions (
    content_hash    TEXT PRIMARY KEY,
    content         TEXT NOT NULL,        -- the raw YAML
    loaded_at       INTEGER NOT NULL,
    loaded_by       TEXT NOT NULL
);
```

Storing every loaded version means an auditor can answer "what was the
policy on 2026-04-15 at 14:00?" by joining `policy_decisions` →
`policy_versions` on `content_hash`. Pruning policy: keep at least one
year, never delete a version still referenced by an unexpired cert's
decision.

---

## CLI flags

```
--policy-file /etc/pypki/policy.yaml    # if unset, legacy CertProfile-only behavior
--policy-mode enforce|warn|off          # enforce = block, warn = log only
--policy-reload-on-sighup true
```

`warn` mode is the migration path: deploy a policy, log what *would*
have been blocked, fix the rules, then flip to `enforce`. Audit-log
both modes the same way; only the side effect differs.

`pypki_admin.py` subcommands:

- `policy-validate <file>` — schema + regex compile, no side effects
- `policy-test <file> --request <json>` — dry-run a request against the
  policy and print the matching rule + decision
- `policy-show --current` — print loaded policy + hash + load time
- `policy-history` — list all loaded versions

---

## Tests

```
class TestPolicyLoader(unittest.TestCase):
    def test_load_valid_policy(self): ...
    def test_unknown_top_level_key_rejected(self): ...
    def test_unknown_predicate_rejected(self): ...
    def test_unknown_decision_rejected(self): ...
    def test_invalid_regex_rejected_at_load(self): ...
    def test_duplicate_rule_names_rejected(self): ...
    def test_sets_cannot_relax_profile(self): ...
    def test_content_hash_stable_across_loads(self): ...

class TestPolicyEvaluation(unittest.TestCase):
    def test_first_matching_rule_wins(self): ...
    def test_no_match_returns_default(self): ...
    def test_default_deny_blocks_unknown(self): ...
    def test_default_allow_permits_unknown(self): ...
    def test_all_match_regex(self): ...
    def test_any_match_regex(self): ...
    def test_none_match_regex(self): ...
    def test_role_membership(self): ...
    def test_validity_cap_applied(self): ...
    def test_require_ra_routes_to_workflow(self): ...
    def test_time_predicates(self): ...

class TestPolicyAudit(unittest.TestCase):
    def test_decision_recorded_with_policy_hash(self): ...
    def test_default_path_recorded_distinctly(self): ...
    def test_policy_version_persisted_on_load(self): ...
    def test_warn_mode_does_not_block_but_logs(self): ...

class TestPolicyHotReload(unittest.TestCase):
    def test_sighup_reloads_valid_policy(self): ...
    def test_sighup_rejects_invalid_and_keeps_previous(self): ...
    def test_reload_failure_is_audit_logged(self): ...
```

Integration test: spin up PyPKI with a sample policy, fire a series of
issuance requests via ACME and REST, assert the audit log records the
expected rule for each.

---

## Per-change checklist

- [ ] `policy.py` — new module
- [ ] `pki_server.py` — wire `policy.evaluate()` into every issuance
      path, expose `IssuanceRequest` dataclass
- [ ] `acme_server.py`, `est_server.py`, `cmp_server.py`,
      `scep_server.py` — pass request context
- [ ] `db_migrations/pki/00X_policy.sql` — decisions + versions tables
- [ ] `pypki_admin.py` — `policy-validate`, `policy-test`,
      `policy-show`, `policy-history`
- [ ] `test_pki_server.py` — four new test classes
- [ ] `README.md` — policy section, authoring guide with worked examples
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `docs/POLICY.md` — full predicate reference, migration playbook
- [ ] `pypki-flows.html` — issuance with policy evaluation step

Run `./run_tests.sh`.

---

## Open questions

1. **PyYAML dependency**: stdlib has no YAML parser. Three options:
   (a) add PyYAML — violates no-pip-deps but it's near-universal;
   (b) use JSON instead of YAML for the policy file — less ergonomic;
   (c) write a flat-subset YAML parser in stdlib — ~300 LoC, well-scoped.
   Recommend (b) initially: JSON is fine for a config file authored by
   humans who'll also write the policy. Revisit if operator feedback
   says YAML is non-negotiable.

2. **Performance under high load**: rules evaluate in O(rules ×
   predicates). For 100 rules × 10 predicates × 1000 reqs/sec that's
   1M predicate evals/sec — fine. If someone writes a 10k-rule policy,
   add a planner phase that buckets rules by profile to skip
   inapplicable ones. Defer until needed.

3. **Cross-cutting policies**: "deny any issuance to subjects on
   sanctions list X." This wants a lookup against external data, which
   the pure-stdlib evaluator deliberately can't do. Add a webhook
   decision point (`hooks.py: policy.consult`) that fires *before*
   policy evaluation and can short-circuit with a deny. Keep this
   separate from the policy file — webhooks are stateful and slow;
   the policy file is fast and pure.

4. **Multi-CA policies**: when PyPKI runs multiple sub-CAs from one
   process, do they share a policy file or have separate ones? Default
   to one shared file with `match.ca: <name>` predicate; allow
   `--policy-file-ca-<name>` overrides for ops who want per-CA files.

5. **Comparison to CABF policy linting (zlint, x509lint)**: out of
   scope here. Those validate the cert after issuance against
   external rules; this engine governs whether issuance happens. Both
   are valuable; the lint can run as a webhook post-issuance.
