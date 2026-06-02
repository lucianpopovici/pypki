"""policy.py — Policy-as-code for issuance decisions (CLAUDE-policy-engine.md).

Policy files use JSON format (no external parser dependency). Example:

    {
      "version": 1,
      "default": "deny",
      "rules": [
        {
          "name": "tls-server-internal",
          "match": {
            "profile": "tls_server",
            "requester": {"backend": "oidc", "roles": ["pki:operator"]},
            "sans": {"all_match_regex": "\\.internal\\.example\\.com$"}
          },
          "decide": "allow",
          "sets": {"validity_days_max": 90}
        }
      ]
    }

An absent or empty --policy-file means legacy CertProfile-only behavior (implicit allow).

Thread-safety: Policy is a frozen dataclass. PolicyEngine swaps the active
policy reference under a threading.RLock — readers always see a consistent object.

Public API
----------
  IssuanceRequest   — frozen dataclass describing a single issuance request
  Decision          — frozen dataclass with the engine's verdict + sets overrides
  PolicyEngine      — thread-safe loader/evaluator with hot-reload
  load_policy(path) — load + validate a JSON policy file
  evaluate(req, policy) — pure evaluation (no I/O); testable without a DB
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import logging
import re
import threading
import time
from typing import Any, Optional

logger = logging.getLogger("pypki.policy")

_VALID_DECISIONS = frozenset({"allow", "deny", "require_ra", "require_dual_control"})
_VALID_MATCH_KEYS = frozenset({"profile", "profile_in", "requester", "sans", "key", "validity", "time", "codesign"})
_VALID_REQUESTER_KEYS = frozenset({"backend", "roles", "identity_regex"})
_VALID_SANS_KEYS = frozenset({"all_match_regex", "any_match_regex", "none_match_regex", "count_max"})
_VALID_KEY_KEYS = frozenset({"type_in", "size_min"})
_VALID_VALIDITY_KEYS = frozenset({"requested_days_max"})
_VALID_TIME_KEYS = frozenset({"day_of_week_in", "hour_range"})
_VALID_SETS_KEYS = frozenset({"validity_days_max", "hsm_required", "ct_submission_required", "ra_approval_required"})
_VALID_TOP_KEYS = frozenset({"version", "default", "rules"})
_DAY_NAMES = frozenset({"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"})

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class IssuanceRequest:
    """Immutable snapshot of a single certificate issuance request.

    Build one in each protocol handler before calling issue_certificate()
    and pass it as policy_req=... to trigger policy evaluation.
    """
    profile: str
    requester_backend: str           # pam | oidc | acme | scep | est | cmp
    requester_roles: tuple[str, ...] = ()
    requester_identity: str = ""     # username, account KID, DN, etc.
    sans: tuple[str, ...] = ()       # SAN values as plain strings
    key_type: str = ""               # ecdsa-p256, rsa-2048, ml-dsa-44, …
    key_bits: int = 0                # RSA modulus bits; 0 for non-RSA
    validity_days_requested: int = 0
    request_id: str = ""
    now: Optional[datetime.datetime] = None  # fixed clock for time predicates; None → real UTC
    codesign_meta: dict = dataclasses.field(default_factory=dict)  # codesign.* predicates


@dataclasses.dataclass(frozen=True)
class Decision:
    """The policy engine's verdict for one issuance request."""
    action: str                      # allow | deny | require_ra | require_dual_control
    rule_name: Optional[str]         # None when the default matched
    policy_hash: str
    sets: dict[str, Any] = dataclasses.field(default_factory=dict)
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    @property
    def denied(self) -> bool:
        return self.action == "deny"


@dataclasses.dataclass(frozen=True)
class _Rule:
    name: str
    match: dict[str, Any]
    decide: str
    sets: dict[str, Any]
    requires: dict[str, Any]
    reason: str
    # Pre-compiled regexes extracted from match at load time
    _compiled: dict[str, re.Pattern] = dataclasses.field(
        default_factory=dict, compare=False, hash=False
    )


@dataclasses.dataclass(frozen=True)
class Policy:
    """Immutable loaded policy."""
    content_hash: str
    default: str
    rules: tuple[_Rule, ...]
    loaded_at: float
    content: str   # raw JSON for storage in policy_versions


# ---------------------------------------------------------------------------
# Loader and validator
# ---------------------------------------------------------------------------

def load_policy(path: str) -> Policy:
    """Load, parse, and validate a JSON policy file. Raises ValueError on error."""
    with open(path, "rb") as f:
        raw = f.read()
    content_hash = hashlib.sha256(raw).hexdigest()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Policy file is not valid JSON: {exc}") from exc
    _validate_schema(doc)
    rules = tuple(_rule_from_dict(r) for r in doc.get("rules", []))
    return Policy(
        content_hash=content_hash,
        default=doc.get("default", "deny"),
        rules=rules,
        loaded_at=time.time(),
        content=raw.decode(),
    )


def _validate_schema(doc: dict) -> None:
    if not isinstance(doc, dict):
        raise ValueError("Policy root must be a JSON object")
    unknown = set(doc.keys()) - _VALID_TOP_KEYS
    if unknown:
        raise ValueError(f"Unknown top-level keys: {sorted(unknown)}")
    if doc.get("version", 1) != 1:
        raise ValueError(f"Unsupported policy version: {doc['version']}")
    default = doc.get("default", "deny")
    if default not in _VALID_DECISIONS:
        raise ValueError(f"Invalid default decision {default!r}; valid: {sorted(_VALID_DECISIONS)}")
    rules = doc.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("'rules' must be a list")
    names_seen: set[str] = set()
    for i, rule in enumerate(rules):
        _validate_rule(rule, i, names_seen)


def _validate_rule(rule: dict, idx: int, names_seen: set[str]) -> None:
    if not isinstance(rule, dict):
        raise ValueError(f"Rule [{idx}] must be an object")
    name = rule.get("name")
    if not name or not isinstance(name, str):
        raise ValueError(f"Rule [{idx}] missing 'name'")
    if name in names_seen:
        raise ValueError(f"Duplicate rule name: {name!r}")
    names_seen.add(name)
    decide = rule.get("decide")
    if decide not in _VALID_DECISIONS:
        raise ValueError(f"Rule {name!r}: unknown decide {decide!r}; valid: {sorted(_VALID_DECISIONS)}")
    match = rule.get("match", {})
    if not isinstance(match, dict):
        raise ValueError(f"Rule {name!r}: 'match' must be an object")
    _validate_match(match, name)
    sets = rule.get("sets", {})
    if not isinstance(sets, dict):
        raise ValueError(f"Rule {name!r}: 'sets' must be an object")
    unknown = set(sets.keys()) - _VALID_SETS_KEYS
    if unknown:
        raise ValueError(f"Rule {name!r}: unknown 'sets' keys: {sorted(unknown)}")


def _validate_match(match: dict, rule_name: str) -> None:
    unknown = set(match.keys()) - _VALID_MATCH_KEYS
    if unknown:
        raise ValueError(f"Rule {rule_name!r}: unknown match predicates: {sorted(unknown)}")
    if "requester" in match:
        req = match["requester"]
        if not isinstance(req, dict):
            raise ValueError(f"Rule {rule_name!r}: match.requester must be an object")
        unknown = set(req.keys()) - _VALID_REQUESTER_KEYS
        if unknown:
            raise ValueError(f"Rule {rule_name!r}: unknown match.requester keys: {sorted(unknown)}")
        if "identity_regex" in req:
            _compile_re(req["identity_regex"], rule_name, "match.requester.identity_regex")
    if "sans" in match:
        sans = match["sans"]
        if not isinstance(sans, dict):
            raise ValueError(f"Rule {rule_name!r}: match.sans must be an object")
        unknown = set(sans.keys()) - _VALID_SANS_KEYS
        if unknown:
            raise ValueError(f"Rule {rule_name!r}: unknown match.sans keys: {sorted(unknown)}")
        for k in ("all_match_regex", "any_match_regex", "none_match_regex"):
            if k in sans:
                _compile_re(sans[k], rule_name, f"match.sans.{k}")
    if "key" in match:
        key = match["key"]
        if not isinstance(key, dict):
            raise ValueError(f"Rule {rule_name!r}: match.key must be an object")
        unknown = set(key.keys()) - _VALID_KEY_KEYS
        if unknown:
            raise ValueError(f"Rule {rule_name!r}: unknown match.key keys: {sorted(unknown)}")
    if "validity" in match:
        val = match["validity"]
        if not isinstance(val, dict):
            raise ValueError(f"Rule {rule_name!r}: match.validity must be an object")
        unknown = set(val.keys()) - _VALID_VALIDITY_KEYS
        if unknown:
            raise ValueError(f"Rule {rule_name!r}: unknown match.validity keys: {sorted(unknown)}")
    if "time" in match:
        t = match["time"]
        if not isinstance(t, dict):
            raise ValueError(f"Rule {rule_name!r}: match.time must be an object")
        unknown = set(t.keys()) - _VALID_TIME_KEYS
        if unknown:
            raise ValueError(f"Rule {rule_name!r}: unknown match.time keys: {sorted(unknown)}")
        if "day_of_week_in" in t:
            bad = [d for d in t["day_of_week_in"] if d.lower() not in _DAY_NAMES]
            if bad:
                raise ValueError(f"Rule {rule_name!r}: unknown day names: {bad}")
        if "hour_range" in t:
            hr = t["hour_range"]
            if not (isinstance(hr, list) and len(hr) == 2):
                raise ValueError(f"Rule {rule_name!r}: match.time.hour_range must be [start, end]")


def _compile_re(pattern: str, rule_name: str, field: str) -> re.Pattern:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Rule {rule_name!r}: invalid regex in {field}: {exc}") from exc


def _rule_from_dict(d: dict) -> _Rule:
    """Build a _Rule from a validated dict, pre-compiling all regexes."""
    match = d.get("match", {})
    compiled: dict[str, re.Pattern] = {}
    sans = match.get("sans", {})
    for k in ("all_match_regex", "any_match_regex", "none_match_regex"):
        if k in sans:
            compiled[f"sans.{k}"] = re.compile(sans[k])
    req = match.get("requester", {})
    if "identity_regex" in req:
        compiled["requester.identity_regex"] = re.compile(req["identity_regex"])
    return _Rule(
        name=d["name"],
        match=match,
        decide=d["decide"],
        sets=d.get("sets", {}),
        requires=d.get("requires", {}),
        reason=d.get("reason", ""),
        _compiled=compiled,
    )


# ---------------------------------------------------------------------------
# Pure evaluator
# ---------------------------------------------------------------------------

def evaluate(req: IssuanceRequest, policy: Policy) -> Decision:
    """Evaluate req against policy. Pure: no I/O, no side effects."""
    for rule in policy.rules:
        if _matches(rule.match, rule._compiled, req):
            return Decision(
                action=rule.decide,
                rule_name=rule.name,
                policy_hash=policy.content_hash,
                sets=dict(rule.sets),
                reason=rule.reason,
            )
    return Decision(
        action=policy.default,
        rule_name=None,
        policy_hash=policy.content_hash,
        sets={},
        reason="default",
    )


def _matches(match: dict, compiled: dict[str, re.Pattern], req: IssuanceRequest) -> bool:
    for key, val in match.items():
        if key == "profile":
            if req.profile != val:
                return False
        elif key == "profile_in":
            if req.profile not in val:
                return False
        elif key == "requester":
            if not _match_requester(val, compiled, req):
                return False
        elif key == "sans":
            if not _match_sans(val, compiled, req.sans):
                return False
        elif key == "key":
            if not _match_key(val, req):
                return False
        elif key == "validity":
            if "requested_days_max" in val and req.validity_days_requested > val["requested_days_max"]:
                return False
        elif key == "time":
            now = req.now or datetime.datetime.now(datetime.timezone.utc)
            if not _match_time(val, now):
                return False
        elif key == "codesign":
            if not _match_codesign(val, req):
                return False
    return True


def _match_codesign(pred: dict, req: IssuanceRequest) -> bool:
    """Match codesign.* predicates against req.codesign_meta."""
    meta = req.codesign_meta or {}
    for field, expected in pred.items():
        actual = meta.get(field, "")
        if isinstance(expected, str):
            # Treat as regex pattern
            if not re.search(expected, str(actual)):
                return False
        elif actual != expected:
            return False
    return True


def _match_requester(pred: dict, compiled: dict, req: IssuanceRequest) -> bool:
    if "backend" in pred and req.requester_backend != pred["backend"]:
        return False
    if "roles" in pred:
        if not any(r in req.requester_roles for r in pred["roles"]):
            return False
    if "identity_regex" in pred:
        pat = compiled.get("requester.identity_regex") or re.compile(pred["identity_regex"])
        if not pat.search(req.requester_identity):
            return False
    return True


def _match_sans(pred: dict, compiled: dict, sans: tuple[str, ...]) -> bool:
    if "count_max" in pred and len(sans) > pred["count_max"]:
        return False
    if "all_match_regex" in pred:
        pat = compiled.get("sans.all_match_regex") or re.compile(pred["all_match_regex"])
        if not sans or not all(pat.search(s) for s in sans):
            return False
    if "any_match_regex" in pred:
        pat = compiled.get("sans.any_match_regex") or re.compile(pred["any_match_regex"])
        if not any(pat.search(s) for s in sans):
            return False
    if "none_match_regex" in pred:
        pat = compiled.get("sans.none_match_regex") or re.compile(pred["none_match_regex"])
        if any(pat.search(s) for s in sans):
            return False
    return True


def _match_key(pred: dict, req: IssuanceRequest) -> bool:
    if "type_in" in pred and req.key_type not in pred["type_in"]:
        return False
    if "size_min" in pred and req.key_bits < pred["size_min"]:
        return False
    return True


def _match_time(pred: dict, now: datetime.datetime) -> bool:
    if "day_of_week_in" in pred:
        day = now.strftime("%A").lower()
        if day not in [d.lower() for d in pred["day_of_week_in"]]:
            return False
    if "hour_range" in pred:
        start, end = pred["hour_range"]
        if not (start <= now.hour < end):
            return False
    return True


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _store_policy_version(db, policy: Policy, loaded_by: str = "system") -> None:
    try:
        db.execute(
            "INSERT OR IGNORE INTO policy_versions(content_hash, content, loaded_at, loaded_by) "
            "VALUES (?, ?, ?, ?)",
            (policy.content_hash, policy.content, int(policy.loaded_at), loaded_by),
        )
    except Exception as exc:
        logger.warning("Failed to store policy version: %s", exc)


def _record_decision(db, req: IssuanceRequest, decision: Decision) -> None:
    sans_summary = ", ".join(req.sans[:5])
    if len(req.sans) > 5:
        sans_summary += f" (+{len(req.sans) - 5} more)"
    try:
        db.execute(
            "INSERT INTO policy_decisions"
            "(request_id, policy_hash, rule_name, decision, decided_at, requester, profile, sans_summary)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                req.request_id, decision.policy_hash, decision.rule_name,
                decision.action, int(time.time()),
                f"{req.requester_backend}:{req.requester_identity}",
                req.profile, sans_summary,
            ),
        )
    except Exception as exc:
        logger.warning("Failed to record policy decision: %s", exc)


# ---------------------------------------------------------------------------
# PolicyEngine — thread-safe, hot-reloadable
# ---------------------------------------------------------------------------

class PolicyEngine:
    """Thread-safe container for the active Policy with SIGHUP hot-reload.

    mode:
      "enforce" — deny/require_ra decisions block issuance (default)
      "warn"    — log what would be blocked but always allow (migration path)
      "off"     — skip evaluation entirely (same as no policy file)
    """

    def __init__(
        self,
        policy_file: Optional[str] = None,
        mode: str = "enforce",
        db=None,
        audit=None,
        loaded_by: str = "system",
    ) -> None:
        self._lock = threading.RLock()
        self._policy: Optional[Policy] = None
        self._policy_file = policy_file
        self._mode = mode
        self._db = db
        self._audit = audit
        self._loaded_by = loaded_by

        if policy_file:
            self.load_from_file(policy_file)

    def load_from_file(self, path: str) -> None:
        """Load a policy file and swap atomically. Raises ValueError on parse/schema error."""
        policy = load_policy(path)
        with self._lock:
            self._policy = policy
            self._policy_file = path
        if self._db:
            _store_policy_version(self._db, policy, self._loaded_by)
        logger.info(
            "Policy loaded: %s (hash=%s…, %d rules, default=%s)",
            path, policy.content_hash[:12], len(policy.rules), policy.default,
        )

    def reload(self) -> bool:
        """Reload from the current policy file. Returns True on success, False on error."""
        with self._lock:
            path = self._policy_file
        if not path:
            return False
        try:
            self.load_from_file(path)
            if self._audit:
                self._audit.record("policy_reloaded", f"path={path}")
            return True
        except Exception as exc:
            logger.error("Policy reload failed (keeping previous policy): %s", exc)
            if self._audit:
                self._audit.record("policy_reload_failed", str(exc))
            return False

    @property
    def active(self) -> Optional[Policy]:
        with self._lock:
            return self._policy

    @property
    def mode(self) -> str:
        return self._mode

    def evaluate(self, req: IssuanceRequest) -> Decision:
        """Evaluate a request. In warn mode, always returns allow but logs the decision."""
        with self._lock:
            pol = self._policy
            mode = self._mode

        if pol is None or mode == "off":
            return Decision(action="allow", rule_name=None, policy_hash="", sets={})

        decision = evaluate(req, pol)

        if self._db:
            _record_decision(self._db, req, decision)

        if mode == "warn" and decision.action != "allow":
            logger.warning(
                "POLICY [warn-mode] would %s: profile=%s requester=%s:%s sans=%s rule=%s",
                decision.action, req.profile,
                req.requester_backend, req.requester_identity,
                list(req.sans)[:3], decision.rule_name,
            )
            return Decision(
                action="allow",
                rule_name=decision.rule_name,
                policy_hash=decision.policy_hash,
                sets=decision.sets,
                reason=decision.reason,
            )

        return decision

    def status(self) -> dict:
        with self._lock:
            pol = self._policy
        return {
            "mode": self._mode,
            "policy_file": self._policy_file,
            "loaded": pol is not None,
            "content_hash": pol.content_hash if pol else None,
            "loaded_at": pol.loaded_at if pol else None,
            "rule_count": len(pol.rules) if pol else 0,
            "default": pol.default if pol else None,
        }
