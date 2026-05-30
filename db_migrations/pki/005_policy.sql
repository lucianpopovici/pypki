-- Policy engine decisions and version log (CLAUDE-policy-engine.md)
-- policy_decisions: one row per evaluated request; joins to audit via request_id
-- policy_versions: one row per unique policy file content; retains the full
--   YAML/JSON so auditors can answer "what was the policy on date X?"

CREATE TABLE IF NOT EXISTS policy_decisions (
    id              {{auto_pk}},
    request_id      TEXT NOT NULL,
    policy_hash     TEXT NOT NULL,
    rule_name       TEXT,
    decision        TEXT NOT NULL,
    decided_at      INTEGER NOT NULL,
    requester       TEXT,
    profile         TEXT,
    sans_summary    TEXT
);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_hash ON policy_decisions(policy_hash);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_time ON policy_decisions(decided_at);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_req  ON policy_decisions(request_id);

CREATE TABLE IF NOT EXISTS policy_versions (
    content_hash    TEXT PRIMARY KEY,
    content         TEXT NOT NULL,
    loaded_at       INTEGER NOT NULL,
    loaded_by       TEXT NOT NULL
);
