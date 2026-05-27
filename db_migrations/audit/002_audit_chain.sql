-- ---------------------------------------------------------------------------
-- audit/002_audit_chain.sql — Hash-chained tamper-evident audit log
--
-- Adds two columns so each row commits to the previous row's hash.
-- Existing rows are backfilled by audit_chain.backfill_chain() at next
-- startup (pure Python — non-trivial to express in portable SQL).
--
-- This migration is online-safe on both backends:
--   SQLite  — ALTER TABLE ADD COLUMN takes a table lock but the table is
--             rarely written during server startup.
--   Postgres — ALTER TABLE ADD COLUMN with no default/constraint is
--             metadata-only and does not rewrite the table.
-- ---------------------------------------------------------------------------

ALTER TABLE audit ADD COLUMN prev_hash TEXT;
ALTER TABLE audit ADD COLUMN this_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_this_hash ON audit(this_hash);
