-- Warden Phase 5 clearing schema additions
--
-- Fresh init: this file runs automatically alongside 001_initial_schema.sql
-- because postgres docker-entrypoint-initdb.d processes *.sql files in
-- lexicographic order on first container init.
--
-- Existing volume: the migrations dir is mounted read-only; Postgres does NOT
-- re-run initdb scripts on subsequent starts. To apply to an existing volume:
--   docker compose down -v  (destroys data) then docker compose up -d postgres
-- For a production upgrade path apply each ALTER/CREATE manually.

-- Deduplicate spool entries by breach_id at the outbox level
CREATE UNIQUE INDEX attestation_outbox_breach_id_unique
    ON attestation_outbox ((event_json->>'breach_id'));

ALTER TABLE slash_event ADD COLUMN breach_id TEXT;
ALTER TABLE slash_event ADD COLUMN agent_id TEXT;
ALTER TABLE slash_event ADD COLUMN reputation_penalty INT NOT NULL DEFAULT 10;
CREATE INDEX slash_event_breach_id_idx ON slash_event (breach_id);

ALTER TABLE agent_identity ADD COLUMN reputation_score INT NOT NULL DEFAULT 100;
