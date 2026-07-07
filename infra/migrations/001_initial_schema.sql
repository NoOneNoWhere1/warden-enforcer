-- Warden initial schema
-- Applied automatically by postgres container on first init via docker-entrypoint-initdb.d

CREATE EXTENSION IF NOT EXISTS vector;

-- ── Attester signing key archive ─────────────────────────────────────────────
-- Shared by enforcer, MCP server, and API.
-- Retired keys are never deleted — breach events remain verifiable after rotation.
CREATE TABLE signing_key (
    key_id      TEXT PRIMARY KEY,
    attester    TEXT NOT NULL,       -- warden-enforcer | warden-mcp | warden-api
    public_key  JSONB NOT NULL,      -- JWK
    created_at  TIMESTAMPTZ DEFAULT now(),
    retired_at  TIMESTAMPTZ          -- NULL = active; non-NULL = retired but verifiable
);
CREATE INDEX ON signing_key (attester, retired_at);

-- ── Transactional outbox for Rekor writes ────────────────────────────────────
-- Written in the same DB transaction as tool execution.
-- Background worker drains to Rekor; partial index keeps scans fast.
CREATE TABLE attestation_outbox (
    id             BIGSERIAL PRIMARY KEY,
    event_json     JSONB NOT NULL,
    attester       TEXT NOT NULL,
    created_at     TIMESTAMPTZ DEFAULT now(),
    submitted_at   TIMESTAMPTZ,         -- NULL = pending; non-NULL = confirmed to Rekor
    rekor_entry_id TEXT
);
CREATE INDEX ON attestation_outbox (submitted_at) WHERE submitted_at IS NULL;

-- ── CVE spine ────────────────────────────────────────────────────────────────
CREATE TABLE vulnerability (
    cve_id         TEXT PRIMARY KEY,
    state          TEXT NOT NULL,
    assigner_cna   TEXT,
    date_published TIMESTAMPTZ,
    date_updated   TIMESTAMPTZ,
    title          TEXT,
    description    TEXT,
    raw_record     JSONB NOT NULL,
    source_commit  TEXT NOT NULL,       -- git SHA from CVEProject/cvelistV5; reproducibility anchor
    first_seen     TIMESTAMPTZ DEFAULT now(),
    last_ingested  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE cvss_metric (
    cve_id        TEXT REFERENCES vulnerability(cve_id) ON DELETE CASCADE,
    version       TEXT NOT NULL,
    vector_string TEXT,
    base_score    NUMERIC(3,1),
    base_severity TEXT,
    source        TEXT NOT NULL,        -- cna | adp | nvd
    PRIMARY KEY (cve_id, version, source)
);

CREATE TABLE affected_product (
    id           BIGSERIAL PRIMARY KEY,
    cve_id       TEXT REFERENCES vulnerability(cve_id) ON DELETE CASCADE,
    vendor       TEXT,
    product      TEXT,
    cpe          TEXT,
    version_info JSONB
);
CREATE INDEX ON affected_product (cpe);
CREATE INDEX ON affected_product (lower(vendor), lower(product));

-- ── Enrichment feeds ─────────────────────────────────────────────────────────
CREATE TABLE epss_score (
    cve_id     TEXT REFERENCES vulnerability(cve_id) ON DELETE CASCADE,
    score      NUMERIC(6,5) NOT NULL,
    percentile NUMERIC(6,5) NOT NULL,
    score_date DATE NOT NULL,
    PRIMARY KEY (cve_id, score_date)
);

CREATE TABLE kev_entry (
    cve_id           TEXT PRIMARY KEY REFERENCES vulnerability(cve_id) ON DELETE CASCADE,
    date_added       DATE NOT NULL,
    due_date         DATE,
    known_ransomware BOOLEAN,
    required_action  TEXT,
    notes            TEXT
);

-- Supplemental feed — schema may change; parser is isolated behind a versioned interface
CREATE TABLE ssvc_decision (
    cve_id           TEXT REFERENCES vulnerability(cve_id) ON DELETE CASCADE,
    role             TEXT,
    exploitation     TEXT,       -- none | poc | active
    automatable      TEXT,       -- yes | no
    technical_impact TEXT,       -- partial | total
    decision         TEXT,       -- Track | Track* | Attend | Act
    source           TEXT DEFAULT 'cisa-adp',
    decided_at       TIMESTAMPTZ,
    PRIMARY KEY (cve_id, role)
);

-- ── CWE weakness catalog ─────────────────────────────────────────────────────
CREATE TABLE weakness (
    cwe_id      TEXT PRIMARY KEY,
    name        TEXT,
    abstraction TEXT,            -- Pillar | Class | Base | Variant
    description TEXT
);

CREATE TABLE cve_cwe (
    cve_id TEXT REFERENCES vulnerability(cve_id) ON DELETE CASCADE,
    cwe_id TEXT REFERENCES weakness(cwe_id) ON DELETE CASCADE,
    source TEXT,
    PRIMARY KEY (cve_id, cwe_id)
);

-- ── Identity registry ─────────────────────────────────────────────────────────
CREATE TABLE agent_identity (
    agent_id       TEXT PRIMARY KEY,
    did_web_url    TEXT NOT NULL,
    public_key_jwk JSONB NOT NULL,
    operator_id    TEXT NOT NULL,
    created_at     TIMESTAMPTZ DEFAULT now()
);

-- ── Session ───────────────────────────────────────────────────────────────────
CREATE TABLE session (
    session_id    TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL REFERENCES agent_identity(agent_id),
    operator_id   TEXT NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    terminated_at TIMESTAMPTZ         -- set on breach kill or TTL expiry
);
CREATE INDEX ON session (operator_id);

-- ── Corpus versioning ─────────────────────────────────────────────────────────
-- Partial unique index enforces: only one run may be in_progress at a time.
-- A failed run sets status = 'failed'; the previous sealed version remains current.
CREATE TABLE corpus_version (
    version_id   BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMPTZ DEFAULT now(),
    content_hash TEXT,       -- NULL while in_progress
    manifest     JSONB,      -- NULL while in_progress
    status       TEXT NOT NULL DEFAULT 'in_progress',  -- in_progress | sealed | failed
    notes        TEXT
);
CREATE UNIQUE INDEX corpus_version_one_in_progress
    ON corpus_version (status) WHERE status = 'in_progress';

-- ── Chunk + vector + lexical (APPEND-ONLY) ───────────────────────────────────
-- Never UPDATE a chunk row's embedding — doing so silently breaks reproducibility.
-- Changed content gets a new row; old rows get valid_to_version set.
CREATE TABLE chunk (
    chunk_id           BIGSERIAL PRIMARY KEY,
    source_type        TEXT NOT NULL,       -- cve | cwe
    source_id          TEXT NOT NULL,
    text               TEXT NOT NULL,
    embedding          VECTOR(1024),        -- dim locked at M3.5 benchmark
    lexical            TSVECTOR,
    metadata           JSONB NOT NULL,      -- cpe[], cwe[], kev bool, epss, severity, vendor, product, ports[]
    valid_from_version BIGINT NOT NULL REFERENCES corpus_version(version_id),
    valid_to_version   BIGINT REFERENCES corpus_version(version_id)  -- NULL = current
);

-- Partial HNSW index: current chunks only.
-- Without WHERE valid_to_version IS NULL the index spans all superseded rows
-- and degrades continuously as the corpus grows. Rebuild quarterly.
CREATE INDEX chunk_embedding_hnsw ON chunk
    USING hnsw (embedding vector_cosine_ops)
    WHERE valid_to_version IS NULL;
CREATE INDEX chunk_lexical_gin ON chunk USING gin (lexical);
CREATE INDEX chunk_metadata_gin ON chunk USING gin (metadata jsonb_path_ops);
CREATE INDEX chunk_version_range ON chunk (valid_from_version, valid_to_version);

-- ── Bonding (Path A — reputational) ──────────────────────────────────────────
CREATE TABLE operator_bond (
    operator_id             TEXT PRIMARY KEY,
    amount_usd              NUMERIC(12,2) NOT NULL,
    posted_at               TIMESTAMPTZ DEFAULT now(),
    status                  TEXT NOT NULL DEFAULT 'active',  -- active | depleted | withdrawn
    withdrawal_requested_at TIMESTAMPTZ,
    withdrawal_hold_days    INT NOT NULL DEFAULT 7
);

CREATE TABLE slash_event (
    id                  BIGSERIAL PRIMARY KEY,
    session_id          TEXT NOT NULL,
    breach_log_entry_id TEXT,                                        -- NULL until attestation_outbox drains
    attester_key_id     TEXT NOT NULL REFERENCES signing_key(key_id),
    operator_id         TEXT REFERENCES operator_bond(operator_id),
    amount_usd          NUMERIC(12,2) NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',             -- pending | executed | disputed
    created_at          TIMESTAMPTZ DEFAULT now()
);
