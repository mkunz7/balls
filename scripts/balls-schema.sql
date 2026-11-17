-- BALLS session database schema (one balls.db per scan, under the session dir).
--
-- Normalized pipeline store: scans -> components -> raw_findings -> council -> findings.
-- Fan-out children (investigators, category hunters) write rows DIRECTLY via the
-- balls-db CLI, so there is no "funnel results back up" plumbing. SQLite (WAL mode +
-- busy_timeout, set at connect time) serializes concurrent writers safely, so parallel
-- subagents never lose or clobber each other's rows.
--
-- CHECK constraints enforce the completeness rules (non-empty council perspectives,
-- valid enums) at insert time — the DB itself rejects an empty perspective, which
-- subsumes the old validate.py --strict gate.

PRAGMA foreign_keys = ON;

-- One row per scan (== session).
CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,          -- sessionId
    slug         TEXT,
    remote       TEXT,
    target_path  TEXT,
    state        TEXT NOT NULL DEFAULT 'initializing',
    risk_rating  TEXT,                       -- computed by `promote`
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

-- Components mapped by the Planner (balls-scan).
CREATE TABLE IF NOT EXISTS components (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    language     TEXT,
    framework    TEXT,
    type         TEXT,
    risk_level   TEXT,
    description  TEXT,
    paths        TEXT,                        -- JSON array of path globs
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL,
    UNIQUE (scan_id, name)
);

-- Reviewer intelligence: areas of interest the hunters should probe. Written directly
-- by the reviewer's investigator children (entry-points, data-flows, auth, etc.).
CREATE TABLE IF NOT EXISTS areas_of_interest (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    component_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    note         TEXT NOT NULL,
    file         TEXT,
    line         INTEGER,
    question     TEXT,
    created_by   TEXT,                        -- which investigator wrote it
    created_at   TEXT NOT NULL
);

-- Raw hunter findings (pre-council). Written directly by category-hunter children.
CREATE TABLE IF NOT EXISTS raw_findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    component_id   INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    fingerprint    TEXT NOT NULL,             -- component|cwe|file|line|type (computed)
    type           TEXT NOT NULL,
    severity       TEXT NOT NULL,
    confidence     TEXT,
    attack_vector  TEXT,
    cwe_id         TEXT,
    cwe_name       TEXT,
    file           TEXT NOT NULL,
    line_start     INTEGER,
    line_end       INTEGER,
    code_snippet   TEXT,
    description    TEXT,
    df_source      TEXT,
    df_sink        TEXT,
    df_sanitization TEXT,
    df_proof       TEXT,
    hunter         TEXT,                       -- which category hunter found it
    created_at     TEXT NOT NULL,
    CHECK (severity IN ('Critical','High','Medium','Low','Info'))
);
CREATE INDEX IF NOT EXISTS idx_raw_scan_comp ON raw_findings(scan_id, component_id);
CREATE INDEX IF NOT EXISTS idx_raw_fp ON raw_findings(scan_id, fingerprint);

-- Council verdicts (one row per reviewed raw_finding). Perspectives are enforced
-- non-empty by CHECK, so a council row can never ship blank Attacker/Defender/Auditor.
CREATE TABLE IF NOT EXISTS council (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    component_id      INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    raw_finding_id    INTEGER NOT NULL REFERENCES raw_findings(id) ON DELETE CASCADE,
    council_vote      TEXT NOT NULL,
    severity          TEXT NOT NULL,          -- council-adjusted severity
    attacker          TEXT NOT NULL,
    defender          TEXT NOT NULL,
    auditor           TEXT NOT NULL,
    proven_primitive  INTEGER NOT NULL DEFAULT 0,
    attack_scenario   TEXT,
    impact            TEXT,
    remediation       TEXT,
    rationale         TEXT,
    created_at        TEXT NOT NULL,
    UNIQUE (raw_finding_id),
    CHECK (council_vote IN ('CONFIRMED','LIKELY','POSSIBLE','FALSE_POSITIVE')),
    CHECK (severity IN ('Critical','High','Medium','Low','Info')),
    CHECK (length(trim(attacker)) > 0 AND length(trim(defender)) > 0 AND length(trim(auditor)) > 0)
);

-- Final report findings: the deterministic promotion of surviving council verdicts,
-- deduped by fingerprint, with assigned BALLS-NNN ids. Populated by `promote`.
CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    component_id     INTEGER REFERENCES components(id) ON DELETE CASCADE,
    raw_finding_id   INTEGER REFERENCES raw_findings(id) ON DELETE SET NULL,
    council_id       INTEGER REFERENCES council(id) ON DELETE SET NULL,
    fingerprint      TEXT NOT NULL,
    report_id        TEXT,                     -- BALLS-NNN (assigned by promote)
    component        TEXT,
    type             TEXT,
    severity         TEXT,
    confidence       TEXT,
    council_vote     TEXT,
    attack_vector    TEXT,
    cwe_id           TEXT,
    cwe_name         TEXT,
    file             TEXT,
    line_start       INTEGER,
    line_end         INTEGER,
    code_snippet     TEXT,
    description      TEXT,
    df_source        TEXT,
    df_sink          TEXT,
    df_sanitization  TEXT,
    df_proof         TEXT,
    attack_scenario  TEXT,
    impact           TEXT,
    remediation      TEXT,
    attacker         TEXT,
    defender         TEXT,
    auditor          TEXT,
    proven_primitive INTEGER DEFAULT 0,
    UNIQUE (scan_id, fingerprint)
);

-- Suppressed findings (kept for transparency, out of the report). Populated by promote.
CREATE TABLE IF NOT EXISTS suppressions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint  TEXT,
    component    TEXT,
    type         TEXT,
    cwe_id       TEXT,
    severity     TEXT,
    reason       TEXT,
    created_at   TEXT NOT NULL
);

-- Exploit chains and their members (members reference findings by fingerprint).
CREATE TABLE IF NOT EXISTS chains (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    report_id         TEXT,                    -- CHAIN-NN (assigned by promote)
    title             TEXT NOT NULL,
    combined_severity TEXT,
    rationale         TEXT,
    created_at        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chain_members (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id    INTEGER NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    step_order  INTEGER,
    gains       TEXT
);
