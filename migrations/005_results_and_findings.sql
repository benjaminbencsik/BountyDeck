-- PostgreSQL migration 005-results-and-findings
CREATE TABLE IF NOT EXISTS raw_results (
    id BIGSERIAL PRIMARY KEY,
    job_id BIGINT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    tool_version TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL,
    stdout TEXT NOT NULL DEFAULT '',
    stderr TEXT NOT NULL DEFAULT '',
    exit_code INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings_normalized (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL,
    job_id BIGINT REFERENCES scan_jobs(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    category TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    cwe TEXT NOT NULL DEFAULT '',
    cvss TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
