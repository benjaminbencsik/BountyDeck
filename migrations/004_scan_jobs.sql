-- PostgreSQL migration 004-scan-jobs
CREATE TABLE IF NOT EXISTS scan_jobs (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL,
    profile TEXT NOT NULL,
    tools TEXT NOT NULL,
    target_snapshot TEXT NOT NULL,
    authorization_id BIGINT NOT NULL REFERENCES authorization_records(id),
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending-approval','approved','queued','running','completed','failed','canceled')),
    dry_run JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error TEXT NOT NULL DEFAULT ''
);
