-- PostgreSQL migration 006-audit
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    project_id BIGINT,
    target TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT ''
);
