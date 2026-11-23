-- PostgreSQL migration 003-authorizations
CREATE TABLE IF NOT EXISTS authorization_records (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL,
    approved_by TEXT NOT NULL,
    scope_text TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    written_auth_reference TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);
