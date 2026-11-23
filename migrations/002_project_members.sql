-- PostgreSQL migration 002-project-members
CREATE TABLE IF NOT EXISTS project_members (
    project_id BIGINT NOT NULL,
    user_id BIGINT NOT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'approver', 'admin')),
    PRIMARY KEY (project_id, user_id)
);
