from __future__ import annotations

import sqlite3


def ensure_job_schema(db: sqlite3.Connection) -> None:
    db.executescript("""
    CREATE TABLE IF NOT EXISTS authorization_records (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL,
        approved_by TEXT NOT NULL,
        scope_text TEXT NOT NULL,
        scope_hash TEXT NOT NULL,
        written_auth_reference TEXT NOT NULL,
        approved_at TEXT NOT NULL,
        expires_at TEXT,
        revoked INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS scan_jobs (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL,
        profile TEXT NOT NULL,
        tools TEXT NOT NULL,
        target_snapshot TEXT NOT NULL,
        authorization_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','pending-approval','approved','queued','running','completed','failed','canceled')),
        dry_run TEXT NOT NULL DEFAULT '{}',
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        approved_by TEXT,
        approved_at TEXT,
        started_at TEXT,
        finished_at TEXT,
        error TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS scan_events (
        id INTEGER PRIMARY KEY,
        job_id INTEGER NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS raw_results (
        id INTEGER PRIMARY KEY,
        job_id INTEGER NOT NULL,
        tool TEXT NOT NULL,
        tool_version TEXT NOT NOT NULL DEFAULT '',
        target TEXT NOT NULL,
        stdout TEXT NOT NULL DEFAULT '',
        stderr TEXT NOT NULL DEFAULT '',
        exit_code INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS findings_normalized (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL,
        job_id INTEGER,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Open',
        category TEXT NOT NULL DEFAULT '',
        target TEXT NOT NULL DEFAULT '',
        evidence TEXT NOT NULL DEFAULT '',
        remediation TEXT NOT NULL DEFAULT '',
        cwe TEXT NOT NULL DEFAULT '',
        cvss TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)
