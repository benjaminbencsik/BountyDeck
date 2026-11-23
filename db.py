"""SQLite access shared by the web app and the scheduled hunter service."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("BOUNTYDECK_DB", "/data/bountydeck.sqlite3"))

ASSET_KINDS = ("Hostname", "URL", "IP address", "Other")
SEVERITIES = ("Informational", "Low", "Medium", "High", "Critical")
# Marking a result with one of these requires a note on how it was confirmed or ruled out.
NOTE_REQUIRED_STATUSES = ("Verified", "False positive")
REPORTABLE_STATUSES = ("Verified", "Reported", "Resolved")
STATUSES = ("Unverified", "Open", "Triaged", "Verified", "Reported", "Resolved", "Informative", "False positive")

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    program_url TEXT NOT NULL DEFAULT '',
    authorized_scope TEXT NOT NULL,
    authorization_notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    value TEXT NOT NULL,
    kind TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS login_failures (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS hunt_runs (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL DEFAULT 'running',
    log TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_login_failures_ip ON login_failures(ip, ts);
CREATE INDEX IF NOT EXISTS idx_hunt_runs_project ON hunt_runs(project_id, started_at);
"""

# Columns added after the first release: (table, column, DDL). Applied to existing databases.
MIGRATIONS = (
    ("projects", "automation_enabled", "INTEGER NOT NULL DEFAULT 0"),
    ("projects", "automation_ack_at", "REAL"),
    ("projects", "schedule_hours", "INTEGER NOT NULL DEFAULT 24"),
    ("projects", "last_run_at", "REAL"),
    ("projects", "run_requested", "INTEGER NOT NULL DEFAULT 0"),
    ("findings", "dedupe_key", "TEXT"),
    ("findings", "verification_notes", "TEXT NOT NULL DEFAULT ''"),
)


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with connect() as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(SCHEMA)
        for table, column, ddl in MIGRATIONS:
            existing = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
            if column not in existing:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedupe "
                   "ON findings(project_id, dedupe_key) WHERE dedupe_key IS NOT NULL")
