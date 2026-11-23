from __future__ import annotations

from pathlib import Path


def apply_migrations(database_url: str | None = None) -> list[str]:
    """Return migration names. PostgreSQL support is a deployment scaffold; SQLite remains local default."""
    migrations = [
        "001_team_auth.sql",
        "002_project_members.sql",
        "003_authorizations.sql",
        "004_scan_jobs.sql",
        "005_results_and_findings.sql",
        "006_audit_log.sql",
    ]
    return migrations
