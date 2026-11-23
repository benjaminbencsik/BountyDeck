from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone

from scope import ScopeRule, parse_scope, target_allowed

SCAN_PROFILES = {
    "passive": {"description": "Public-data, DNS, and HTTP metadata only", "active": False, "intrusive": False},
    "light": {"description": "Low-volume approved web and DNS probing", "active": True, "intrusive": False},
    "intrusive": {"description": "Fuzzing or vulnerability templates; requires separate approval", "active": True, "intrusive": True},
}

TOOL_ALLOWLIST = {
    "passive": {"assetfinder", "gau", "waybackurls", "whois", "dig"},
    "light": {"subfinder", "dnsx", "httpx", "katana", "gowitness"},
    "intrusive": {"nmap", "naabu", "ffuf", "dirsearch", "nuclei"},
}


def ensure_scan_schema(db: sqlite3.Connection) -> None:
    db.executescript("""
    CREATE TABLE IF NOT EXISTS authorization_records (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL,
        approved_by TEXT NOT NOT NULL,
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
        status TEXT NOT NULL DEFAULT 'draft',
        dry_run TEXT NOT NULL DEFAULT '{}',
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        started_at TEXT,
        finished_at TEXT,
        error TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS raw_results (
        id INTEGER PRIMARY KEY,
        job_id INTEGER NOT NULL,
        tool TEXT NOT NULL,
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
        target TEXT NOT NULL DEFAULT '',
        evidence TEXT NOT NULL DEFAULT '',
        remediation TEXT NOT NULL DEFAULT '',
        cwe TEXT NOT NULL DEFAULT '',
        cvss TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)


def validate_profile(profile: str, tools: list[str]) -> None:
    if profile not in SCAN_PROFILES:
        raise ValueError("Unknown scan profile")
    allowed = set().union(*(TOOL_ALLOWLIST[name] for name in ("passive", profile) if name in TOOL_ALLOWLIST))
    rejected = set(tools) - allowed
    if rejected:
        raise ValueError("Tools are not allowed in this profile: " + ", ".join(sorted(rejected)))
    if profile == "intrusive":
        raise PermissionError("Intrusive scans require a separate approved authorization workflow")


def build_dry_run(profile: str, scope_text: str, targets: list[str], tools: list[str]) -> dict:
    validate_profile(profile, tools)
    rules = parse_scope(scope_text)
    allowed_targets = []
    blocked_targets = []
    for target in targets:
        (allowed_targets if target_allowed(target, rules) else blocked_targets).append(target)
    if blocked_targets:
        raise PermissionError("Blocked out-of-scope targets: " + ", ".join(blocked_targets))
    if not allowed_targets:
        raise ValueError("No in-scope targets supplied")
    return {
        "profile": profile,
        "scope_hash": __import__("hashlib").sha256(scope_text.encode()).hexdigest(),
        "targets": allowed_targets,
        "tools": tools,
        "commands": [f"{tool} --target {target}" for tool in tools for target in allowed_targets],
        "approval_required": profile != "passive",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
