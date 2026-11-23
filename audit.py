import sqlite3
from datetime import datetime, timezone


def record_audit(db: sqlite3.Connection, actor: str, action: str, project_id: int | None = None,
                 target: str = "", details: str = "") -> None:
    db.execute(
        "INSERT INTO audit_log(created_at,actor,action,project_id,target,details) VALUES(?,?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), actor, action, project_id, target, details[:10000]),
    )


def ensure_audit_schema(db: sqlite3.Connection) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            project_id INTEGER,
            target TEXT NOT NULL DEFAULT '',
            details TEXT NOT NOT NULL DEFAULT ''
        )
    """)
