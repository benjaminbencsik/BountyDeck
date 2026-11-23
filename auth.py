from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

import sqlite3

PBKDF2_ITERATIONS = 600_000
ROLES = {"viewer", "operator", "approver", "admin"}


def hash_password(password: str) -> str:
    if len(password) < 14:
        raise ValueError("Password must contain at least 14 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(PBKDF2_ITERATIONS, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, digest = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iterations))
        return hmac.compare_digest(actual, base64.b64decode(digest))
    except Exception:
        return False


def ensure_auth_schema(db: sqlite3.Connection) -> None:
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NOT NULL CHECK(role IN ('viewer','operator','approver','admin')),
        totp_secret TEXT NOT NULL DEFAULT '',
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS api_tokens (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        token_digest TEXT NOT NULL UNIQUE,
        revoked INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS project_members (
        project_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('viewer','operator','approver','admin')),
        PRIMARY KEY(project_id, user_id)
    );
    """)


def require_role(user_role: str, required: str) -> bool:
    rank = {"viewer": 1, "operator": 2, "approver": 3, "admin": 4}
    return rank.get(user_role, 0) >= rank.get(required, 99)


def create_api_token(db: sqlite3.Connection, user_id: int, name: str, expires_at: str | None = None) -> str:
    token = "bd_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    db.execute("INSERT INTO api_tokens(user_id,name,token_digest,expires_at) VALUES(?,?,?,?)", (user_id, name, digest, expires_at))
    return token
