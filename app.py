from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
from functools import wraps
from typing import Any
from urllib.parse import urlsplit

from flask import (Flask, Response, abort, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

from db import ASSET_KINDS, SEVERITIES, STATUSES, connect, init_db
from scope import OUT_OF_SCOPE, check_scope

ADMIN_PASSWORD = os.environ.get("BOUNTYDECK_ADMIN_PASSWORD", "")
SECRET_KEY = os.environ.get("BOUNTYDECK_SECRET_KEY", "")
VERSION = os.environ.get("BOUNTYDECK_VERSION", "dev")
UPDATE_REPO = os.environ.get("BOUNTYDECK_REPO", "benjaminbencsik/BountyDeck")
UPDATE_BRANCH = os.environ.get("BOUNTYDECK_BRANCH", "main")

LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60


if len(ADMIN_PASSWORD) < 14:
    raise RuntimeError("Set BOUNTYDECK_ADMIN_PASSWORD to a unique password of at least 14 characters.")
if len(SECRET_KEY) < 32:
    raise RuntimeError("Set BOUNTYDECK_SECRET_KEY to a random value of at least 32 characters.")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("BOUNTYDECK_HTTPS", "0") == "1",
    MAX_CONTENT_LENGTH=64 * 1024,
)
# The container is only reachable through the local port or the single Caddy proxy.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


init_db()


# --------------------------------------------------------------------------- helpers

def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def require_csrf() -> None:
    sent = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, "Invalid form token. Reload the page and try again.")


def login_required(fn):
    @wraps(fn)
    def wrapped(*args: Any, **kwargs: Any):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


def field(name: str, limit: int, required: bool = False) -> str:
    value = request.form.get(name, "").strip()
    if len(value) > limit or (required and not value):
        abort(400, f"Invalid {name} field.")
    return value


def int_field(name: str) -> int:
    try:
        return int(request.form.get(name, ""))
    except ValueError:
        abort(400, f"Invalid {name}.")


def safe_http_url(value: str) -> str:
    """Only http(s) URLs may be stored; blocks javascript:/data: links."""
    if not value:
        return ""
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        abort(400, "Program policy URL must start with http:// or https://")
    return value


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "project"


@app.context_processor
def inject_helpers():
    return {"csrf_token": csrf_token, "version": VERSION}


@app.template_filter("ts")
def format_ts(value: float | None) -> str:
    if not value:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(value))


def client_ip() -> str:
    return request.remote_addr or "unknown"


def login_is_locked(db: sqlite3.Connection, ip: str) -> bool:
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    db.execute("DELETE FROM login_failures WHERE ts < ?", (cutoff,))
    count = db.execute("SELECT COUNT(*) FROM login_failures WHERE ip=? AND ts>=?", (ip, cutoff)).fetchone()[0]
    return count >= LOGIN_MAX_FAILURES


# --------------------------------------------------------------------------- auth

@app.get("/login")
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("login.html", title="Sign in", error="")


@app.post("/login")
def login_post():
    require_csrf()
    ip = client_ip()
    with connect() as db:
        if login_is_locked(db, ip):
            return render_template("login.html", title="Sign in",
                                   error="Too many failed attempts. Try again in 15 minutes."), 429
        supplied = request.form.get("password", "")
        if hmac.compare_digest(supplied.encode(), ADMIN_PASSWORD.encode()):
            db.execute("DELETE FROM login_failures WHERE ip=?", (ip,))
            session.clear()
            session["authenticated"] = True
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("index"))
        db.execute("INSERT INTO login_failures(ip, ts) VALUES(?,?)", (ip, time.time()))
    return render_template("login.html", title="Sign in", error="Incorrect password."), 401


@app.post("/logout")
@login_required
def logout():
    require_csrf()
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------- workspace

def annotate_assets(assets: list[sqlite3.Row], projects: list[sqlite3.Row]) -> list[dict[str, Any]]:
    scopes = {p["id"]: p["authorized_scope"] for p in projects}
    out = []
    for a in assets:
        row = dict(a)
        row["scope_status"] = check_scope(a["value"], scopes.get(a["project_id"], ""))
        out.append(row)
    return out


@app.get("/")
@login_required
def index():
    with connect() as db:
        projects = db.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
        assets = db.execute("SELECT * FROM assets ORDER BY id DESC").fetchall()
        findings = db.execute("SELECT * FROM findings ORDER BY id DESC").fetchall()
        runs = db.execute("SELECT * FROM hunt_runs ORDER BY id DESC LIMIT 200").fetchall()
    runs_by_project: dict[int, list[Any]] = {}
    for run in runs:
        bucket = runs_by_project.setdefault(run["project_id"], [])
        if len(bucket) < 3:
            bucket.append(run)
    return render_template("dashboard.html", title="Workspace", projects=projects,
                           assets=annotate_assets(assets, projects), findings=findings,
                           runs=runs_by_project, schedule_choices=SCHEDULE_CHOICES,
                           kinds=ASSET_KINDS, severities=SEVERITIES, statuses=STATUSES)


@app.post("/projects")
@login_required
def add_project():
    require_csrf()
    values = (field("name", 120, True), safe_http_url(field("program_url", 500)),
              field("authorized_scope", 5000, True), field("authorization_notes", 2000))
    with connect() as db:
        db.execute("INSERT INTO projects(name, program_url, authorized_scope, authorization_notes) "
                   "VALUES(?,?,?,?)", values)
    return redirect(url_for("index"))


@app.post("/assets")
@login_required
def add_asset():
    require_csrf()
    project_id = int_field("project_id")
    kind = field("kind", 30, True)
    if kind not in ASSET_KINDS:
        abort(400, "Invalid asset type.")
    value, notes = field("value", 500, True), field("notes", 2000)
    with connect() as db:
        project = db.execute("SELECT authorized_scope FROM projects WHERE id=?", (project_id,)).fetchone()
        if not project:
            abort(400, "Unknown project.")
        db.execute("INSERT INTO assets(project_id,value,kind,notes) VALUES(?,?,?,?)",
                   (project_id, value, kind, notes))
    if check_scope(value, project["authorized_scope"]) == OUT_OF_SCOPE:
        flash(f"Saved, but “{value}” does not match this project's scope rules. "
              "Double-check the program policy before testing it.", "warning")
    return redirect(url_for("index"))


@app.post("/findings")
@login_required
def add_finding():
    require_csrf()
    project_id = int_field("project_id")
    severity, status = field("severity", 20, True), field("status", 20, True)
    if severity not in SEVERITIES or status not in STATUSES:
        abort(400, "Invalid severity or status.")
    values = (field("title", 180, True), field("details", 5000))
    with connect() as db:
        if not db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
            abort(400, "Unknown project.")
        db.execute("INSERT INTO findings(project_id,title,severity,status,details) VALUES(?,?,?,?,?)",
                   (project_id, values[0], severity, status, values[1]))
    return redirect(url_for("index"))


@app.post("/findings/<int:item_id>/status")
@login_required
def update_finding_status(item_id: int):
    require_csrf()
    status = field("status", 20, True)
    if status not in STATUSES:
        abort(400, "Invalid status.")
    with connect() as db:
        cur = db.execute("UPDATE findings SET status=? WHERE id=?", (status, item_id))
        if cur.rowcount == 0:
            abort(404)
    return redirect(url_for("index"))


@app.post("/delete/<table>/<int:item_id>")
@login_required
def delete_item(table: str, item_id: int):
    require_csrf()
    if table not in {"projects", "assets", "findings"}:
        abort(404)
    with connect() as db:
        db.execute(f"DELETE FROM {table} WHERE id=?", (item_id,))  # table is allow-listed above
    return redirect(url_for("index"))


# --------------------------------------------------------------------------- automation

SCHEDULE_CHOICES = (6, 12, 24, 72, 168)


@app.post("/projects/<int:project_id>/automation")
@login_required
def set_automation(project_id: int):
    require_csrf()
    action = field("action", 10, True)
    with connect() as db:
        if not db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
            abort(404)
        if action == "disable":
            db.execute("UPDATE projects SET automation_enabled=0, run_requested=0 WHERE id=?", (project_id,))
            flash("Automation disabled. A run in progress will stop at its next stage.", "info")
        elif action == "enable":
            if request.form.get("acknowledge") != "yes":
                abort(400, "Confirm that the program permits automated scanning before enabling automation.")
            try:
                hours = int(request.form.get("schedule_hours", ""))
            except ValueError:
                abort(400, "Invalid schedule.")
            if hours not in SCHEDULE_CHOICES:
                abort(400, "Invalid schedule.")
            db.execute("UPDATE projects SET automation_enabled=1, automation_ack_at=?, schedule_hours=? WHERE id=?",
                       (time.time(), hours, project_id))
            flash("Automation enabled. The hunter service picks it up within a minute "
                  "(start it with: docker compose --profile hunter up -d).", "info")
        else:
            abort(400, "Invalid action.")
    return redirect(url_for("index"))


@app.post("/projects/<int:project_id>/run-now")
@login_required
def run_now(project_id: int):
    require_csrf()
    with connect() as db:
        cur = db.execute("UPDATE projects SET run_requested=1 WHERE id=? AND automation_enabled=1", (project_id,))
        if cur.rowcount == 0:
            abort(400, "Enable automation for this project first.")
    flash("Run queued.", "info")
    return redirect(url_for("index"))


# --------------------------------------------------------------------------- export

def project_export(project_id: int) -> dict[str, Any]:
    with connect() as db:
        project = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if not project:
            abort(404)
        assets = db.execute("SELECT * FROM assets WHERE project_id=? ORDER BY id", (project_id,)).fetchall()
        findings = db.execute("SELECT * FROM findings WHERE project_id=? ORDER BY id", (project_id,)).fetchall()
    return {
        "project": dict(project),
        "assets": [dict(a, scope_status=check_scope(a["value"], project["authorized_scope"])) for a in assets],
        "findings": [dict(f) for f in findings],
    }


def render_markdown(data: dict[str, Any]) -> str:
    p = data["project"]
    lines = [f"# {p['name']}", ""]
    if p["program_url"]:
        lines += [f"Program policy: {p['program_url']}", ""]
    lines += ["## Scope on record", "", "```", p["authorized_scope"], "```", ""]
    if p["authorization_notes"]:
        lines += ["## Authorization notes", "", p["authorization_notes"], ""]
    lines += ["## Assets", ""]
    if data["assets"]:
        lines += ["| Asset | Type | Scope | Notes |", "|---|---|---|---|"]
        for a in data["assets"]:
            notes = a["notes"].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {a['value'].replace('|', '\\|')} | {a['kind']} | {a['scope_status']} | {notes} |")
    else:
        lines.append("_None recorded._")
    lines += ["", "## Findings", ""]
    if data["findings"]:
        for f in data["findings"]:
            lines += [f"### {f['title']}", "", f"- Severity: {f['severity']}", f"- Status: {f['status']}", ""]
            if f["details"]:
                lines += [f["details"], ""]
    else:
        lines.append("_None recorded._")
    return "\n".join(lines) + "\n"


@app.get("/projects/<int:project_id>/export.<fmt>")
@login_required
def export_project(project_id: int, fmt: str):
    data = project_export(project_id)
    slug = slugify(data["project"]["name"])
    if fmt == "json":
        body, mime = json.dumps(data, indent=2), "application/json"
    elif fmt == "md":
        body, mime = render_markdown(data), "text/markdown"
    else:
        abort(404)
    return Response(body, mimetype=mime,
                    headers={"Content-Disposition": f'attachment; filename="{slug}.{fmt}"'})


# --------------------------------------------------------------------------- updates

def fetch_latest_commit() -> dict[str, str]:
    """Ask GitHub for the newest commit on the update branch. Raises on any failure."""
    url = f"https://api.github.com/repos/{UPDATE_REPO}/commits/{UPDATE_BRANCH}"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "BountyDeck-update-check"})
    with urllib.request.urlopen(req, timeout=6) as resp:  # noqa: S310 - fixed https URL
        data = json.load(resp)
    return {"sha": data["sha"], "message": data["commit"]["message"].splitlines()[0],
            "date": data["commit"]["committer"]["date"]}


@app.get("/update")
@login_required
def update_page():
    return render_template("update.html", title="Updates", repo=UPDATE_REPO, branch=UPDATE_BRANCH, result=None)


@app.post("/update/check")
@login_required
def update_check():
    require_csrf()
    result: dict[str, Any]
    try:
        latest = fetch_latest_commit()
        current = VERSION
        up_to_date = current != "dev" and latest["sha"].startswith(current) or latest["sha"] == current
        result = {"ok": True, "latest": latest, "up_to_date": up_to_date, "dev_build": current == "dev"}
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, OSError) as exc:
        result = {"ok": False, "error": f"Could not reach GitHub: {exc}"}
    return render_template("update.html", title="Updates", repo=UPDATE_REPO, branch=UPDATE_BRANCH, result=result)


# --------------------------------------------------------------------------- headers

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store" if session.get("authenticated") else response.headers.get("Cache-Control", "no-cache")
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'self'")
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
