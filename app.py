from __future__ import annotations

import hmac
import os
import secrets
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Any

from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("BOUNTYDECK_DB", "/data/bountydeck.sqlite3"))
ADMIN_PASSWORD = os.environ.get("BOUNTYDECK_ADMIN_PASSWORD", "")
SECRET_KEY = os.environ.get("BOUNTYDECK_SECRET_KEY", "")

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


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with connect() as db:
        db.executescript("""
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
        """)


init_db()


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
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped


BASE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} · BountyDeck</title><style>
:root{color-scheme:dark;--bg:#0d1117;--panel:#161b22;--line:#30363d;--text:#e6edf3;--muted:#9da7b3;--accent:#58a6ff;--green:#3fb950;--red:#f85149}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}header{border-bottom:1px solid var(--line);padding:16px max(20px,calc((100vw - 1100px)/2));display:flex;justify-content:space-between;align-items:center}header a{color:var(--text);text-decoration:none;font-weight:700;font-size:20px}.wrap{max-width:1100px;margin:32px auto;padding:0 20px}.muted{color:var(--muted)}.warning{border:1px solid #9e6a03;background:#2b210b;padding:12px 16px;border-radius:8px;margin:18px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin:16px 0}.card h2,.card h3{margin-top:0}label{display:block;color:var(--muted);margin:10px 0 4px}input,textarea,select{width:100%;padding:10px;border:1px solid var(--line);border-radius:6px;background:#0d1117;color:var(--text);font:inherit}textarea{min-height:84px;resize:vertical}button,.button{background:#238636;color:white;border:0;padding:9px 14px;border-radius:6px;font:inherit;cursor:pointer;margin-top:12px}button:hover{background:#2ea043}.danger{background:#8c2828}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted)}.small{font-size:13px}.inline{display:inline}.inline button{margin:0;padding:5px 9px}.pill{border:1px solid var(--line);padding:2px 8px;border-radius:99px;white-space:nowrap}a{color:var(--accent)}.empty{color:var(--muted);padding:12px 0}.login{max-width:420px;margin:10vh auto}.top-actions{display:flex;gap:14px;align-items:center}@media(max-width:600px){table{font-size:13px}th,td{padding:6px}.wrap{margin-top:18px}}
</style></head><body><header><a href="{{ url_for('index') }}">BountyDeck</a>{% if session.get('authenticated') %}<div class="top-actions"><span class="muted small">Authorized assessment workspace</span><form class="inline" method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="danger">Sign out</button></form></div>{% endif %}</header><main class="wrap">{{ content|safe }}</main></body></html>"""

LOGIN = """<section class="card login"><h1>Sign in</h1><p class="muted">Use the administrator password configured during setup.</p>{% if error %}<p role="alert">{{ error }}</p>{% endif %}<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><label for="password">Password</label><input id="password" name="password" type="password" required autofocus><button>Sign in</button></form></section>"""

DASHBOARD = """<h1>Assessment workspace</h1><p class="muted">Organize explicitly authorized programs, manually recorded assets, and findings. BountyDeck does not probe targets or run scanners.</p><div class="warning"><strong>Authorization required:</strong> Add only programs and assets you are permitted to assess. Scope notes are records for your team; they are not a technical authorization check.</div>
<section class="grid"><div class="card"><h2>New project</h2><form method="post" action="{{ url_for('add_project') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><label>Project / program name</label><input name="name" maxlength="120" required><label>Program policy URL (optional)</label><input name="program_url" type="url" maxlength="500"><label>Authorized domains / scope (one per line)</label><textarea name="authorized_scope" maxlength="5000" required placeholder="example.com&#10;app.example.com"></textarea><label>Authorization notes</label><textarea name="authorization_notes" maxlength="2000" placeholder="Policy reference, dates, exclusions…"></textarea><button>Create project</button></form></div><div class="card"><h2>Record an asset</h2>{% if projects %}<form method="post" action="{{ url_for('add_asset') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><label>Project</label><select name="project_id" required>{% for p in projects %}<option value="{{ p.id }}">{{ p.name }}</option>{% endfor %}</select><label>Asset (manually collected)</label><input name="value" maxlength="500" required placeholder="hostname, URL, IP, or other identifier"><label>Type</label><select name="kind"><option>Hostname</option><option>URL</option><option>IP address</option><option>Other</option></select><label>Notes</label><textarea name="notes" maxlength="2000"></textarea><button>Save asset</button></form>{% else %}<p class="empty">Create a project first.</p>{% endif %}</div></section>
<section class="card"><h2>Projects</h2>{% if projects %}{% for p in projects %}<article class="card"><div class="grid"><div><h3>{{ p.name }}</h3>{% if p.program_url %}<p><a href="{{ p.program_url }}" rel="noreferrer noopener" target="_blank">Program policy</a></p>{% endif %}<p><strong>Authorized scope on record</strong></p><pre class="muted">{{ p.authorized_scope }}</pre>{% if p.authorization_notes %}<p class="muted">{{ p.authorization_notes }}</p>{% endif %}<form method="post" action="{{ url_for('delete_item', table='projects', item_id=p.id) }}" onsubmit="return confirm('Delete this project and its recorded assets/findings?')"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="danger">Delete project</button></form></div><div><h3>Assets</h3>{% set project_assets = assets|selectattr('project_id','equalto',p.id)|list %}{% if project_assets %}<table><thead><tr><th>Value</th><th>Type</th><th></th></tr></thead><tbody>{% for a in project_assets %}<tr><td>{{ a.value }}{% if a.notes %}<br><span class="muted small">{{ a.notes }}</span>{% endif %}</td><td>{{ a.kind }}</td><td><form method="post" action="{{ url_for('delete_item', table='assets', item_id=a.id) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="danger">Delete</button></form></td></tr>{% endfor %}</tbody></table>{% else %}<p class="empty">No assets recorded.</p>{% endif %}</div><div><h3>Findings</h3>{% set project_findings = findings|selectattr('project_id','equalto',p.id)|list %}{% if project_findings %}<table><thead><tr><th>Finding</th><th>Severity / status</th><th></th></tr></thead><tbody>{% for f in project_findings %}<tr><td><strong>{{ f.title }}</strong>{% if f.details %}<br><span class="muted small">{{ f.details }}</span>{% endif %}</td><td>{{ f.severity }} / {{ f.status }}</td><td><form method="post" action="{{ url_for('delete_item', table='findings', item_id=f.id) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="danger">Delete</button></form></td></tr>{% endfor %}</tbody></table>{% else %}<p class="empty">No findings recorded.</p>{% endif %}<details><summary>Record finding</summary><form method="post" action="{{ url_for('add_finding') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="project_id" value="{{ p.id }}"><label>Title</label><input name="title" maxlength="180" required><label>Severity</label><select name="severity"><option>Informational</option><option>Low</option><option>Medium</option><option>High</option><option>Critical</option></select><label>Status</label><select name="status"><option>Open</option><option>Triaged</option><option>Reported</option><option>Resolved</option><option>Informative</option></select><label>Details / evidence notes</label><textarea name="details" maxlength="5000"></textarea><button>Save finding</button></form></details></div></div></article>{% endfor %}{% else %}<p class="empty">No projects yet. Create one to start organizing an authorized assessment.</p>{% endif %}</section>
<section class="card"><h2>Tool integrations</h2><p>Tool installation, updates, and scan execution are not enabled in this deployment. This version is a locally/VPS-hosted program, asset, and findings manager; it does not invoke Subfinder, Amass, Nmap, ffuf, Nuclei, or other network-scanning tools.</p><p class="muted">This avoids turning an unverified scope note into an automated scanner authorization. Use each tool only under its own documented authorization and scope controls.</p></section>"""


@app.context_processor
def inject_helpers():
    return {"csrf_token": csrf_token}


def page(title: str, content_template: str, **context: Any):
    content = render_template_string(content_template, **context)
    return render_template_string(BASE, title=title, content=content)


@app.get("/login")
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    return page("Sign in", LOGIN, error="")


@app.post("/login")
def login_post():
    require_csrf()
    supplied = request.form.get("password", "")
    if hmac.compare_digest(supplied.encode(), ADMIN_PASSWORD.encode()):
        session.clear()
        session["authenticated"] = True
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("index"))
    return page("Sign in", LOGIN, error="Incorrect password."), 401


@app.post("/logout")
@login_required
def logout():
    require_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    with connect() as db:
        projects = db.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
        assets = db.execute("SELECT * FROM assets ORDER BY id DESC").fetchall()
        findings = db.execute("SELECT * FROM findings ORDER BY id DESC").fetchall()
    return page("Workspace", DASHBOARD, projects=projects, assets=assets, findings=findings)


def field(name: str, limit: int, required: bool = False) -> str:
    value = request.form.get(name, "").strip()
    if len(value) > limit or (required and not value):
        abort(400, f"Invalid {name} field.")
    return value


@app.post("/projects")
@login_required
def add_project():
    require_csrf()
    with connect() as db:
        db.execute("INSERT INTO projects(name, program_url, authorized_scope, authorization_notes) VALUES(?,?,?,?)", (
            field("name", 120, True), field("program_url", 500), field("authorized_scope", 5000, True), field("authorization_notes", 2000)))
    return redirect(url_for("index"))


@app.post("/assets")
@login_required
def add_asset():
    require_csrf()
    try:
        project_id = int(request.form.get("project_id", ""))
    except ValueError:
        abort(400, "Invalid project.")
    kind = field("kind", 30, True)
    if kind not in {"Hostname", "URL", "IP address", "Other"}:
        abort(400, "Invalid asset type.")
    with connect() as db:
        if not db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
            abort(400, "Unknown project.")
        db.execute("INSERT INTO assets(project_id,value,kind,notes) VALUES(?,?,?,?)", (project_id, field("value", 500, True), kind, field("notes", 2000)))
    return redirect(url_for("index"))


@app.post("/findings")
@login_required
def add_finding():
    require_csrf()
    try:
        project_id = int(request.form.get("project_id", ""))
    except ValueError:
        abort(400, "Invalid project.")
    severity, status = field("severity", 20, True), field("status", 20, True)
    if severity not in {"Informational", "Low", "Medium", "High", "Critical"} or status not in {"Open", "Triaged", "Reported", "Resolved", "Informative"}:
        abort(400, "Invalid severity or status.")
    with connect() as db:
        if not db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
            abort(400, "Unknown project.")
        db.execute("INSERT INTO findings(project_id,title,severity,status,details) VALUES(?,?,?,?,?)", (project_id, field("title", 180, True), severity, status, field("details", 5000)))
    return redirect(url_for("index"))


@app.post("/delete/<table>/<int:item_id>")
@login_required
def delete_item(table: str, item_id: int):
    require_csrf()
    if table not in {"projects", "assets", "findings"}:
        abort(404)
    with connect() as db:
        db.execute(f"DELETE FROM {table} WHERE id=?", (item_id,))
    return redirect(url_for("index"))


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
