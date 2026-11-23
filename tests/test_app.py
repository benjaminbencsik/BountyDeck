import json
import time


def test_login_required(app_module):
    r = app_module.app.test_client().get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_csp_blocks_inline_script(client):
    csp = client.c.get("/").headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp


def test_login_lockout(app_module):
    from conftest import Client
    c = Client(app_module.app.test_client())
    for _ in range(app_module.LOGIN_MAX_FAILURES):
        assert c.login("wrong-password-123").status_code == 401
    assert c.login("correct-horse-battery-staple").status_code == 429


def test_rejects_javascript_url(client):
    r = client.post("/projects", name="p", program_url="javascript:alert(1)", authorized_scope="example.com")
    assert r.status_code == 400


def create_project(client, scope="example.com\n*.example.com\n!admin.example.com"):
    r = client.post("/projects", name="Acme", program_url="https://acme.test/policy",
                    authorized_scope=scope, authorization_notes="")
    assert r.status_code == 302


def test_asset_scope_badge_and_warning(client):
    create_project(client)
    client.post("/assets", project_id="1", value="api.example.com", kind="Hostname", notes="")
    r = client.post("/assets", project_id="1", value="other.net", kind="Hostname", notes="")
    page = client.c.get("/").get_data(as_text=True)
    assert 'badge in-scope' in page and 'badge out-of-scope' in page
    assert "does not match this project" in page


def test_finding_status_update_and_export(client):
    create_project(client)
    client.post("/findings", project_id="1", title="XSS | reflected", severity="High", status="Open", details="d")
    # Verified / False positive need an explanation of how the result was confirmed.
    assert client.post("/findings/1/status", status="False positive").status_code == 400
    assert client.post("/findings/1/status", status="False positive", verification_notes="short").status_code == 400
    assert client.post("/findings/1/status", status="False positive",
                       verification_notes="Replayed request manually; payload is HTML-encoded in response.").status_code == 302
    assert client.post("/findings/1/status", status="Bogus").status_code == 400
    data = json.loads(client.c.get("/projects/1/export.json").get_data(as_text=True))
    assert data["findings"][0]["status"] == "False positive"
    md = client.c.get("/projects/1/export.md")
    assert md.status_code == 200 and "attachment" in md.headers["Content-Disposition"]
    assert client.c.get("/projects/1/export.exe").status_code == 404


def test_html_is_escaped(client):
    create_project(client)
    client.post("/findings", project_id="1", title="<script>alert(1)</script>", severity="Low", status="Open", details="")
    assert "<script>alert(1)</script>" not in client.c.get("/").get_data(as_text=True)


def test_automation_requires_acknowledgement(client, app_module):
    create_project(client)
    assert client.post("/projects/1/automation", action="enable", schedule_hours="24").status_code == 400
    assert client.post("/projects/1/automation", action="enable", schedule_hours="24", acknowledge="yes").status_code == 302
    with app_module.connect() as db:
        row = db.execute("SELECT automation_enabled, automation_ack_at FROM projects").fetchone()
    assert row["automation_enabled"] == 1 and row["automation_ack_at"]
    assert client.post("/projects/1/run-now").status_code == 302
    client.post("/projects/1/automation", action="disable")
    assert client.post("/projects/1/run-now").status_code == 400


def test_update_check_reports_newer_commit(client, app_module, monkeypatch):
    monkeypatch.setattr(app_module, "fetch_latest_commit",
                        lambda: {"sha": "a" * 40, "message": "New stuff", "date": "2026-01-01"})
    monkeypatch.setattr(app_module, "VERSION", "b" * 40)
    page = client.post("/update/check").get_data(as_text=True)
    assert "Update available" in page and "./update.sh" in page
    monkeypatch.setattr(app_module, "VERSION", "a" * 40)
    assert "up to date" in client.post("/update/check").get_data(as_text=True)


def test_verified_only_report(client):
    create_project(client)
    client.post("/findings", project_id="1", title="Unconfirmed thing", severity="Low", status="Unverified", details="")
    client.post("/findings", project_id="1", title="Real thing", severity="High", status="Open", details="")
    client.post("/findings/2/status", status="Verified", verification_notes="Reproduced with curl, see request 12.")
    full = client.c.get("/projects/1/export.md").get_data(as_text=True)
    only = client.c.get("/projects/1/export.md?verified=1").get_data(as_text=True)
    assert "Unconfirmed thing" in full and "Real thing" in full
    assert "Real thing" in only and "Unconfirmed thing" not in only
    assert "Reproduced with curl" in only
