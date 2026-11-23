import json
import time

import pytest

SCOPE = "*.example.com\nexample.com\n!admin.example.com"


def make_project(db_module, enabled=True, ack=True, scope=SCOPE):
    with db_module.connect() as db:
        db.execute("INSERT INTO projects(name, authorized_scope, automation_enabled, automation_ack_at) VALUES(?,?,?,?)",
                   ("Acme", scope, int(enabled), time.time() if ack else None))
    return 1


class FakeTools:
    """Replaces hunter.run_tool and records every argv it is asked to run."""
    def __init__(self, nuclei_lines=()):
        self.calls, self.nuclei_lines = [], list(nuclei_lines)

    def __call__(self, argv, stdin_text=""):
        self.calls.append((argv, stdin_text))
        if argv[0] == "subfinder":
            return ["www.example.com", "admin.example.com", "evil.net", "-oX", "api.example.com"]
        if argv[0] == "assetfinder":
            return ["staging.example.com", "evil.net"]
        if argv[0] == "gau":
            return ["https://old.example.com/a?x=1", "https://evil.net/b"]
        if argv[0] == "waybackurls":
            return ["http://admin.example.com/x", "http://legacy.example.com/"]
        if argv[0] == "dnsx":
            return [h for h in stdin_text.split() if h != "legacy.example.com"]   # one name does not resolve
        if argv[0] == "httpx":
            return [json.dumps({"url": f"https://{h}"}) for h in stdin_text.split()] + [json.dumps({"url": "https://evil.net"})]
        if argv[0] == "nuclei":
            return self.nuclei_lines
        raise AssertionError(argv)


def nuclei(template, host, sev="high"):
    return json.dumps({"template-id": template, "matched-at": host, "info": {"name": f"Name {template}", "severity": sev}})


def test_only_in_scope_hosts_reach_tools(hunter_module, monkeypatch):
    import db
    make_project(db)
    fake = FakeTools([nuclei("t1", "https://www.example.com/x"), nuclei("t2", "https://evil.net/x")])
    monkeypatch.setattr(hunter_module, "run_tool", fake)
    hunter_module.run_project(1)

    fed = " ".join(stdin for _, stdin in fake.calls)
    for bad in ("evil.net", "admin.example.com", "-oX"):
        assert bad not in fed
    assert "www.example.com" in fed and "api.example.com" in fed
    with db.connect() as conn:
        titles = [r["title"] for r in conn.execute("SELECT title FROM findings")]
        statuses = {r["status"] for r in conn.execute("SELECT status FROM findings")}
        assets = {r["value"] for r in conn.execute("SELECT value FROM assets")}
    assert titles == ["Name t1 (t1)"] and statuses == {"Unverified"}
    assert assets == {"www.example.com", "api.example.com", "staging.example.com", "old.example.com"}


def test_passive_source_failure_does_not_fail_run(hunter_module, monkeypatch):
    import db
    make_project(db)
    fake = FakeTools()

    def flaky(argv, stdin_text=""):
        if argv[0] in ("assetfinder", "gau", "waybackurls", "dnsx"):
            raise hunter_module.ToolError(f"{argv[0]} is not installed in this container")
        return fake(argv, stdin_text)

    monkeypatch.setattr(hunter_module, "run_tool", flaky)
    hunter_module.run_project(1)
    with db.connect() as conn:
        assert conn.execute("SELECT status FROM hunt_runs").fetchone()["status"] == "completed"
        assert {r["value"] for r in conn.execute("SELECT value FROM assets")} == {"www.example.com", "api.example.com"}


def test_active_tools_are_not_allowed(hunter_module):
    for tool in ("katana", "naabu", "nmap", "ffuf", "dirsearch", "gowitness", "amass"):
        with pytest.raises(hunter_module.ToolError):
            hunter_module.run_tool([tool, "example.com"])


def test_findings_are_deduplicated_across_runs(hunter_module, monkeypatch):
    import db
    make_project(db)
    monkeypatch.setattr(hunter_module, "run_tool", FakeTools([nuclei("t1", "https://www.example.com/")]))
    hunter_module.run_project(1)
    hunter_module.run_project(1)
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1


@pytest.mark.parametrize("enabled,ack", [(False, True), (True, False)])
def test_disabled_or_unacknowledged_project_is_never_scanned(hunter_module, monkeypatch, enabled, ack):
    import db
    make_project(db, enabled=enabled, ack=ack)
    fake = FakeTools()
    monkeypatch.setattr(hunter_module, "run_tool", fake)
    assert hunter_module.due_projects() == []
    hunter_module.run_project(1)
    assert fake.calls == []


def test_disabling_mid_run_aborts(hunter_module, monkeypatch):
    import db
    make_project(db)

    class Disabling(FakeTools):
        def __call__(self, argv, stdin_text=""):
            out = super().__call__(argv, stdin_text)
            with db.connect() as conn:
                conn.execute("UPDATE projects SET automation_enabled=0")
            return out

    fake = Disabling()
    monkeypatch.setattr(hunter_module, "run_tool", fake)
    hunter_module.run_project(1)
    assert [a[0] for a, _ in fake.calls] == ["subfinder"]
    with db.connect() as conn:
        assert conn.execute("SELECT status FROM hunt_runs").fetchone()["status"] == "aborted"


def test_schedule_and_run_requested(hunter_module):
    import db
    make_project(db)
    assert hunter_module.due_projects() == [1]          # never ran
    with db.connect() as conn:
        conn.execute("UPDATE projects SET last_run_at=?", (time.time(),))
    assert hunter_module.due_projects() == []           # ran just now
    with db.connect() as conn:
        conn.execute("UPDATE projects SET run_requested=1")
    assert hunter_module.due_projects() == [1]          # run-now
    with db.connect() as conn:
        conn.execute("UPDATE projects SET run_requested=0, last_run_at=?", (time.time() - 25 * 3600,))
    assert hunter_module.due_projects() == [1]          # 24h elapsed


def test_tool_allowlist_and_target_validation(hunter_module):
    with pytest.raises(hunter_module.ToolError):
        hunter_module.run_tool(["nmap", "example.com"])
    with pytest.raises(hunter_module.ToolError):
        hunter_module.run_tool(["sh", "-c", "id"])
    assert not hunter_module.valid_target("-oX")
    assert not hunter_module.valid_target("a b.example.com")
    assert not hunter_module.valid_target("exa;mple.com")
    assert hunter_module.valid_target("api.example.com") and hunter_module.valid_target("10.0.0.1")


def test_tool_failure_is_logged_not_fatal(hunter_module, monkeypatch):
    import db
    make_project(db)
    def boom(argv, stdin_text=""):
        raise hunter_module.ToolError("subfinder is not installed in this container")
    monkeypatch.setattr(hunter_module, "run_tool", boom)
    hunter_module.run_project(1)
    with db.connect() as conn:
        row = conn.execute("SELECT status, log FROM hunt_runs").fetchone()
    assert row["status"] == "failed" and "not installed" in row["log"]
