"""Scheduled, scope-enforced hunting service.

Runs as a separate container (compose profile "hunter"). For every project that
you have explicitly enabled automation on, it periodically:

  1. discovers subdomains of the project's wildcard scope rules   (subfinder)
  2. probes in-scope hosts for live web servers                   (httpx)
  3. runs low-impact vulnerability templates against live URLs    (nuclei)

Guardrails, all enforced here in code and not only in the UI:

  * A project is only ever touched if automation_enabled=1 AND you ticked the
    authorization acknowledgement (automation_ack_at is set). Both are re-checked
    between stages, so disabling a project stops it at the next stage.
  * Every host is matched against the project's scope rules (scope.check_scope,
    "!" exclusions win) before it is handed to ANY tool, including hosts that a
    tool discovered itself. Anything out of scope is dropped and logged.
  * Only subfinder, httpx and nuclei are ever run, with fixed argument lists (no
    shell), a request-rate cap, and intrusive nuclei templates excluded.
  * Results are stored as status "Unverified". Scanner output is frequently a false
    positive: confirm each one by hand before reporting it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.request
from typing import Any, Iterable

from db import SEVERITIES, connect, init_db
from scope import IN_SCOPE, check_scope, normalize_host

log = logging.getLogger("hunter")

TICK_SECONDS = int(os.environ.get("BOUNTYDECK_HUNT_TICK", "60"))
RATE_LIMIT = str(int(os.environ.get("BOUNTYDECK_HUNT_RATE", "10")))  # requests/second, per tool
TOOL_TIMEOUT = int(os.environ.get("BOUNTYDECK_HUNT_TOOL_TIMEOUT", "3600"))
MAX_TARGETS = int(os.environ.get("BOUNTYDECK_HUNT_MAX_TARGETS", "500"))
WEBHOOK_URL = os.environ.get("BOUNTYDECK_WEBHOOK_URL", "")

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
NUCLEI_EXCLUDE_TAGS = "dos,fuzz,intrusive,bruteforce,brute-force"
SEVERITY_MAP = {"info": "Informational", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
# Nuclei "info" templates are mostly fingerprinting noise; hunt medium and above.
NUCLEI_SEVERITIES = "medium,high,critical"

_stop = False


class ToolError(RuntimeError):
    pass


class Aborted(RuntimeError):
    """Raised when automation was switched off while a run was in progress."""


# --------------------------------------------------------------------------- target hygiene

def valid_target(host: str) -> bool:
    """True only for plain hostnames / IP literals. Rejects anything that could be a CLI flag."""
    if not host or host.startswith("-"):
        return False
    if HOST_RE.match(host):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def wildcard_roots(scope_text: str) -> list[str]:
    roots = []
    for raw in scope_text.splitlines():
        line = raw.strip().lower()
        if line.startswith("*."):
            root = normalize_host(line[2:])
            if root and HOST_RE.match(root) and root not in roots:
                roots.append(root)
    return roots


def keep_in_scope(candidates: Iterable[str], scope_text: str, logf, what: str) -> list[str]:
    kept: list[str] = []
    dropped = 0
    for raw in candidates:
        host = normalize_host(raw)
        if not valid_target(host):
            dropped += 1
            continue
        if check_scope(host, scope_text) != IN_SCOPE:
            dropped += 1
            continue
        if host not in kept:
            kept.append(host)
    if dropped:
        logf(f"{what}: dropped {dropped} out-of-scope or invalid entries")
    return kept


# --------------------------------------------------------------------------- tool execution

def run_tool(argv: list[str], stdin_text: str = "") -> list[str]:
    """Run one allow-listed tool without a shell and return its stdout lines."""
    if argv[0] not in ("subfinder", "httpx", "nuclei"):
        raise ToolError(f"tool not allowed: {argv[0]}")
    if shutil.which(argv[0]) is None:
        raise ToolError(f"{argv[0]} is not installed in this container")
    try:
        proc = subprocess.run(argv, input=stdin_text, capture_output=True, text=True,
                              timeout=TOOL_TIMEOUT, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"{argv[0]} timed out after {TOOL_TIMEOUT}s") from exc
    if proc.returncode != 0:
        tail = proc.stderr.strip().splitlines()[-3:]
        raise ToolError(f"{argv[0]} exited {proc.returncode}: {' | '.join(tail)}")
    return proc.stdout.splitlines()[:50000]


def discover_subdomains(roots: list[str], scope_text: str, logf) -> list[str]:
    found: list[str] = []
    for root in roots:
        if root and valid_target(root):
            lines = run_tool(["subfinder", "-d", root, "-silent"])
            found += keep_in_scope(lines, scope_text, logf, f"subfinder {root}")
    return found


def probe_live(hosts: list[str], scope_text: str, logf) -> list[str]:
    if not hosts:
        return []
    lines = run_tool(["httpx", "-silent", "-json", "-rl", RATE_LIMIT, "-timeout", "10", "-retries", "1"],
                     "\n".join(hosts) + "\n")
    urls: list[str] = []
    for line in lines:
        try:
            url = json.loads(line).get("url", "")
        except json.JSONDecodeError:
            continue
        if url.startswith(("http://", "https://")) and check_scope(url, scope_text) == IN_SCOPE and url not in urls:
            urls.append(url)
    return urls


def scan_urls(urls: list[str], scope_text: str, logf) -> list[dict[str, str]]:
    if not urls:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".txt") as fh:
        fh.write("\n".join(urls) + "\n")
        fh.flush()
        lines = run_tool(["nuclei", "-l", fh.name, "-severity", NUCLEI_SEVERITIES,
                          "-exclude-tags", NUCLEI_EXCLUDE_TAGS, "-rl", RATE_LIMIT, "-c", "10",
                          "-timeout", "10", "-retries", "1", "-ni", "-duc", "-jsonl", "-silent"])
    results: list[dict[str, str]] = []
    out_of_scope = 0
    for line in lines:
        try:
            item = json.loads(line)
            template = str(item["template-id"])
            matched = str(item.get("matched-at") or item.get("host") or "")
            name = str(item["info"]["name"])
            severity = SEVERITY_MAP.get(str(item["info"].get("severity", "")).lower())
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        if severity not in SEVERITIES:
            continue
        if check_scope(matched, scope_text) != IN_SCOPE:
            out_of_scope += 1
            continue
        results.append({"template": template, "name": name, "severity": severity, "matched": matched})
    if out_of_scope:
        logf(f"nuclei: dropped {out_of_scope} results outside scope")
    return results


# --------------------------------------------------------------------------- persistence

def save_assets(project_id: int, hosts: list[str], source: str) -> int:
    added = 0
    with connect() as db:
        known = {r["value"].lower() for r in db.execute("SELECT value FROM assets WHERE project_id=?", (project_id,))}
        for host in hosts:
            if host.lower() not in known:
                db.execute("INSERT INTO assets(project_id,value,kind,notes) VALUES(?,?,?,?)",
                           (project_id, host, "Hostname", f"Discovered by {source}"))
                known.add(host.lower())
                added += 1
    return added


def save_findings(project_id: int, results: list[dict[str, str]]) -> list[dict[str, str]]:
    """Insert new findings (deduplicated); returns only the ones that were new."""
    new: list[dict[str, str]] = []
    with connect() as db:
        for r in results:
            key = hashlib.sha256(f"{r['template']}|{r['matched']}".encode()).hexdigest()
            details = (f"Matched at: {r['matched']}\nTemplate: {r['template']}\n\n"
                       "Automated nuclei result - NOT verified. Reproduce it manually and rule out a "
                       "false positive before reporting.")
            cur = db.execute(
                "INSERT OR IGNORE INTO findings(project_id,title,severity,status,details,dedupe_key) "
                "VALUES(?,?,?,?,?,?)",
                (project_id, f"{r['name']} ({r['template']})", r["severity"], "Unverified", details, key))
            if cur.rowcount:
                new.append(r)
    return new


def still_enabled(project_id: int) -> bool:
    with connect() as db:
        row = db.execute("SELECT automation_enabled, automation_ack_at FROM projects WHERE id=?",
                         (project_id,)).fetchone()
    return bool(row and row["automation_enabled"] and row["automation_ack_at"])


def notify(project_name: str, new: list[dict[str, str]], status: str, new_assets: int = 0) -> None:
    if not WEBHOOK_URL.startswith("https://"):
        return
    titles = "; ".join(f"[{r['severity']}] {r['name']}" for r in new[:5])
    text = (f"BountyDeck hunt on {project_name}: {status}, {new_assets} new in-scope asset(s), "
            f"{len(new)} new unverified finding(s)." + (f" {titles}" if titles else ""))
    body = json.dumps({"content": text, "text": text}).encode()
    req = urllib.request.Request(WEBHOOK_URL, data=body, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10).close()  # noqa: S310 - https enforced above
    except Exception as exc:  # notification failure must never fail a run
        log.warning("webhook failed: %s", exc)


# --------------------------------------------------------------------------- orchestration

def run_project(project_id: int) -> None:
    with connect() as db:
        project = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if not project or not still_enabled(project_id):
            return
        run_id = db.execute("INSERT INTO hunt_runs(project_id, started_at) VALUES(?,?)",
                            (project_id, time.time())).lastrowid
        db.execute("UPDATE projects SET run_requested=0, last_run_at=? WHERE id=?", (time.time(), project_id))

    lines: list[str] = []

    def logf(msg: str) -> None:
        log.info("[%s] %s", project["name"], msg)
        lines.append(f"{time.strftime('%H:%M:%S')} {msg}")

    def checkpoint() -> None:
        if _stop or not still_enabled(project_id):
            raise Aborted("automation disabled or service stopping")

    scope_text = project["authorized_scope"]
    status, new, added = "completed", [], 0
    try:
        checkpoint()
        roots = wildcard_roots(scope_text)
        discovered = discover_subdomains(roots, scope_text, logf) if roots else []
        added = save_assets(project_id, discovered[:MAX_TARGETS], "subfinder") if discovered else 0
        logf(f"discovery: {len(discovered)} in-scope hosts, {added} new assets")

        checkpoint()
        with connect() as db:
            recorded = [r["value"] for r in db.execute("SELECT value FROM assets WHERE project_id=?", (project_id,))]
        targets = keep_in_scope(recorded + discovered, scope_text, logf, "targets")[:MAX_TARGETS]
        logf(f"{len(targets)} in-scope targets selected")

        checkpoint()
        urls = probe_live(targets, scope_text, logf)
        logf(f"httpx: {len(urls)} live in-scope URLs")

        checkpoint()
        results = scan_urls(urls, scope_text, logf)
        new = save_findings(project_id, results)
        logf(f"nuclei: {len(results)} results, {len(new)} new unverified findings")
    except Aborted as exc:
        status = "aborted"
        logf(f"aborted: {exc}")
    except ToolError as exc:
        status = "failed"
        logf(f"failed: {exc}")
    except Exception as exc:  # keep the service alive whatever happens
        status = "failed"
        log.exception("run crashed")
        logf(f"crashed: {type(exc).__name__}: {exc}")

    with connect() as db:
        db.execute("UPDATE hunt_runs SET finished_at=?, status=?, log=? WHERE id=?",
                   (time.time(), status, "\n".join(lines)[-8000:], run_id))
    notify(project["name"], new, status, added)


def due_projects() -> list[int]:
    now = time.time()
    with connect() as db:
        rows = db.execute(
            "SELECT id FROM projects WHERE automation_enabled=1 AND automation_ack_at IS NOT NULL AND ("
            "run_requested=1 OR last_run_at IS NULL OR last_run_at + schedule_hours*3600 <= ?) ORDER BY id",
            (now,)).fetchall()
    return [r["id"] for r in rows]


def recover_interrupted() -> None:
    with connect() as db:
        db.execute("UPDATE hunt_runs SET status='interrupted', finished_at=? WHERE status='running'", (time.time(),))


def _handle_signal(signum: int, _frame: Any) -> None:
    global _stop
    _stop = True


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    init_db()
    recover_interrupted()
    log.info("hunter started; tick=%ss rate=%s req/s", TICK_SECONDS, RATE_LIMIT)
    while not _stop:
        for project_id in due_projects():
            if _stop:
                break
            run_project(project_id)
        for _ in range(TICK_SECONDS):
            if _stop:
                break
            time.sleep(1)
    log.info("hunter stopped")


if __name__ == "__main__":
    main()
