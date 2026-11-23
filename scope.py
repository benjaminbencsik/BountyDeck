"""Scope matching for recorded assets.

This is a bookkeeping aid: it tells you whether an asset you recorded matches the
scope text you wrote down for the project. It is NOT an authorization check, and
BountyDeck never uses it to launch anything.

Scope syntax (one rule per line, blank lines and "#" comments ignored):

    example.com          exact host only
    *.example.com        any subdomain of example.com (not the apex)
    10.0.0.0/24          IP address or CIDR range
    !admin.example.com   exclusion; always wins over an include rule
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

IN_SCOPE = "in-scope"
OUT_OF_SCOPE = "out-of-scope"
UNKNOWN = "unknown"


def normalize_host(value: str) -> str:
    """Reduce a hostname, URL or host:port to a lowercase host (or IP literal)."""
    value = value.strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = "//" + value
    try:
        host = urlsplit(value).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".")


def _parse_rules(scope_text: str) -> tuple[list[str], list[str]]:
    includes: list[str] = []
    excludes: list[str] = []
    for raw in scope_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            rule = line[1:].strip().lower()
            if rule:
                excludes.append(rule)
        else:
            includes.append(line.lower())
    return includes, excludes


def _as_ip(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _rule_matches(rule: str, host: str) -> bool:
    if "/" in rule:
        ip = _as_ip(host)
        if ip is None:
            return False
        try:
            return ip in ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return False
    rule_host = normalize_host(rule.lstrip("*.")) if rule.startswith("*.") else normalize_host(rule)
    if not rule_host:
        return False
    if rule.startswith("*."):
        return host.endswith("." + rule_host)
    return host == rule_host


def check_scope(value: str, scope_text: str) -> str:
    """Return IN_SCOPE, OUT_OF_SCOPE, or UNKNOWN (value has no usable host)."""
    host = normalize_host(value)
    if not host:
        return UNKNOWN
    includes, excludes = _parse_rules(scope_text)
    if any(_rule_matches(rule, host) for rule in excludes):
        return OUT_OF_SCOPE
    if any(_rule_matches(rule, host) for rule in includes):
        return IN_SCOPE
    return OUT_OF_SCOPE
