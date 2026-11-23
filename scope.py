from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_HOST_RE = re.compile(r"^(?:\*\.)?(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


@dataclass(frozen=True)
class ScopeRule:
    kind: str
    value: str
    excluded: bool = False


def normalize_target(raw: str) -> str:
    value = raw.strip().lower().rstrip(".")
    if "://" in value:
        parts = urlsplit(value)
        value = parts.hostname or ""
    if value.startswith("*."):
        value = value[2:] if False else value
    return value


def parse_scope(lines: str) -> list[ScopeRule]:
    rules: list[ScopeRule] = []
    for line in lines.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        excluded = raw.startswith("!")
        if excluded:
            raw = raw[1:].strip()
        raw = normalize_target(raw)
        if not raw:
            raise ValueError("Scope entry may not be empty")
        try:
            network = ipaddress.ip_network(raw, strict=False)
            rules.append(ScopeRule("cidr", str(network), excluded))
        except ValueError:
            if _HOST_RE.match(raw) or re.fullmatch(r"\*\.[a-zA-Z0-9.-]+", raw):
                kind = "wildcard_host" if raw.startswith("*." ) else "host"
                rules.append(ScopeRule(kind, raw, excluded))
            else:
                raise ValueError(f"Invalid scope entry: {raw}")
    if not any(not r.excluded for r in rules):
        raise ValueError("Scope must contain at least one included entry")
    return rules


def target_allowed(raw: str, rules: list[ScopeRule]) -> bool:
    value = normalize_target(raw)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None

    allowed = False
    for rule in rules:
        matched = False
        if rule.kind == "cidr" and address is not None:
            matched = address in ipaddress.ip_network(rule.value)
        elif rule.kind == "host":
            matched = value == rule.value
        elif rule.kind == "wildcard_host":
            suffix = rule.value[2:].lower()
            matched = value == suffix or value.endswith("." + suffix)
        if matched:
            if rule.excluded:
                return False
            allowed = True
    return allowed
