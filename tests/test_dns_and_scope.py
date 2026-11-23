from __future__ import annotations

import ipaddress

from scope import parse_scope


def validate_cidr_allowlist(value: str) -> str:
    network = ipaddress.ip_network(value, strict=False)
    if network.is_private or network.is_loopback or network.is_link_local or network.is_reserved:
        raise ValueError("Only explicitly approved public CIDR ranges may be included")
    return str(network)


def scope_report(scope_text: str) -> dict:
    rules = parse_scope(scope_text)
    return {
        "rule_count": len(rules),
        "included": [rule.value for rule in rules if not rule.excluded],
        "excluded": [rule.value for rule in rules if rule.excluded],
    }
