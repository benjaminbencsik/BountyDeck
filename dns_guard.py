from __future__ import annotations

import ipaddress
import socket


class DNSScopeError(ValueError):
    pass


def resolve_host(host: str) -> list[str]:
    """Resolve a host and return unique numeric addresses."""
    infos = socket.getaddrinfo(host, None, type=socket.SocketKind.SOCK_STREAM)
    addresses = sorted({item[4][0] for item in infos})
    if not addresses:
        raise DNSScopeError("Host resolved to no addresses")
    return addresses


def validate_resolved_addresses(host: str, allowed_networks: list[str] | None = None) -> list[str]:
    """
    Reject addresses that are private, loopback, link-local, reserved, multicast,
    unspecified, or otherwise unsuitable for public target testing.

    Pass allowed_networks only for explicitly authorized program CIDR ranges.
    """
    addresses = resolve_host(host)
    approved_networks = [ipaddress.ip_network(value, strict=False) for value in (allowed_networks or [])]

    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified or ip.is_multicast:
            raise DNSScopeError(f"Resolved address {address} is not a public testing destination")
        if approved_networks and not any(ip in network for network in approved_networks):
            raise DNSScopeError(f"Resolved address {address} is outside approved CIDR ranges")
    return addresses
