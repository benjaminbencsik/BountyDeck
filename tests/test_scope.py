from __future__ import annotations

import pytest

from scope import parse_scope, target_allowed


def test_exact_domain():
    rules = parse_scope("example.com")
    assert target_allowed("example.com", rules)
    assert not target_allowed("evil.example", rules)


def test_wildcard_and_exclusion():
    rules = parse_scope("*.example.com\n!excluded.example.com")
    assert target_allowed("api.example.com", rules)
    assert not target_allowed("excluded.example.com", rules)
    assert not target_allowed("example.net", rules)


def test_cidr_and_exclusion():
    rules = parse_scope("192.0.2.0/24\n!192.0.2.100")
    assert target_allowed("192.0.2.10", rules)
    assert not target_allowed("192.0.2.100", rules)
    assert not target_allowed("198.51.100.1", rules)


def test_requires_included_scope():
    with pytest.raises(ValueError):
        parse_scope("!example.com")


def test_rejects_invalid_scheme_and_localhost():
    with pytest.raises(ValueError):
        parse_scope("http://example.com")
    with pytest.raises(ValueError):
        parse_scope("localhost")
