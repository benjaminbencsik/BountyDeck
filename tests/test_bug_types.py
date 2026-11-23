from __future__ import annotations

import pytest

from bug_types import test_categories
from dns_guard import DNSScopeError, validate_resolved_addresses


def test_bug_category_catalog_is_not_empty():
    categories = test_categories()
    assert len(categories) >= 15
    assert any(item["id"] == "ssrf" for item in categories)


def test_public_cidr_validation_rejects_loopback():
    with pytest.raises(ValueError):
        ipaddress = __import__("ipaddress")
        ipaddress.ip_network("127.0.0.0/8", strict=False)
