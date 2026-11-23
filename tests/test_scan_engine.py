from __future__ import annotations

import pytest

from scan_engine import build_dry_run


def test_passive_dry_run_is_scoped():
    plan = build_dry_run("passive", "example.com", ["example.com"], ["dig"])
    assert plan["targets"] == ["example.com"]


def test_dry_run_blocks_out_of_scope():
    with pytest.raises(PermissionError):
        build_dry_run("passive", "example.com", ["evil.example"], ["dig"])


def test_intrusive_profile_is_blocked():
    with pytest.raises(PermissionError):
        build_dry_run("intrusive", "example.com", ["example.com"], ["nuclei"])
