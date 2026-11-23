from __future__ import annotations

import pytest

from reporting import export_test_plan_csv
from test_planner import build_test_plan


def test_build_test_plan():
    plan = build_test_plan(["broken-access-control", "ssrf"])
    assert plan["category_count"] == 2


def test_build_test_plan_rejects_unknown_category():
    with pytest.raises(ValueError):
        build_test_plan(["not-a-category"])


def test_csv_export():
    csv_text = export_test_plan_csv()
    assert "broken-access-control" in csv_text
    assert "ssrf" in csv_text
