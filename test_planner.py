from __future__ import annotations

import json

from bug_types import test_categories


def build_test_plan(categories: list[str] | None = None) -> dict:
    catalog = {item["id"]: item for item in test_categories()}
    selected = categories or list(catalog)
    unknown = sorted(set(selected) - set(catalog))
    if unknown:
        raise ValueError("Unknown test categories: " + ", ".join(unknown))
    return {
        "categories": [catalog[item] for item in selected],
        "category_count": len(selected),
    }
