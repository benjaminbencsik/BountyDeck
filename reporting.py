from __future__ import annotations

import csv
import io

from bug_types import test_categories


def export_test_plan_csv() -> str:
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["id", "name", "risk", "checks"])
    for item in test_categories():
        writer.writerow([item["id"], item["name"], item["risk"], "; ".join(item["checks"])])
    return stream.getvalue()
