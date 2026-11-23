from __future__ import annotations

FALSE_POSITIVE_CAUSES = (
    "scanner-alert-only",
    "theoretical-code-path",
    "expected-behavior",
    "missing-impact-demonstration",
    "staging-only-context",
    "stale-or-duplicate-finding",
    "unverified-data-source",
    "test-data-contamination",
    "out-of-scope-target",
)

VALID_REPORT_STATES = (
    "Needs review",
    "Confirmed",
    "Duplicate",
    "Informative",
    "False positive",
)


def review_decision(cause: str | None = None) -> dict:
    """Normalize the manual report triage decision."""
    if cause and cause not in FALSE_POSITIVE_CAUSES:
        raise ValueError("Unknown false-positive cause")
    return {
        "state": "False positive" if cause else "Needs review",
        "cause": cause or "",
        "human_review_required": True,
    }
