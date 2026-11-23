from __future__ import annotations

from finding_quality import validate_finding


def normalize_finding_payload(payload: dict) -> dict:
    """Normalize a submitted finding for review and duplicate detection."""
    return validate_finding(
        title=payload.get("title", ""),
        severity=payload.get("severity", ""),
        details=payload.get("details", ""),
        evidence=payload.get("evidence", ""),
        reproduction=payload.get("reproduction", ""),
        impact=payload.get("impact", ""),
        cwe=payload.get("cwe", ""),
        cvss=payload.get("cvss", ""),
    )
