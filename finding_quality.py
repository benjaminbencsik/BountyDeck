from __future__ import annotations

import hashlib
import re

SEVERITIES = {"Informational", "Low", "Medium", "High", "Critical"}
CWE_PATTERN = re.compile(r"^CWE-[0-9]{1,4}$", re.I)
CVSS_PATTERN = re.compile(r"^(?:10(?:\.0)?|[0-9](?:\.[0-9])?|0)$")


def validate_finding(title: str, severity: str, details: str,
                     evidence: str = "", cwe: str = "", cvss: str = "",
                     reproduction: str = "", impact: str = "") -> dict:
    """Validate report quality and return normalized metadata.

    This intentionally validates evidence and reporting completeness; it does not
    claim that a finding is exploitable or automatically verify a vulnerability.
    """
    title = title.strip()
    details = details.strip()
    evidence = evidence.strip()
    reproduction = reproduction.strip()
    impact = impact.strip()
    cwe = cwe.strip().upper()
    cvss = cvss.strip()

    if not 8 <= len(title) <= 180:
        raise ValueError("Finding title must contain 8 to 180 characters")
    if severity not in SEVERITIES:
        raise ValueError("Invalid finding severity")
    if len(details) < 20:
        raise ValueError("Finding details must explain the issue and affected context")
    if len(evidence) < 20:
        raise ValueError("Include reproducible, redacted evidence of at least 20 characters")
    if len(reproduction) < 20:
        raise ValueError("Include a reproducible test procedure of at least 20 characters")
    if len(impact) < 20:
        raise ValueError("Describe the concrete impact of at least 20 characters")
    if cwe and not CWE_PATTERN.fullmatch(cwe):
        raise ValueError("CWE must use format CWE-123")
    if cvss and not CVSS_PATTERN.fullmatch(cvss):
        raise ValueError("CVSS must be a numeric score from 0 to 10")

    fingerprint_source = "\n".join((title.casefold(), cwe, evidence[:1000]))
    return {
        "title": title,
        "severity": severity,
        "details": details,
        "evidence": evidence,
        "reproduction": reproduction,
        "impact": impact,
        "cwe": cwe,
        "cvss": cvss,
        "fingerprint": hashlib.sha256(fingerprint_source.encode()).hexdigest(),
    }
