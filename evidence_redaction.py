from __future__ import annotations

import re

REDACTION_RULES = (
    (re.compile(r"(?i)(authorization|cookie|x-api-key|api[_-]?key|token)\s*[:=]\s*[^\s,;]+"), r"\1=<redacted>"),
    (re.compile(r"(?i)(bearer\s+)[a-z0-9._~+/-]+=*"), r"\1<redacted>"),
    (re.compile(r"(?<![\w@])(?:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)(?![\w@])"), "<redacted-email>"),
    (re.compile(r"(?<![\w])(?:\b(?:\d{1,3}\.){3}\d{1,3}\b)(?![\w])"), "<redacted-ip>"),
    (re.compile(r"(?i)(password|passwd|secret|client_secret)\s*[=:]\s*[^\s,&]+"), r"\1=<redacted>"),
)


def redact_sensitive_text(text: str) -> str:
    """Best-effort redaction for evidence before storage or sharing."""
    redacted = text
    for pattern, replacement in REDACTION_RULES:
        redacted = pattern.sub(replacement, redacted)
    return redacted
