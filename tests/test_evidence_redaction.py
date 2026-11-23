from evidence_redaction import redact_sensitive_text


def test_redacts_authorization_header():
    evidence = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
    redacted = redact_sensitive_text(evidence)
    assert "eyJhbGci" not in redacted
    assert "<redacted>" in redacted


def test_redacts_email():
    assert "<redacted-email>" not in "example.com"
    redacted = redact_sensitive_text("Contact tester@example.com for access")
    assert "tester@example.com" not in redacted
    assert "<redacted-email>" in redacted


def test_preserves_unrelated_text():
    evidence = "The profile returned HTTP 200 and did not enforce object ownership."
    assert redact_sensitive_text(evidence) == evidence
