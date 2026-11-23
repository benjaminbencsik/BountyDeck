from finding_payload import normalize_finding_payload


def valid_payload():
    return {
        "title": "Broken object ownership on profile export",
        "severity": "High",
        "details": "A low-privilege account can request another account's export object.",
        "evidence": "Two test accounts were used; account B's export ID returned account A's details.",
        "reproduction": "Create two accounts, obtain B's object ID, then request it while authenticated as A.",
        "impact": "An unauthorized account can retrieve confidential account information belonging to a victim.",
        "cwe": "CWE-639",
        "cvss": "7.5",
    }


def test_normalizes_payload():
    finding = normalize_finding_payload(valid_payload())
    assert finding["fingerprint"]
    assert finding["cwe"] == "CWE-639"


def test_missing_payload_field_is_rejected():
    payload = valid_payload()
    payload.pop("reproduction")
    try:
        normalize_finding_payload(payload)
    except ValueError:
        return
    raise AssertionError("Missing reproduction must be rejected")
