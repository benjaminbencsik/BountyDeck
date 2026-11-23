from __future__ import annotations

from finding_quality import validate_finding


def test_complete_finding_is_normalized():
    finding = validate_finding(
        "Stored XSS in profile biography",
        "High",
        "A crafted payload is rendered on the victim profile without HTML encoding.",
        evidence="The response returned the supplied script text inside an element; victim session was tested.",
        reproduction="Save the payload in the authorized test account profile, then open the profile in an incognito session.",
        impact="An attacker could execute script in another user's session within the authorized application origin.",
        cwe="cwe-79",
        cvss="8.1",
    )
    assert finding["cwe"] == "CWE-79"
    assert len(finding["fingerprint"]) == 64


def test_incomplete_finding_is_rejected():
    try:
        validate_finding("XSS", "High", "short", evidence="none", reproduction="none", impact="none")
    except ValueError:
        return
    raise AssertionError("Incomplete finding should be rejected")
