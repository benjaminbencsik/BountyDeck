from finding_triage import FALSE_POSITIVE_CAUSES, VALID_REPORT_STATES, review_decision


def test_review_defaults_to_manual_verification():
    result = review_decision()
    assert result == {
        "state": "Needs review",
        "cause": "",
        "human_review_required": True,
    }


def test_false_positive_cause_is_known():
    result = review_decision("scanner-alert-only")
    assert result["state"] == "False positive"
    assert "scanner-alert-only" in FALSE_POSITIVE_CAUSES
    assert "Confirmed" in VALID_REPORT_STATES


def test_unknown_false_positive_cause_is_rejected():
    try:
        review_decision("made-up-cause")
    except ValueError:
        return
    raise AssertionError("Unknown false-positive causes must be rejected")
