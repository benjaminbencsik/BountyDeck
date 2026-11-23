from scope import IN_SCOPE, OUT_OF_SCOPE, UNKNOWN, check_scope, normalize_host

SCOPE = "example.com\n*.example.com\n10.0.0.0/24\n!admin.example.com\n# comment\n"


def test_exact_and_apex():
    assert check_scope("example.com", SCOPE) == IN_SCOPE
    assert check_scope("https://EXAMPLE.com/path?q=1", SCOPE) == IN_SCOPE


def test_wildcard_matches_subdomains_only():
    assert check_scope("api.example.com", SCOPE) == IN_SCOPE
    assert check_scope("a.b.example.com:8443", SCOPE) == IN_SCOPE
    assert check_scope("example.com", "*.example.com") == OUT_OF_SCOPE


def test_lookalikes_are_out():
    assert check_scope("evilexample.com", SCOPE) == OUT_OF_SCOPE
    assert check_scope("example.com.evil.net", SCOPE) == OUT_OF_SCOPE


def test_exclusion_wins():
    assert check_scope("admin.example.com", SCOPE) == OUT_OF_SCOPE
    assert check_scope("https://admin.example.com/x", SCOPE) == OUT_OF_SCOPE


def test_cidr():
    assert check_scope("10.0.0.7", SCOPE) == IN_SCOPE
    assert check_scope("10.0.1.7", SCOPE) == OUT_OF_SCOPE


def test_unknown_for_garbage():
    assert check_scope("", SCOPE) == UNKNOWN
    assert normalize_host("http://[::1]:80/") == "::1"


def test_empty_scope_denies_everything():
    assert check_scope("example.com", "") == OUT_OF_SCOPE
