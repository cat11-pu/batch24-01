import pytest

from session_bind import check_binding

GOOD = {"ua": "Mozilla", "ip": "10.0.0.", "tls": "abc123"}

BAD_CASES = [
    ({}, GOOD),
    (None, GOOD),
    (GOOD, None),
    ("x", GOOD),
    (GOOD, "x"),
    ({"ua": "Other", "ip": "10.0.0.", "tls": "abc123"}, GOOD),
    ({"ua": "Mozilla", "ip": "10.0.1.", "tls": "abc123"}, GOOD),
    ({"ua": "Mozilla", "ip": "10.0.0.", "tls": "zzz"}, GOOD),
    ({"ua": "", "ip": "10.0.0.", "tls": "abc123"}, GOOD),
    ({"ua": "Mozilla", "ip": "", "tls": "abc123"}, GOOD),
    ({"ua": "Mozilla", "ip": "10.0.0.", "tls": ""}, GOOD),
    ({"ua": 123, "ip": "10.0.0.", "tls": "abc123"}, GOOD),
    ({"ua": "Mozilla", "ip": 123, "tls": "abc123"}, GOOD),
    ({"ua": "Mozilla", "ip": "10.0.0.", "tls": 123}, GOOD),
    ({"ua": " Mozilla", "ip": "10.0.0.", "tls": "abc123"}, GOOD),
]


@pytest.mark.parametrize("bound,current", BAD_CASES)
def test_session_binding_mismatch_is_rejected(bound, current):
    with pytest.raises(ValueError):
        check_binding(bound, current, ("ua", "ip", "tls"))
