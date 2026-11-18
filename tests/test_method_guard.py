import pytest

from method_guard import resolve_method

ALLOWED = {"GET", "POST"}

BAD_CASES = [
    ("GET ", None),
    ("get", None),
    ("", None),
    (None, None),
    (123, None),
    ("GE T", None),
    ("GET\n", None),
    ("GET\x00", None),
    ("DELETE", None),
    ("TRACE", None),
    ("CONNECT", None),
    ("HEAD", None),
    ("GET", "DELETE"),
    ("POST", "TRACE"),
    ("GET", ""),
]


@pytest.mark.parametrize("method,override", BAD_CASES)
def test_bad_method_is_rejected(method, override):
    with pytest.raises(ValueError):
        resolve_method(method, override, ALLOWED)
