import pytest

from login_response import respond

BAD_CASES = [
    (False, False, False),
    (False, True, False),
    (False, False, True),
    (True, False, False),
    (True, False, True),
    (True, True, True),
    (True, True, False),
    ("", False, False),
    (None, False, False),
    (1, False, False),
    (True, 0, False),
    (True, None, False),
    (True, False, "yes"),
    (True, False, 1),
    (True, False, None),
]


@pytest.mark.parametrize("value", BAD_CASES)
def test_login_failures_are_generic(value):
    with pytest.raises((ValueError, TypeError)):
        assert respond(*value) == "invalid credentials"
