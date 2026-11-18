import pytest

from email_verify_guard import validate

BAD_VALUES = [
  "",
  "123456",
  "user-1000-1700000000",
  "alice@example.com:1000",
  "short",
  "aaaaaaaa",
  "123456789012345",
  "token\nX-Evil: 1",
  "token\r\n",
  "token\u0000",
  "UNIX-1700000000",
  "alice:1700000000",
  "verify-1",
  "0000000000000000",
  "token with space"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
