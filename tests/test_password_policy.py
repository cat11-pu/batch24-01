import pytest

from password_policy import validate

BAD_VALUES = [
  "",
  "123456",
  "password",
  "qwerty",
  "111111",
  "abcdef",
  "alice123",
  "Alice123",
  "aaaaaaaa",
  "12345678",
  "password1",
  "letmein",
  "admin",
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "P@ssw0rd"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
