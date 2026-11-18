import pytest

from csp_guard import validate

BAD_VALUES = [
  "",
  "abc",
  "123456",
  "aaaaaaaa",
  "nonce",
  "static",
  "AAAAAAAA",
  "0000000000000000",
  "test",
  "None",
  "undefined",
  "a\nb",
  "a\u0000b",
  "a b",
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
