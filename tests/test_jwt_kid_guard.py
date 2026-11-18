import pytest

from jwt_kid_guard import validate

BAD_VALUES = [
  "../../etc/passwd",
  "../keys/secret",
  "/etc/passwd",
  "C:\\keys\\secret",
  "keys/../../etc/passwd",
  "key\u0000id",
  "",
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "key id",
  "key/id",
  "key\\id",
  "..%2f..%2fetc%2fpasswd",
  "%2e%2e%2fsecret",
  "key..id",
  "KEY-ID"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
