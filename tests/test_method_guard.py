import pytest

from method_guard import validate

BAD_VALUES = [
  "TRACE",
  "CONNECT",
  "DELETE",
  "PUT",
  "PATCH",
  "HEAD",
  "OPTIONS",
  "get",
  "POST\r\n",
  "",
  "G ET",
  "GET\u0000",
  "X-HTTP-Method-Override: DELETE",
  "GET /admin",
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
