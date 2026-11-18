import pytest

from client_key_guard import validate

BAD_VALUES = [
  "",
  "unknown",
  "1.2.3.4, 5.6.7.8",
  "1.2.3.4,",
  ",1.2.3.4",
  "1.2.3.4\r\n",
  "1.2.3.4\u0000",
  "999.999.999.999",
  "::1",
  "[::1]",
  "1.2.3.4:80",
  "1.2.3.4 ",
  " 1.2.3.4",
  "1.2.3.4, evil",
  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
