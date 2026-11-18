import pytest

from ip_allow_guard import validate

BAD_VALUES = [
  "10.0.0.1",
  "10.0.0.10",
  "10.0.0.100",
  "10.0.0.1/8",
  "010.000.000.001",
  "10.0.0.1\n",
  "10.0.0.1\u0000",
  "10.0.0.1 ",
  " 10.0.0.1",
  "10.0.0.1:80",
  "0x0a000001",
  "167772161",
  "::ffff:10.0.0.1",
  "10.0.0.1,10.0.0.2",
  "999.0.0.1"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
