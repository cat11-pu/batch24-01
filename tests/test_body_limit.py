import pytest

from body_limit import validate

BAD_VALUES = [
  0,
  -1,
  1048577,
  1000000000,
  1.5,
  True,
  False,
  "1024",
  None,
  [],
  {},
  9007199254740991,
  -9007199254740991,
  2097152,
  "1MiB"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
