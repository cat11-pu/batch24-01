import pytest

from csv_guard import validate

BAD_VALUES = [
  "=cmd|' /C calc'!A0",
  "+cmd",
  "-2+3",
  "@SUM(A1)",
  "\t=cmd",
  "\r=cmd",
  "\n=cmd",
  " =cmd",
  "\u0000=cmd",
  "=1+1",
  "=HYPERLINK(\"http://evil\")",
  "+cmd|' /C calc'!A0",
  "-cmd",
  "@cmd",
  "=cmd\u0000"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
