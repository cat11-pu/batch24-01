import pytest

from backup_code_guard import validate

BAD_VALUES = [
  [
    0,
    "123456"
  ],
  [
    5,
    "123456"
  ],
  [
    6,
    "123456"
  ],
  [
    100,
    "123456"
  ],
  [
    -1,
    "123456"
  ],
  [
    1,
    ""
  ],
  [
    1,
    "12345"
  ],
  [
    1,
    "1234567"
  ],
  [
    1,
    "abcdef"
  ],
  [
    1,
    123456
  ],
  [
    1,
    "123456\n"
  ],
  [
    1,
    "123456\u0000"
  ],
  [
    1,
    " 123456"
  ],
  [
    1,
    "123456 "
  ],
  [
    1,
    "000000"
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
