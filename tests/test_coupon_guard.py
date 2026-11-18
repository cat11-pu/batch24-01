import pytest

from coupon_guard import validate

BAD_VALUES = [
  [
    0,
    1,
    1000
  ],
  [
    1,
    1,
    1000
  ],
  [
    5,
    1,
    1000
  ],
  [
    -1,
    1,
    1000
  ],
  [
    1,
    0,
    1000
  ],
  [
    1,
    -1,
    1000
  ],
  [
    1,
    1,
    -1
  ],
  [
    1,
    1,
    0
  ],
  [
    "1",
    1,
    1000
  ],
  [
    1,
    "1",
    1000
  ],
  [
    1,
    1,
    "1000"
  ],
  [
    True,
    1,
    1000
  ],
  [
    1,
    True,
    1000
  ],
  [
    1,
    1,
    1.5
  ],
  [
    1,
    1,
    None
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
