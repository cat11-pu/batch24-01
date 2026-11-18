import pytest

from zip_bomb_guard import validate

BAD_VALUES = [
  [
    1,
    1000,
    1
  ],
  [
    1,
    100000000,
    1
  ],
  [
    100,
    1000000000,
    1
  ],
  [
    1000,
    1000,
    100000
  ],
  [
    0,
    0,
    0
  ],
  [
    -1,
    100,
    1
  ],
  [
    1,
    -1,
    1
  ],
  [
    1,
    100,
    -1
  ],
  [
    1,
    100,
    1,
    2
  ],
  [
    1,
    1000000000,
    1
  ],
  [
    1,
    1,
    1000000
  ],
  [
    1,
    100,
    1
  ],
  [
    100,
    100000,
    10000
  ],
  [
    1,
    10000000,
    1
  ],
  [
    0,
    1,
    1
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
