import pytest

from pagination_guard import validate

BAD_VALUES = [
  [
    0,
    0
  ],
  [
    1,
    -1
  ],
  [
    201,
    0
  ],
  [
    1000000000,
    0
  ],
  [
    "10",
    0
  ],
  [
    True,
    0
  ],
  [
    10,
    1.5
  ],
  [
    None,
    0
  ],
  [
    10,
    None
  ],
  [
    10,
    100000001
  ],
  [
    -1,
    0
  ],
  [
    1,
    100000000
  ],
  [
    1,
    True
  ],
  [
    1000000000,
    1000000000
  ],
  [
    1,
    2,
    3
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
