import pytest

from otp_resend_guard import validate

BAD_VALUES = [
  [
    0,
    0
  ],
  [
    0,
    59
  ],
  [
    0,
    60
  ],
  [
    0,
    -1
  ],
  [
    0,
    3600
  ],
  [
    -1,
    0
  ],
  [
    1000,
    999
  ],
  [
    1000,
    1060
  ],
  [
    1000,
    1061
  ],
  [
    1000,
    4600
  ],
  [
    "",
    0
  ],
  [
    "",
    -1
  ],
  [
    0,
    1.5
  ],
  [
    True,
    0
  ],
  [
    0,
    None
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
