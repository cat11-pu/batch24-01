import pytest

from tmp_guard import validate

BAD_VALUES = [
  [
    "/tmp/x",
    "w"
  ],
  [
    "/tmp/x",
    "a"
  ],
  [
    "/tmp/x",
    "r"
  ],
  [
    "/tmp/x",
    "wx"
  ],
  [
    "/tmp/x",
    "w+"
  ],
  [
    "/tmp/x",
    "x"
  ],
  [
    "/tmp/x",
    ""
  ],
  [
    "",
    "w"
  ],
  [
    "/tmp/x",
    "w\u0000"
  ],
  [
    "/tmp/x",
    "w\r\n"
  ],
  [
    "../x",
    "w"
  ],
  [
    "/etc/passwd",
    "w"
  ],
  [
    "/tmp/x",
    "wb"
  ],
  [
    "/tmp/x",
    "a+"
  ],
  [
    "/tmp/x",
    "rw"
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
