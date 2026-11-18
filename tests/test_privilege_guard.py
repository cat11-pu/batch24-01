import pytest

from privilege_guard import validate

BAD_VALUES = [
  [
    "user",
    "admin",
    "s1",
    False
  ],
  [
    "admin",
    "user",
    "s1",
    False
  ],
  [
    "user",
    "admin",
    "s1",
    True
  ],
  [
    "user",
    "user",
    "s1",
    False
  ],
  [
    "",
    "admin",
    "s1",
    False
  ],
  [
    "user",
    "",
    "s1",
    False
  ],
  [
    "user",
    "admin",
    "",
    False
  ],
  [
    "user",
    "admin",
    "",
    True
  ],
  [
    "guest",
    "admin",
    "s1",
    False
  ],
  [
    "user",
    "root",
    "s1",
    False
  ],
  [
    "user",
    "admin",
    "s1",
    0
  ],
  [
    "user",
    "admin",
    "s1",
    1
  ],
  [
    "user",
    "admin",
    "s1",
    None
  ],
  [
    None,
    "admin",
    "s1",
    False
  ],
  [
    "user",
    None,
    "s1",
    False
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
