import pytest

from pkce_guard import validate

BAD_VALUES = [
  [
    "plain",
    "abc",
    "abc"
  ],
  [
    "S256",
    "abc",
    "wrong"
  ],
  [
    "s256",
    "abc",
    "abc"
  ],
  [
    "",
    "abc",
    "abc"
  ],
  [
    "S256",
    "",
    ""
  ],
  [
    "S256",
    "aaaaaaaaaa",
    "aaaaaaaaaa"
  ],
  [
    "S256",
    "abc",
    None
  ],
  [
    "S256",
    "abc",
    ""
  ],
  [
    "S256",
    "abc",
    "abc\n"
  ],
  [
    "S256",
    "abc",
    "abc\u0000"
  ],
  [
    "S256",
    "abc",
    "abc "
  ],
  [
    "S256",
    "abc",
    "ABC"
  ],
  [
    "S256",
    "abc",
    "abcd"
  ],
  [
    "none",
    "abc",
    "abc"
  ],
  [
    "S256",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
