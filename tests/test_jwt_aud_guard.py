import pytest

from jwt_aud_guard import validate

BAD_VALUES = [
  {
    "aud": "other",
    "iss": "app",
    "exp": 2000,
    "nbf": 1000,
    "typ": "JWT"
  },
  {
    "aud": "app",
    "iss": "other",
    "exp": 2000,
    "nbf": 1000,
    "typ": "JWT"
  },
  {
    "aud": "app",
    "iss": "app",
    "exp": 1000,
    "nbf": 1000,
    "typ": "JWT"
  },
  {
    "aud": "app",
    "iss": "app",
    "exp": 3000,
    "nbf": 2000,
    "typ": "JWT"
  },
  {
    "aud": "app",
    "iss": "app",
    "exp": 2000,
    "nbf": 1000,
    "typ": "JWT2"
  },
  {
    "aud": "",
    "iss": "app",
    "exp": 2000,
    "nbf": 1000,
    "typ": "JWT"
  },
  {
    "aud": "app",
    "iss": "",
    "exp": 2000,
    "nbf": 1000,
    "typ": "JWT"
  },
  {
    "aud": [
      "other"
    ],
    "iss": "app",
    "exp": 2000,
    "nbf": 1000,
    "typ": "JWT"
  },
  {
    "aud": "app",
    "iss": "app",
    "exp": "2000",
    "nbf": 1000,
    "typ": "JWT"
  },
  {
    "aud": "app",
    "iss": "app",
    "exp": 2000,
    "nbf": "1000",
    "typ": "JWT"
  },
  {
    "aud": "app",
    "iss": "app",
    "exp": 2000,
    "nbf": 1000,
    "typ": "jwt"
  },
  {
    "aud": "app",
    "iss": "app",
    "exp": -1,
    "nbf": 0,
    "typ": "JWT"
  },
  {},
  None,
  {
    "aud": "app",
    "iss": "app",
    "exp": 2000,
    "nbf": 1000,
    "typ": "JWT",
    "x": 1
  }
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
