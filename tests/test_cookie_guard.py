import pytest

from cookie_guard import validate

BAD_VALUES = [
  "session=abc; Domain=.example.com",
  "session=abc; Domain=example.com; Secure",
  "session=abc; SameSite=None",
  "session=abc; Path=/; HttpOnly",
  "session=abc; SameSite=None; Secure; HttpOnly; Domain=.example.com",
  "__Host-session=abc; Domain=example.com; Path=/; Secure; HttpOnly",
  "__Secure-session=abc; HttpOnly",
  "session=abc; Domain=evil.com; Path=/; Secure; HttpOnly; SameSite=Lax",
  "=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
  "session=abc\r\nX-Evil: 1; Path=/; Secure; HttpOnly",
  "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax; SameSite=None",
  "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.com.evil.com",
  "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=127.0.0.1",
  "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax\u0000",
  "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
