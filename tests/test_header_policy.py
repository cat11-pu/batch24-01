import pytest

from header_policy import validate

BAD_VALUES = [
  [
    "Strict-Transport-Security",
    "max-age=0"
  ],
  [
    "Strict-Transport-Security",
    "max-age=31536000"
  ],
  [
    "Content-Security-Policy",
    "default-src *"
  ],
  [
    "X-Frame-Options",
    "ALLOW"
  ],
  [
    "X-Content-Type-Options",
    "sniff"
  ],
  [
    "Referrer-Policy",
    "unsafe-url"
  ],
  [
    "Set-Cookie",
    "session=abc"
  ],
  [
    "X-Test",
    "ok\r\nX-Evil: 1"
  ],
  [
    "",
    "value"
  ],
  [
    "X-Frame-Options",
    "SAMEORIGIN\r\n"
  ],
  [
    "Access-Control-Allow-Origin",
    "*"
  ],
  [
    "Permissions-Policy",
    "*"
  ],
  [
    "Strict-Transport-Security",
    "max-age=abc"
  ],
  [
    "Content-Security-Policy",
    "script-src 'unsafe-eval'"
  ],
  [
    "X-Content-Type-Options",
    "nosniff\u0000"
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
