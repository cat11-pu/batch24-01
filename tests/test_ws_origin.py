import pytest

from ws_origin import validate

BAD_VALUES = [
  "http://app.example.com",
  "https://app.example.com.evil.com",
  "https://evil.com",
  "null",
  "file://app.example.com",
  "https://app.example.com:8443",
  "https://user@app.example.com",
  "https://app.example.com/path",
  "https://app.example.com#frag",
  "",
  "https://app.example.com\nX-Evil: 1",
  "https://app.example.com\\evil",
  "https://127.0.0.1",
  "https://[::1]",
  "https://APP.EXAMPLE.COM.EVIL.COM"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
