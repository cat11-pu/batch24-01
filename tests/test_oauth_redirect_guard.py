import pytest

from oauth_redirect_guard import validate

BAD_VALUES = [
  "https://app.example.com.evil.com/cb",
  "https://user@app.example.com/cb",
  "https://app.example.com:8443/cb",
  "https://app.example.com/cb/extra",
  "https://app.example.com/cb#frag",
  "http://app.example.com/cb",
  "https://app.example.com/cb?x=1",
  "https://app.example.com/%2e%2e/cb",
  "https://app.example.com/cb\n",
  "",
  "https://app.example.com/cb\\evil",
  "https://app.example.com./cb",
  "https://app.example.com/cb%00",
  "https://APP.EXAMPLE.COM.EVIL.COM/cb",
  "https://app.example.com/cb/..;/evil"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
