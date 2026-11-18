import pytest

from secret_url_guard import validate

BAD_VALUES = [
  "https://app.example.com/cb?token=abc",
  "https://app.example.com/cb?password=secret",
  "https://app.example.com/cb?api_key=abc",
  "https://app.example.com/cb?secret=abc",
  "https://app.example.com/cb?access_token=abc",
  "https://app.example.com/cb?refresh_token=abc",
  "https://user:pass@app.example.com/cb",
  "https://app.example.com/cb#token=abc",
  "https://app.example.com/cb?%74oken=abc",
  "https://app.example.com/cb?TOKEN=abc",
  "https://app.example.com/cb?to%6ben=abc",
  "https://app.example.com/cb?key=abc",
  "https://app.example.com/cb?auth=abc",
  "https://app.example.com/cb?session=abc",
  "https://app.example.com/cb?client_secret=abc"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
