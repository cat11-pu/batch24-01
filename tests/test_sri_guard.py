import pytest

from sri_guard import validate

BAD_VALUES = [
  "",
  "sha256-",
  "sha256-abc",
  "md5-abc",
  "sha1-abc",
  "sha256-AAAA",
  "sha256-!!!!",
  "sha256-aaaaaaaaaa",
  "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "sha256-abc sha256-abc",
  "sha256-abc\n",
  "sha256-abc\u0000",
  "sha256-abc?",
  "sha256-abc=",
  "sha256-abc def"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
