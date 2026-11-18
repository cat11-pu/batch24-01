import pytest

from directory_guard import validate

BAD_VALUES = [
  "/uploads/",
  "/static/",
  "/img/",
  "/./",
  "//",
  "/..",
  "/%2e%2e/",
  "/uploads//",
  "/UPLOADS/",
  "/uploads/%2e",
  "/uploads/..;/",
  "/uploads/%00",
  "",
  "/uploads/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "/uploads/."
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
