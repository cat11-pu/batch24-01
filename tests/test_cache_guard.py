import pytest

from cache_guard import validate

BAD_VALUES = [
  "/admin.css",
  "/admin.js",
  "/admin.json",
  "/admin%2ecss",
  "/admin;.css",
  "/admin/.css",
  "/admin/..;/css",
  "/admin%00.css",
  "/admin?x=.css",
  "/ADMIN.CSS",
  "/admin/.",
  "//admin.css",
  "/admin%2f..%2fcss",
  "/admin.css/..",
  "/admin.css%20"
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
