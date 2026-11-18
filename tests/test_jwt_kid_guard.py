import pytest

from jwt_kid_guard import resolve_key_path

ALLOWED = ["key-1", "key-2"]
DIR = "/srv/keys"

BAD_KIDS = [
    "../secret",
    "..\\secret",
    "/etc/passwd",
    "a/b",
    "",
    None,
    123,
    "key\x00",
    "key\n",
    ".",
    "..",
    "a" * 300,
    "CON",
    "key-1/..",
    "%2e%2e/x",
]


@pytest.mark.parametrize("kid", BAD_KIDS)
def test_bad_kid_is_rejected(kid):
    with pytest.raises(ValueError):
        resolve_key_path(kid, DIR, ALLOWED)
