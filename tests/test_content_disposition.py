import pytest

from content_disposition import build_disposition

BAD_NAMES = [
    "\r\nX: y",
    "a\nb",
    "a\rb",
    "a\x00b",
    "",
    None,
    123,
    "a/b",
    "..",
    ".",
    "a" * 300,
    "a\x1fb",
    'a"b',
    "a\\b",
    "   ",
]


@pytest.mark.parametrize("name", BAD_NAMES)
def test_bad_disposition_filename_is_rejected(name):
    with pytest.raises(ValueError):
        build_disposition(name, "download", 200)
