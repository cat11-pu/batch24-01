import pytest

from xpath_guard import build_xpath

BAD_NAMES = [
    "' or '1'='1",
    "admin' or 1=1 or '",
    "x'] | //user['",
    "a[b]",
    "a|b",
    "a and b",
    "a or b",
    "concat('a')",
    "text()",
    "//user",
    "a\x00",
    "",
    None,
    123,
    "a\nb",
]


@pytest.mark.parametrize("name", BAD_NAMES)
def test_dangerous_xpath_input_is_rejected(name):
    with pytest.raises(ValueError):
        build_xpath(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
