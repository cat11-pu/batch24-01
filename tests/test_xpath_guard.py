import pytest

from xpath_guard import validate_xpath_value

BAD_VALUES = [
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "]",
    "//user",
    "*",
    "@",
    "count(",
    "contains(",
    "|",
    "..",
    "\x00",
    "",
    "a'b",
    "a\"b",
    123,
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_xpath_injection_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate_xpath_value(value)
