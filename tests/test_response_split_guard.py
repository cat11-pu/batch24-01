import pytest

from response_split_guard import build_header

BAD_HEADERS = [
    ("X-Test", "a\r\nSet-Cookie: x=1"),
    ("X-Test", "a\nb"),
    ("X-Test", "a\rb"),
    ("X-Test", "a\x00b"),
    ("X-Test", "a\x0bb"),
    ("X-Test", "a\x0cb"),
    ("X-Test", "a\u2028b"),
    ("X-Test", "a\u2029b"),
    ("X-Test", "a" * 5000),
    ("Bad:Name", "x"),
    ("Bad Name", "x"),
    ("", "x"),
    ("X-Test\n", "x"),
    ("X-Test", 123),
    (123, "x"),
]


@pytest.mark.parametrize("name,value", BAD_HEADERS)
def test_bad_header_is_rejected(name, value):
    with pytest.raises(ValueError):
        build_header(name, value, 4096)
