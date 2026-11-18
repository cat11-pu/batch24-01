import pytest

from header_size_guard import check_headers

BAD_HEADERS = [
    [],
    "not-list",
    [("Host", "a")] * 101,
    [("Host", "a"), ("X", "b" * 5000)],
    [("", "a")],
    [(None, "a")],
    [("Host",)],
    [("Host", 123)],
    [("Host\n", "a")],
    [("Host", "a\nb")],
    [("Host", "a\x00b")],
    [("Host", "a"), ("Host", "b")],
    [("X", "b" * 5000)],
    [("Host", "a"), ("X", "b" * 4096), ("Y", "c" * 4096)],
    [("Host", "a\x00")],
]


@pytest.mark.parametrize("headers", BAD_HEADERS)
def test_oversized_or_malformed_headers_are_rejected(headers):
    with pytest.raises(ValueError):
        check_headers(headers, 100, 8192, 4096)
