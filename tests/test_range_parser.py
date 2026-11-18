import pytest

from range_parser import parse_range

BAD_HEADERS = [
    "",
    None,
    123,
    "bytes=",
    "bytes=abc",
    "bytes=5-1",
    "bytes=-0",
    "bytes=0-1,3-4,5-6,7-8",
    "bytes=0-1,0-1",
    "bytes=100-200",
    "items=0-1",
    "bytes=1-2-3",
    "bytes= 0-1",
    "bytes=0 - 1",
    "bytes=+1-2",
]


@pytest.mark.parametrize("header", BAD_HEADERS)
def test_bad_range_header_is_rejected(header):
    with pytest.raises(ValueError):
        parse_range(header, 100, 3)
