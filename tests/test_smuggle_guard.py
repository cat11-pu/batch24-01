import pytest

from smuggle_guard import parse_request

BAD_HEADERS = [
    [("Content-Length", "5"), ("Transfer-Encoding", "chunked")],
    [("Content-Length", "5"), ("Content-Length", "6")],
    [("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "identity")],
    [("Transfer-Encoding", "chunked, identity")],
    [("Transfer-Encoding", "xchunked")],
    [("Transfer-Encoding", " chunked")],
    [("Content-Length", "-1")],
    [("Content-Length", "abc")],
    [("Content-Length", "5, 6")],
    [("Content-Length", "+5")],
    [("Content-Length", "0x5")],
    [("Content-Length", " 5")],
    [("Content-Length", "5 ")],
    [("Transfer-Encoding", "chunked\r\n")],
    [("Content-Length", "5\x00")],
]


@pytest.mark.parametrize("headers", BAD_HEADERS)
def test_bad_headers_are_rejected(headers):
    with pytest.raises(ValueError):
        parse_request(headers, b"x")
