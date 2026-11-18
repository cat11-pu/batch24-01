import pytest

from ws_origin_guard import check_handshake

ALLOWED = ["https://app.example.com"]

BAD_CASES = [
    ("", "app.example.com"),
    (None, "app.example.com"),
    ("null", "app.example.com"),
    ("http://app.example.com", "app.example.com"),
    ("https://app.example.com.evil.com", "app.example.com"),
    ("https://app.example.com:8443", "app.example.com"),
    ("https://user@app.example.com", "app.example.com"),
    ("https://app.example.com/path", "app.example.com"),
    ("https://app.example.com/", "app.example.com"),
    ("https://APP.EXAMPLE.COM", "app.example.com"),
    ("https://app.example.com\n", "app.example.com"),
    ("https://app.example.com\x00", "app.example.com"),
    ("*", "app.example.com"),
    ("https://a.example.com https://b.example.com", "a.example.com"),
    ("https://app.example.com", "evil.com"),
]


@pytest.mark.parametrize("origin,host", BAD_CASES)
def test_bad_websocket_handshake_is_rejected(origin, host):
    with pytest.raises(ValueError):
        check_handshake(origin, host, ALLOWED)
