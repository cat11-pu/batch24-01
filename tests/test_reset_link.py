import pytest

from reset_link import build_reset_link

BAD_HOSTS = [
    "app.example.com.evil.com",
    "app.example.com:8443",
    "user@app.example.com",
    "127.0.0.1",
    "",
    "app.example.com\nX-Evil: 1",
    "app.example.com.",
    "app.example.com\\evil",
    "[::1]",
    "evil.example.com",
    "app.example.com@evil.com",
    "app.example.com%00",
    "app.example.com..",
    "APP.EXAMPLE.COM.EVIL.COM",
    " app.example.com",
]


@pytest.mark.parametrize("host", BAD_HOSTS)
def test_bad_reset_host_is_rejected(host):
    with pytest.raises(ValueError):
        build_reset_link(host, "a" * 32)
