import pytest

from cors_guard import cors_headers

ALLOWED = ["https://app.example.com"]

BAD_ORIGINS = [
    "https://evil.com",
    "null",
    "",
    None,
    "https://app.example.com.evil.com",
    "http://app.example.com",
    "https://app.example.com:8443",
    "https://user@app.example.com",
    "*",
    "https://app.example.com/",
    "https://app.example.com#x",
    "https://app.example.com?x",
    "https://app.example.com\n",
    "https://app.example.com\x00",
    "https://APP.EXAMPLE.COM",
]


@pytest.mark.parametrize("origin", BAD_ORIGINS)
def test_untrusted_origin_is_rejected(origin):
    with pytest.raises(ValueError):
        cors_headers(origin, True, ALLOWED)
