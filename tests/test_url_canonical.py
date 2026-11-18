import pytest

from url_canonical import canonicalize

BAD_URLS = [
    "http://user:pass@example.com/",
    "http://example.com\\@evil",
    "http://example.com/../admin",
    "http://example.com/%2e%2e/admin",
    "http://example.com:80/",
    "https://example.com:443/",
    "javascript:alert(1)",
    "//example.com/",
    "http:///path",
    "",
    None,
    123,
    "http://exa mple.com/",
    "http://example.com/\x00",
    "http://example.com/%00",
]


@pytest.mark.parametrize("url", BAD_URLS)
def test_ambiguous_url_is_rejected(url):
    with pytest.raises(ValueError):
        canonicalize(url, ("http", "https"))
