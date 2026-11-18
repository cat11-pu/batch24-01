import pytest

from redirect_guard import safe_redirect

ALLOWED = ["app.example.com"]

BAD_TARGETS = [
    "https://evil.com/",
    "//evil.com/",
    "/\\evil.com",
    "https://app.example.com.evil.com/",
    "https://app.example.com@evil.com/",
    "http://app.example.com/",
    "https://app.example.com:8443/",
    "javascript:alert(1)",
    "data:text/html,x",
    "",
    None,
    "https://app.example.com/%0d%0aLocation:%20https://evil.com",
    "https://app.example.com/../evil",
    "\\\\evil.com",
    "https://app.example.com./",
]


@pytest.mark.parametrize("target", BAD_TARGETS)
def test_unsafe_redirect_is_rejected(target):
    with pytest.raises(ValueError):
        safe_redirect(target, ALLOWED)
