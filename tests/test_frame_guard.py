import pytest

from frame_guard import frame_headers

ALLOWED = ["https://app.example.com"]

BAD_CASES = [
    ("DENY", "https://app.example.com"),
    ("SAMEORIGIN", "https://app.example.com"),
    ("ALLOW-FROM", "http://app.example.com"),
    ("ALLOW-FROM", "https://evil.com"),
    ("", "https://app.example.com"),
    (None, "https://app.example.com"),
    ("ALLOW-FROM", "*"),
    ("ALLOW-FROM", None),
    ("ALLOW-FROM", "https://app.example.com/path"),
    ("ALLOW-FROM", "https://app.example.com:8443"),
    ("ALLOW-FROM", "https://user@app.example.com"),
    ("ALLOW-FROM", "https://app.example.com."),
    ("ALLOW-FROM", "https://app.example.com\n"),
    ("ALLOW-FROM", "https://app.example.com\x00"),
    ("ALLOW-FROM", "https://a.example.com https://b.example.com"),
]


@pytest.mark.parametrize("mode,origin", BAD_CASES)
def test_bad_frame_policy_is_rejected(mode, origin):
    with pytest.raises(ValueError):
        frame_headers(mode, origin, ALLOWED)
