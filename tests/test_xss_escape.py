import pytest

from xss_escape import render_comment

CASES = [
    ("<script>alert(1)</script>", "https://ok.example/x", "<script>"),
    ("\"><img src=x onerror=alert(1)>", "https://ok.example/x", "onerror="),
    ("' onmouseover='alert(1)", "https://ok.example/x", "onmouseover="),
    ("hello", "javascript:alert(1)", "javascript:"),
    ("hello", "JaVaScRiPt:alert(1)", "javascript:"),
    ("hello", "data:text/html,<script>alert(1)</script>", "data:text/html"),
    ("hello", "vbscript:msgbox(1)", "vbscript:"),
    ("a & b", "https://ok.example/x", "& b"),
    ("x\x00y", "https://ok.example/x", "\x00"),
    ("line1\nline2", "https://ok.example/x", "\n"),
    ("</textarea><script>alert(1)</script>", "https://ok.example/x", "<script>"),
    ("hello", "java&#115;cript:alert(1)", "java&#115;cript:"),
    ("hello", " javascript:alert(1)", "javascript:"),
    ("<svg/onload=alert(1)>", "https://ok.example/x", "<svg"),
    ("\x60onclick=alert(1)", "https://ok.example/x", "onclick="),
]


@pytest.mark.parametrize("text,url,forbidden", CASES)
def test_dangerous_markup_is_removed(text, url, forbidden):
    out = render_comment(text, url)
    assert forbidden not in out.lower()
