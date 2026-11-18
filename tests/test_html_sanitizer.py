import pytest

from html_sanitizer import sanitize

CASES = [
    ("<script>alert(1)</script>", "<script"),
    ("<img src=x onerror=alert(1)>", "onerror"),
    ('<a href="javascript:alert(1)">x</a>', "javascript:"),
    ('<a href="http://evil">x</a>', "http://"),
    ("<b onclick=alert(1)>x</b>", "onclick"),
    ("<iframe src=//evil></iframe>", "<iframe"),
    ("<style>body{}</style>", "<style"),
    ("<!--<script>alert(1)</script>-->", "<script"),
    ("a\x00b", "\x00"),
    ("<svg/onload=alert(1)>", "<svg"),
    ("<math><mtext>x</mtext></math>", "<math"),
    ('<a href="https://ok" target="_blank">x</a>', "target="),
    ('<a href="https://ok" style="color:red">x</a>', "style="),
    ("<scr<script>ipt>alert(1)</scr<script>ipt>", "<script"),
    ('<a href="//evil/x">x</a>', "//evil"),
]


@pytest.mark.parametrize("html,forbidden", CASES)
def test_dangerous_html_is_removed(html, forbidden):
    out = sanitize(html, {"b", "i", "p", "a", "br"}, {"a": {"href"}})
    assert forbidden not in out.lower()
