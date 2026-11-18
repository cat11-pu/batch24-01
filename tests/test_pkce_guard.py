import pytest

from pkce_guard import verify

BAD_PKCE = [
    ("plain", "abc", "abc"),
    ("S256", "abc", "wrong"),
    ("s256", "abc", "abc"),
    ("", "abc", "abc"),
    ("S256", "", ""),
    ("S256", "a" * 10, "a" * 10),
    ("S256", "abc", None),
    ("S256", "abc", ""),
    ("S256", "abc", "abc\n"),
    ("S256", "abc", "abc\x00"),
    ("S256", "abc", "abc "),
    ("S256", "abc", "ABC"),
    ("S256", "abc", "abcd"),
    ("none", "abc", "abc"),
    ("S256", "a" * 300, "a" * 300),
]


@pytest.mark.parametrize("value", BAD_PKCE)
def test_bad_pkce_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        verify(*value)
