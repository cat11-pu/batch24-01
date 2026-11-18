import pytest

from email_canonical import canonicalize_email

BAD_EMAILS = [
    "",
    None,
    123,
    "a@b",
    "a@@b",
    ".a@b.com",
    "a.@b.com",
    "a..b@c.com",
    "a b@c.com",
    "a@b..com",
    "a@-b.com",
    "a@b-.com",
    "a@b.com\n",
    "a" * 65 + "@b.com",
    "a@b.com\x00",
]


@pytest.mark.parametrize("raw", BAD_EMAILS)
def test_bad_email_is_rejected(raw):
    with pytest.raises(ValueError):
        canonicalize_email(raw, 254)
