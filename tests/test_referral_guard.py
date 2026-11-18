import pytest

from referral_guard import validate_referral

BAD_CASES = [
    ("a@x.com", "a@x.com", {}, []),
    ("A@x.com", "a@x.com", {}, []),
    ("", "b@x.com", {}, []),
    ("a@x.com", "", {}, []),
    ("not-email", "b@x.com", {}, []),
    ("a@x.com", "not-email", {}, []),
    ("a@x.com", "b@x.com", {}, ["x.com"]),
    ("a@y.com", "b@x.com", {}, ["x.com"]),
    ("a@x.com", "b@x.com", {"b@x.com": "c@x.com"}, []),
    ("b@x.com", "c@x.com", {"b@x.com": "a@x.com", "a@x.com": "c@x.com"}, []),
    (
        "f@x.com",
        "g@x.com",
        {"f@x.com": "e@x.com", "e@x.com": "d@x.com", "d@x.com": "c@x.com", "c@x.com": "b@x.com", "b@x.com": "a@x.com"},
        [],
    ),
    ("a@", "b@x.com", {}, []),
    (" a@x.com", "b@x.com", {}, []),
    ("a@x.com", "b@X.COM", {}, ["x.com"]),
    ("a@x.com", "b@x.com", [], []),
]


@pytest.mark.parametrize("referrer,referee,links,domains", BAD_CASES)
def test_bad_referral_is_rejected(referrer, referee, links, domains):
    with pytest.raises(ValueError):
        validate_referral(referrer, referee, links, domains, 5)
