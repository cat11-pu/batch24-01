import pytest

from reauth_guard import change_email

BAD_CASES = [
    ("alice", "a@b.com", False, True, 10),
    ("alice", "a@b.com", True, False, 10),
    ("alice", "a@b.com", False, False, 10),
    ("alice", "a@b.com", True, True, 301),
    ("alice", "a@b.com", True, True, -1),
    ("alice", "a@b.com", True, True, None),
    ("alice", "not-an-email", True, True, 10),
    ("alice", "", True, True, 10),
    ("alice", None, True, True, 10),
    ("alice", "a@b.com\n", True, True, 10),
    ("alice", " a@b.com", True, True, 10),
    ("alice", "a@b.com ", True, True, 10),
    ("alice", 123, True, True, 10),
    ("", "a@b.com", True, True, 10),
    (None, "a@b.com", True, True, 10),
]


@pytest.mark.parametrize("user,email,pw,mfa,age", BAD_CASES)
def test_unsafe_email_change_is_rejected(user, email, pw, mfa, age):
    with pytest.raises(ValueError):
        change_email(user, email, pw, mfa, age, 300)
