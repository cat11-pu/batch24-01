import pytest

from password_history import check_password

BAD_CASES = [
    ("Passw0rd!123", ["Passw0rd!123"], "alice"),
    ("passw0rd!123", ["Passw0rd!123"], "alice"),
    ("Short1!", [], "alice"),
    ("", [], "alice"),
    (None, [], "alice"),
    (123, [], "alice"),
    ("password1234", [], "alice"),
    ("alicealice1!", [], "alice"),
    ("           ", [], "alice"),
    ("Passw0rd!123", "not-list", "alice"),
    ("Passw0rd!123", [123], "alice"),
    ("Passw0rd!123", [], ""),
    ("Passw0rd!123", [], None),
    (" Passw0rd!123 ", [], "alice"),
    ("ALICE12345678!", [], "alice"),
]


@pytest.mark.parametrize("new,history,username", BAD_CASES)
def test_weak_or_reused_password_is_rejected(new, history, username):
    with pytest.raises(ValueError):
        check_password(new, history, username, 5, 12)
