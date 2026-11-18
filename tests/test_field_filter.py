import pytest

from field_filter import serialize_user

SENSITIVE = {"password_hash", "ssn", "token", "secret", "api_key", "credit_card"}

BAD_CASES = [
    ({"password_hash": "x"}, ["name"]),
    ({"ssn": "x"}, ["name"]),
    ({"token": "x"}, ["name"]),
    ({"api_key": "x"}, ["name"]),
    ({"name": "a"}, ["password_hash"]),
    ({"name": "a"}, ["*"]),
    ({"name": "a"}, []),
    ({"name": "a"}, "name"),
    ({"name": "a"}, None),
    ({"name": "a"}, [123]),
    ({"profile": {"password_hash": "x"}}, ["profile"]),
    ("not-dict", ["name"]),
    (None, ["name"]),
    ({"name": "a", "credit_card": "x"}, ["name"]),
    ({"name": "a", "secret": "x"}, ["name"]),
]


@pytest.mark.parametrize("user,fields", BAD_CASES)
def test_unsafe_serialization_is_rejected(user, fields):
    with pytest.raises(ValueError):
        serialize_user(user, fields, SENSITIVE)
