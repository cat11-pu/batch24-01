import base64

import pytest

from basic_auth import authenticate

USERS = {"alice": "correct-password"}


def enc(text):
    return base64.b64encode(text.encode()).decode()


def test_empty_header_is_rejected():
    with pytest.raises(ValueError):
        authenticate("", USERS, 4096)


def test_none_header_is_rejected():
    with pytest.raises(ValueError):
        authenticate(None, USERS, 4096)


def test_non_string_header_is_rejected():
    with pytest.raises(ValueError):
        authenticate(123, USERS, 4096)


def test_wrong_scheme_is_rejected():
    with pytest.raises(ValueError):
        authenticate("Bearer token", USERS, 4096)


def test_missing_credentials_are_rejected():
    with pytest.raises(ValueError):
        authenticate("Basic", USERS, 4096)


def test_malformed_base64_is_rejected():
    with pytest.raises(ValueError):
        authenticate("Basic !!!", USERS, 4096)


def test_missing_colon_is_rejected():
    with pytest.raises(ValueError):
        authenticate("Basic " + enc("useronly"), USERS, 4096)


def test_empty_username_is_rejected():
    with pytest.raises(ValueError):
        authenticate("Basic " + enc(":pass"), USERS, 4096)


def test_empty_password_is_rejected():
    with pytest.raises(ValueError):
        authenticate("Basic " + enc("alice:"), USERS, 4096)


def test_extra_colon_is_rejected():
    with pytest.raises(ValueError):
        authenticate("Basic " + enc("alice:pass:extra"), USERS, 4096)


def test_control_characters_are_rejected():
    with pytest.raises(ValueError):
        authenticate("Basic " + enc("alice\n:pass"), USERS, 4096)


def test_unknown_user_is_rejected():
    with pytest.raises(ValueError):
        authenticate("Basic " + enc("bob:password"), USERS, 4096)


def test_wrong_password_is_rejected():
    with pytest.raises(ValueError):
        authenticate("Basic " + enc("alice:wrong"), USERS, 4096)


def test_overlong_header_is_rejected():
    with pytest.raises(ValueError):
        authenticate("Basic " + "A" * 5000, USERS, 4096)


def test_non_ascii_credentials_are_rejected():
    with pytest.raises(ValueError):
        authenticate("Basic " + enc("álice:pass"), USERS, 4096)
