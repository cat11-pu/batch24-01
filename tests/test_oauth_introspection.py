import pytest

from oauth_introspection import validate

NOW = 1000
GOOD = {"active": True, "exp": 2000, "iat": 900, "aud": ["client-1"], "iss": "https://issuer.example", "scope": "read write", "token_type": "Bearer", "sub": "alice"}


def test_inactive_token_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "active": False}, NOW, "client-1", "read", "https://issuer.example")


def test_missing_active_is_rejected():
    bad = dict(GOOD)
    del bad["active"]
    with pytest.raises(ValueError):
        validate(bad, NOW, "client-1", "read", "https://issuer.example")


def test_expired_token_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "exp": 900}, NOW, "client-1", "read", "https://issuer.example")


def test_future_issued_at_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "iat": 1100}, NOW, "client-1", "read", "https://issuer.example")


def test_wrong_audience_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "aud": ["client-2"]}, NOW, "client-1", "read", "https://issuer.example")


def test_wrong_issuer_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "iss": "evil"}, NOW, "client-1", "read", "https://issuer.example")


def test_missing_scope_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "scope": "read"}, NOW, "client-1", "write", "https://issuer.example")


def test_wrong_token_type_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "token_type": "MAC"}, NOW, "client-1", "read", "https://issuer.example")


def test_empty_subject_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "sub": ""}, NOW, "client-1", "read", "https://issuer.example")


def test_non_dict_response_is_rejected():
    with pytest.raises(ValueError):
        validate("ok", NOW, "client-1", "read", "https://issuer.example")


def test_non_integer_now_is_rejected():
    with pytest.raises(ValueError):
        validate(GOOD, "now", "client-1", "read", "https://issuer.example")


def test_non_integer_exp_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "exp": "2000"}, NOW, "client-1", "read", "https://issuer.example")


def test_non_string_scope_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "scope": 123}, NOW, "client-1", "read", "https://issuer.example")


def test_non_boolean_active_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "active": "true"}, NOW, "client-1", "read", "https://issuer.example")


def test_empty_audience_is_rejected():
    with pytest.raises(ValueError):
        validate({**GOOD, "aud": []}, NOW, "client-1", "read", "https://issuer.example")
