import pytest

from token_exchange import exchange

ALLOWED = ["access_token", "id_token"]
GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
GOOD = {"grant_type": GRANT, "subject_token": "s" * 32, "subject_token_type": "access_token", "audience": "client-1", "scope": "read", "client_id": "client-1", "requested_token_type": "access_token"}


def test_wrong_grant_type_is_rejected():
    with pytest.raises(ValueError):
        exchange({**GOOD, "grant_type": "password"}, 1000, "client-1", ALLOWED)


def test_missing_subject_token_is_rejected():
    bad = dict(GOOD)
    del bad["subject_token"]
    with pytest.raises(ValueError):
        exchange(bad, 1000, "client-1", ALLOWED)


def test_empty_subject_token_is_rejected():
    with pytest.raises(ValueError):
        exchange({**GOOD, "subject_token": ""}, 1000, "client-1", ALLOWED)


def test_unallowed_subject_type_is_rejected():
    with pytest.raises(ValueError):
        exchange({**GOOD, "subject_token_type": "saml2"}, 1000, "client-1", ALLOWED)


def test_audience_mismatch_is_rejected():
    with pytest.raises(ValueError):
        exchange({**GOOD, "audience": "client-2"}, 1000, "client-1", ALLOWED)


def test_client_mismatch_is_rejected():
    with pytest.raises(ValueError):
        exchange({**GOOD, "client_id": "client-2"}, 1000, "client-1", ALLOWED)


def test_empty_scope_is_rejected():
    with pytest.raises(ValueError):
        exchange({**GOOD, "scope": ""}, 1000, "client-1", ALLOWED)


def test_wrong_requested_token_type_is_rejected():
    with pytest.raises(ValueError):
        exchange({**GOOD, "requested_token_type": "refresh_token"}, 1000, "client-1", ALLOWED)


def test_bad_actor_token_type_is_rejected():
    with pytest.raises(ValueError):
        exchange({**GOOD, "actor_token": "a" * 32, "actor_token_type": "saml2"}, 1000, "client-1", ALLOWED)


def test_non_dict_request_is_rejected():
    with pytest.raises(ValueError):
        exchange("request", 1000, "client-1", ALLOWED)


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        exchange(GOOD, "now", "client-1", ALLOWED)


def test_too_short_subject_token_is_rejected():
    with pytest.raises(ValueError):
        exchange({**GOOD, "subject_token": "short"}, 1000, "client-1", ALLOWED)


def test_too_long_subject_token_is_rejected():
    with pytest.raises(ValueError):
        exchange({**GOOD, "subject_token": "s" * 5000}, 1000, "client-1", ALLOWED)


def test_empty_actor_token_is_rejected():
    with pytest.raises(ValueError):
        exchange({**GOOD, "actor_token": "", "actor_token_type": "access_token"}, 1000, "client-1", ALLOWED)


def test_empty_allowed_types_is_rejected():
    with pytest.raises(ValueError):
        exchange(GOOD, 1000, "client-1", [])
