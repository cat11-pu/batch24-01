import time

import pytest

import api_key_guard as ag


def test_1_key_has_enough_entropy():
    key = ag.issue_api_key("alice")
    assert len(key) >= 32


def test_2_key_is_not_predictable():
    key = ag.issue_api_key("alice")
    assert key != "key-alice"


def test_3_key_does_not_contain_user_name():
    key = ag.issue_api_key("alice")
    assert "alice" not in key


def test_4_key_is_bound_to_user():
    key = ag.issue_api_key("alice")
    with pytest.raises(ValueError):
        ag.validate_api_key(key, user="bob")


def test_5_expired_key_is_rejected(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    key = ag.issue_api_key("alice", ttl=1)
    monkeypatch.setattr(time, "time", lambda: 1010.0)
    with pytest.raises(ValueError):
        ag.validate_api_key(key)


def test_6_revoked_key_is_rejected():
    key = ag.issue_api_key("alice")
    ag.revoke_api_key(key)
    with pytest.raises(ValueError):
        ag.validate_api_key(key)


def test_7_scope_is_enforced():
    key = ag.issue_api_key("alice", scopes=["read"])
    with pytest.raises(ValueError):
        ag.validate_api_key(key, scope="write")


def test_8_rotation_invalidates_old_key():
    old = ag.issue_api_key("alice")
    ag.rotate_api_key(old)
    with pytest.raises(ValueError):
        ag.validate_api_key(old)


def test_9_rotation_returns_new_key():
    old = ag.issue_api_key("alice")
    new = ag.rotate_api_key(old)
    assert new != old


def test_10_empty_user_is_rejected():
    with pytest.raises(ValueError):
        ag.issue_api_key("")


def test_11_non_string_user_is_rejected():
    with pytest.raises(TypeError):
        ag.issue_api_key(123)


def test_12_non_positive_ttl_is_rejected():
    with pytest.raises(ValueError):
        ag.issue_api_key("alice", ttl=0)


def test_13_keys_are_unique_per_issue():
    first = ag.issue_api_key("alice")
    second = ag.issue_api_key("alice")
    assert first != second


def test_14_key_is_not_stored_in_plaintext():
    key = ag.issue_api_key("alice")
    assert key not in ag.KEYS


def test_15_revoke_user_keys_invalidates_all():
    first = ag.issue_api_key("alice")
    second = ag.issue_api_key("alice")
    ag.revoke_user_keys("alice")
    with pytest.raises(ValueError):
        ag.validate_api_key(first)
    with pytest.raises(ValueError):
        ag.validate_api_key(second)
