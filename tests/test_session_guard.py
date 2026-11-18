import threading
import time

import pytest

import session_guard as sg


def test_1_token_has_enough_entropy():
    token = sg.issue_token("alice")
    assert len(token) >= 32


def test_2_tokens_are_unique_for_same_user(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    first = sg.issue_token("alice")
    second = sg.issue_token("alice")
    assert first != second


def test_3_token_does_not_contain_user_name():
    token = sg.issue_token("alice")
    assert "alice" not in token


def test_4_expired_token_is_rejected(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    token = sg.issue_token("alice", ttl=1)
    monkeypatch.setattr(time, "time", lambda: 1010.0)
    assert sg.validate(token) is False


def test_5_expired_token_is_removed_from_store(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    token = sg.issue_token("alice", ttl=1)
    monkeypatch.setattr(time, "time", lambda: 1010.0)
    sg.validate(token)
    assert token not in sg.SESSIONS


def test_6_token_is_bound_to_user():
    token = sg.issue_token("alice")
    assert sg.validate(token, "bob") is False


def test_7_same_token_cannot_be_used_twice():
    token = sg.issue_token("alice")
    assert sg.validate(token) is True
    assert sg.validate(token) is False


def test_8_concurrent_use_only_one_succeeds():
    token = sg.issue_token("alice")
    results = []

    def worker():
        results.append(sg.validate(token))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1


def test_9_logout_invalidates_all_user_tokens():
    tokens = [sg.issue_token("alice") for _ in range(3)]
    sg.logout("alice")
    assert all(sg.validate(token) is False for token in tokens)


def test_10_rotate_invalidates_old_token():
    old = sg.issue_token("alice")
    sg.rotate(old)
    assert sg.validate(old) is False


def test_11_rotate_returns_new_token():
    old = sg.issue_token("alice")
    new = sg.rotate(old)
    assert new != old


def test_12_empty_user_is_rejected():
    with pytest.raises(ValueError):
        sg.issue_token("")


def test_13_non_string_user_is_rejected():
    with pytest.raises(TypeError):
        sg.issue_token(123)


def test_14_non_positive_ttl_is_rejected():
    with pytest.raises(ValueError):
        sg.issue_token("alice", 0)


def test_15_password_change_invalidates_sessions():
    token = sg.issue_token("alice")
    sg.change_password("alice")
    assert sg.validate(token) is False
