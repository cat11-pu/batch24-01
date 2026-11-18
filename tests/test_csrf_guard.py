import threading
import time

import pytest

import csrf_guard as cg


def test_1_token_has_enough_entropy():
    token = cg.issue_csrf_token("session-1")
    assert len(token) >= 32


def test_2_token_is_not_predictable():
    token = cg.issue_csrf_token("session-1")
    assert token != "csrf-session-1"


def test_3_token_is_bound_to_session():
    token = cg.issue_csrf_token("session-1")
    with pytest.raises(ValueError):
        cg.validate_csrf_token("session-2", token)


def test_4_token_cannot_be_replayed():
    token = cg.issue_csrf_token("session-1")
    assert cg.validate_csrf_token("session-1", token) is True
    with pytest.raises(ValueError):
        cg.validate_csrf_token("session-1", token)


def test_5_expired_token_is_rejected(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    token = cg.issue_csrf_token("session-1", ttl=1)
    monkeypatch.setattr(time, "time", lambda: 1010.0)
    with pytest.raises(ValueError):
        cg.validate_csrf_token("session-1", token)


def test_6_empty_token_is_rejected():
    with pytest.raises(ValueError):
        cg.validate_csrf_token("session-1", "")


def test_7_empty_session_is_rejected():
    with pytest.raises(ValueError):
        cg.validate_csrf_token("", "token")


def test_8_non_string_session_is_rejected():
    with pytest.raises(TypeError):
        cg.validate_csrf_token(123, "token")


def test_9_non_positive_ttl_is_rejected():
    with pytest.raises(ValueError):
        cg.issue_csrf_token("session-1", ttl=0)


def test_10_rotation_invalidates_old_token():
    old = cg.issue_csrf_token("session-1")
    cg.rotate_csrf_token("session-1", old)
    with pytest.raises(ValueError):
        cg.validate_csrf_token("session-1", old)


def test_11_rotation_returns_new_token():
    old = cg.issue_csrf_token("session-1")
    new = cg.rotate_csrf_token("session-1", old)
    assert new != old


def test_12_concurrent_use_only_one_succeeds():
    token = cg.issue_csrf_token("session-1")
    results = []

    def worker():
        try:
            results.append(cg.validate_csrf_token("session-1", token))
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1


def test_13_cross_session_token_is_rejected():
    token = cg.issue_csrf_token("session-1")
    with pytest.raises(ValueError):
        cg.validate_csrf_token("session-2", token)


def test_14_unsafe_method_is_rejected():
    token = cg.issue_csrf_token("session-1")
    with pytest.raises(ValueError):
        cg.validate_csrf_token("session-1", token, method="TRACE")


def test_15_tokens_are_unique():
    first = cg.issue_csrf_token("session-1")
    second = cg.issue_csrf_token("session-1")
    assert first != second
