import threading
import time

import pytest

import appeal_token as svc


def test_1_token_has_enough_entropy():
    assert len(svc.issue("alice")) >= 32


def test_2_tokens_are_unique_for_same_owner(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    assert svc.issue("alice") != svc.issue("alice")


def test_3_token_does_not_contain_owner():
    assert "alice" not in svc.issue("alice")


def test_4_token_is_bound_to_owner():
    token = svc.issue("alice")
    assert svc.validate(token, "bob") is False


def test_5_expired_token_is_rejected(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    token = svc.issue("alice", ttl=1)
    monkeypatch.setattr(time, "time", lambda: 1010.0)
    assert svc.validate(token) is False


def test_6_token_cannot_be_replayed():
    token = svc.issue("alice")
    assert svc.validate(token) is True
    assert svc.validate(token) is False


def test_7_revoke_invalidates_token():
    token = svc.issue("alice")
    svc.revoke(token)
    assert svc.validate(token) is False


def test_8_rotate_invalidates_old_token():
    old = svc.issue("alice")
    svc.rotate(old)
    assert svc.validate(old) is False


def test_9_rotate_returns_new_token():
    old = svc.issue("alice")
    assert svc.rotate(old) != old


def test_10_empty_owner_is_rejected():
    with pytest.raises(ValueError):
        svc.issue("")


def test_11_non_string_owner_is_rejected():
    with pytest.raises(TypeError):
        svc.issue(123)


def test_12_non_positive_ttl_is_rejected():
    with pytest.raises(ValueError):
        svc.issue("alice", 0)


def test_13_concurrent_replay_only_one_succeeds():
    token = svc.issue("alice")
    results = []

    def worker():
        results.append(svc.validate(token))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1


def test_14_cleanup_removes_expired_tokens(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    token = svc.issue("alice", ttl=1)
    monkeypatch.setattr(time, "time", lambda: 1010.0)
    svc.cleanup()
    assert token not in svc.STORE


def test_15_token_is_not_stored_in_plaintext():
    token = svc.issue("alice")
    assert token not in svc.STORE
