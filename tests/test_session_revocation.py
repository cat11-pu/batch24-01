import threading

import pytest

import session_revocation as sr


def store():
    return {
        "s1": {"user": "alice", "device": "phone", "status": "active", "refresh_id": "r1"},
        "s2": {"user": "alice", "device": "laptop", "status": "active", "refresh_id": "r2"},
        "s3": {"user": "bob", "device": "phone", "status": "active", "refresh_id": "r3"},
    }


def test_empty_user_is_rejected():
    with pytest.raises(ValueError):
        sr.revoke_user_sessions(store(), "", "logout", 1000)


def test_non_string_user_is_rejected():
    with pytest.raises(ValueError):
        sr.revoke_user_sessions(store(), 123, "logout", 1000)


def test_empty_reason_is_rejected():
    with pytest.raises(ValueError):
        sr.revoke_user_sessions(store(), "alice", "", 1000)


def test_store_must_be_dict():
    with pytest.raises(ValueError):
        sr.revoke_user_sessions([], "alice", "logout", 1000)


def test_active_sessions_are_counted():
    assert sr.revoke_user_sessions(store(), "alice", "logout", 1000) >= 2


def test_idempotent_second_revoke_returns_zero():
    data = store()
    first = sr.revoke_user_sessions(data, "alice", "logout", 1000)
    second = sr.revoke_user_sessions(data, "alice", "logout", 1000)
    assert first >= 2 and second == 0


def test_device_revoke_only_affects_one_device():
    data = store()
    assert sr.revoke_device(data, "alice", "phone", "lost", 1000) >= 1
    assert data["s2"]["status"] == "active"


def test_empty_device_is_rejected():
    with pytest.raises(ValueError):
        sr.revoke_device(store(), "alice", "", "lost", 1000)


def test_non_string_device_is_rejected():
    with pytest.raises(ValueError):
        sr.revoke_device(store(), "alice", 123, "lost", 1000)


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        sr.revoke_user_sessions(store(), "alice", "logout", "now")


def test_concurrent_revoke_does_not_double_count():
    data = store()
    results = []

    def worker():
        results.append(sr.revoke_user_sessions(data, "alice", "logout", 1000))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [0, 2]


def test_refresh_tokens_are_cleared():
    data = store()
    sr.revoke_user_sessions(data, "alice", "logout", 1000)
    assert data["s1"]["refresh_id"] is None and data["s2"]["refresh_id"] is None


def test_session_status_must_be_known():
    data = {"s1": {"user": "alice", "device": "phone", "status": "weird", "refresh_id": "r1"}}
    with pytest.raises(ValueError):
        sr.revoke_user_sessions(data, "alice", "logout", 1000)


def test_missing_device_field_is_rejected():
    data = {"s1": {"user": "alice", "status": "active", "refresh_id": "r1"}}
    with pytest.raises(ValueError):
        sr.revoke_user_sessions(data, "alice", "logout", 1000)


def test_non_string_reason_is_rejected():
    with pytest.raises(ValueError):
        sr.revoke_user_sessions(store(), "alice", 123, 1000)
