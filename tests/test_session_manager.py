import threading

import pytest

import session_manager as sm


def test_session_id_has_enough_entropy():
    store = {}
    sid = sm.login(store, "alice", "phone", 1000)
    assert len(sid) >= 32


def test_two_logins_produce_different_ids():
    store = {}
    assert sm.login(store, "alice", "phone", 1000) != sm.login(store, "alice", "phone", 1001)


def test_empty_user_is_rejected():
    with pytest.raises(ValueError):
        sm.login({}, "", "phone", 1000)


def test_non_string_user_is_rejected():
    with pytest.raises(ValueError):
        sm.login({}, 123, "phone", 1000)


def test_empty_device_is_rejected():
    with pytest.raises(ValueError):
        sm.login({}, "alice", "", 1000)


def test_relogin_rotates_old_session():
    store = {}
    first = sm.login(store, "alice", "phone", 1000)
    sm.login(store, "alice", "phone", 1001)
    assert sm.touch(store, first, 1002) is False


def test_idle_timeout_expires_session():
    store = {}
    sid = sm.login(store, "alice", "phone", 1000)
    assert sm.touch(store, sid, 1901, 900, 28800) is False


def test_absolute_timeout_expires_session():
    store = {}
    sid = sm.login(store, "alice", "phone", 1000)
    assert sm.touch(store, sid, 29801, 900, 28800) is False


def test_revoke_invalidates_session():
    store = {}
    sid = sm.login(store, "alice", "phone", 1000)
    sm.revoke(store, sid)
    assert sm.touch(store, sid, 1001) is False


def test_revoke_user_invalidates_all_sessions():
    store = {}
    first = sm.login(store, "alice", "phone", 1000)
    second = sm.login(store, "alice", "laptop", 1001)
    sm.revoke_user(store, "alice")
    assert sm.touch(store, first, 1002) is False
    assert sm.touch(store, second, 1002) is False


def test_max_sessions_evicts_oldest():
    store = {}
    first = sm.login(store, "alice", "phone", 1000, 1)
    sm.login(store, "alice", "laptop", 1001, 1)
    assert sm.touch(store, first, 1002) is False


def test_unknown_session_is_not_valid():
    assert sm.touch({}, "nope", 1000) is False


def test_time_going_backwards_is_rejected():
    store = {}
    sid = sm.login(store, "alice", "phone", 1000)
    with pytest.raises(ValueError):
        sm.touch(store, sid, 999)


def test_concurrent_logins_are_unique():
    store = {}
    ids = []
    lock = threading.Lock()

    def worker(i):
        sid = sm.login(store, "alice", f"device-{i}", 1000 + i)
        with lock:
            ids.append(sid)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(ids)) == 5


def test_revoke_unknown_session_returns_false():
    assert sm.revoke({}, "nope") is False
