import threading

import pytest

import consent_registry as cr

ALLOWED = ["read", "write"]


def test_empty_user_is_rejected():
    with pytest.raises(ValueError):
        cr.grant({}, "", "client-1", ["read"], 1000)


def test_empty_client_is_rejected():
    with pytest.raises(ValueError):
        cr.grant({}, "alice", "", ["read"], 1000)


def test_scopes_must_be_list():
    with pytest.raises(ValueError):
        cr.grant({}, "alice", "client-1", "read", 1000)


def test_empty_scopes_are_rejected():
    with pytest.raises(ValueError):
        cr.grant({}, "alice", "client-1", [], 1000)


def test_disallowed_scope_is_rejected():
    with pytest.raises(ValueError):
        cr.grant({}, "alice", "client-1", ["admin"], 1000)


def test_duplicate_scope_is_rejected():
    with pytest.raises(ValueError):
        cr.grant({}, "alice", "client-1", ["read", "read"], 1000)


def test_zero_ttl_is_rejected():
    with pytest.raises(ValueError):
        cr.grant({}, "alice", "client-1", ["read"], 1000, 0)


def test_store_must_be_dict():
    with pytest.raises(ValueError):
        cr.grant([], "alice", "client-1", ["read"], 1000)


def test_unknown_grant_check_is_false():
    assert cr.check({}, "alice", "client-1", "read", 1000) is False


def test_expired_grant_check_is_false():
    store = {}
    cr.grant(store, "alice", "client-1", ["read"], 1000, 10)
    assert cr.check(store, "alice", "client-1", "read", 2000) is False


def test_missing_scope_check_is_false():
    store = {}
    cr.grant(store, "alice", "client-1", ["read"], 1000)
    assert cr.check(store, "alice", "client-1", "write", 1000) is False


def test_revoke_unknown_returns_false():
    assert cr.revoke({}, "missing") is False


def test_non_string_scope_is_rejected():
    with pytest.raises(ValueError):
        cr.grant({}, "alice", "client-1", [123], 1000)


def test_concurrent_grant_only_one_active():
    store = {}
    results = []

    def worker():
        try:
            cr.grant(store, "alice", "client-1", ["read"], 1000)
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        cr.grant({}, "alice", "client-1", ["read"], "now")
