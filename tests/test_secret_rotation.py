import threading

import pytest

import secret_rotation as sr


def test_unknown_service_is_rejected():
    with pytest.raises(ValueError):
        sr.rotate({}, "api", "s" * 32, 1000)


def test_empty_secret_is_rejected():
    with pytest.raises(ValueError):
        sr.rotate({"api": {"current": "a" * 32, "history": []}}, "api", "", 1000)


def test_short_secret_is_rejected():
    with pytest.raises(ValueError):
        sr.rotate({"api": {"current": "a" * 32, "history": []}}, "api", "short", 1000)


def test_reused_secret_is_rejected():
    current = "a" * 32
    with pytest.raises(ValueError):
        sr.rotate({"api": {"current": current, "history": [current]}}, "api", current, 1000)


def test_negative_overlap_is_rejected():
    with pytest.raises(ValueError):
        sr.rotate({"api": {"current": "a" * 32, "history": []}}, "api", "b" * 32, 1000, -1)


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        sr.rotate({"api": {"current": "a" * 32, "history": []}}, "api", "b" * 32, "now")


def test_empty_service_is_rejected():
    with pytest.raises(ValueError):
        sr.rotate({"api": {"current": "a" * 32, "history": []}}, "", "b" * 32, 1000)


def test_store_must_be_dict():
    with pytest.raises(ValueError):
        sr.rotate([], "api", "b" * 32, 1000)


def test_concurrent_rotation_only_one_succeeds():
    store = {"api": {"current": "a" * 32, "history": []}}
    results = []

    def worker():
        try:
            sr.rotate(store, "api", "b" * 32, 1000)
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_active_secrets_unknown_service_is_rejected():
    with pytest.raises(ValueError):
        sr.active_secrets({}, "api", 1000)


def test_same_as_current_is_rejected():
    current = "a" * 32
    with pytest.raises(ValueError):
        sr.rotate({"api": {"current": current, "history": []}}, "api", current, 1000)


def test_history_must_be_list():
    with pytest.raises(ValueError):
        sr.rotate({"api": {"current": "a" * 32, "history": "x"}}, "api", "b" * 32, 1000)


def test_overlap_over_limit_is_rejected():
    with pytest.raises(ValueError):
        sr.rotate({"api": {"current": "a" * 32, "history": []}}, "api", "b" * 32, 1000, 100000)


def test_non_string_secret_is_rejected():
    with pytest.raises(ValueError):
        sr.rotate({"api": {"current": "a" * 32, "history": []}}, "api", 123, 1000)


def test_active_secrets_returns_current_after_rotation():
    store = {"api": {"current": "a" * 32, "history": []}}
    sr.rotate(store, "api", "b" * 32, 1000, 300)
    out = sr.active_secrets(store, "api", 1001)
    assert "b" * 32 in out
