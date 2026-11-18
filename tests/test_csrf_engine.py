import threading

import pytest

import csrf_engine as csrf

SECRET = "s" * 32
ALLOWED = ["https://app.example"]


def test_empty_token_is_rejected():
    with pytest.raises(ValueError):
        csrf.check("", "s1", SECRET, 1000, "POST", "https://app.example", ALLOWED, 300)


def test_none_token_is_rejected():
    with pytest.raises(ValueError):
        csrf.check(None, "s1", SECRET, 1000, "POST", "https://app.example", ALLOWED, 300)


def test_wrong_session_is_rejected():
    token = csrf.issue("s1", SECRET, 1000)
    with pytest.raises(ValueError):
        csrf.check(token, "s2", SECRET, 1000, "POST", "https://app.example", ALLOWED, 300)


def test_wrong_secret_is_rejected():
    token = csrf.issue("s1", SECRET, 1000)
    with pytest.raises(ValueError):
        csrf.check(token, "s1", "z" * 32, 1000, "POST", "https://app.example", ALLOWED, 300)


def test_expired_token_is_rejected():
    token = csrf.issue("s1", SECRET, 1000)
    with pytest.raises(ValueError):
        csrf.check(token, "s1", SECRET, 2000, "POST", "https://app.example", ALLOWED, 300)


def test_tampered_token_is_rejected():
    token = csrf.issue("s1", SECRET, 1000)
    with pytest.raises(ValueError):
        csrf.check(token + "x", "s1", SECRET, 1000, "POST", "https://app.example", ALLOWED, 300)


def test_missing_origin_is_rejected():
    token = csrf.issue("s1", SECRET, 1000)
    with pytest.raises(ValueError):
        csrf.check(token, "s1", SECRET, 1000, "POST", "", ALLOWED, 300)


def test_untrusted_origin_is_rejected():
    token = csrf.issue("s1", SECRET, 1000)
    with pytest.raises(ValueError):
        csrf.check(token, "s1", SECRET, 1000, "POST", "https://evil.example", ALLOWED, 300)


def test_connect_method_is_rejected():
    token = csrf.issue("s1", SECRET, 1000)
    with pytest.raises(ValueError):
        csrf.check(token, "s1", SECRET, 1000, "CONNECT", "https://app.example", ALLOWED, 300)


def test_rotation_invalidates_old_token():
    old = csrf.issue("s1", SECRET, 1000)
    csrf.check(old, "s1", SECRET, 1000, "POST", "https://app.example", ALLOWED, 300)
    csrf.issue("s1", SECRET, 1001)
    with pytest.raises(ValueError):
        csrf.check(old, "s1", SECRET, 1002, "POST", "https://app.example", ALLOWED, 300)


def test_empty_secret_is_rejected():
    with pytest.raises(ValueError):
        csrf.issue("s1", "", 1000)


def test_zero_ttl_is_rejected():
    with pytest.raises(ValueError):
        csrf.issue("s1", SECRET, 1000, 0)


def test_http_origin_is_rejected():
    token = csrf.issue("s1", SECRET, 1000)
    with pytest.raises(ValueError):
        csrf.check(token, "s1", SECRET, 1000, "POST", "http://app.example", ["http://app.example"], 300)


def test_empty_session_is_rejected():
    with pytest.raises(ValueError):
        csrf.issue("", SECRET, 1000)


def test_concurrent_same_token_only_one_succeeds():
    token = csrf.issue("s1", SECRET, 1000)
    results = []

    def worker():
        try:
            csrf.check(token, "s1", SECRET, 1000, "POST", "https://app.example", ALLOWED, 300)
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
