import threading

import pytest

import webauthn_challenge as wc

NOW = 1000
RP = "app.example"
ORIGIN = "https://app.example"


def test_empty_user_is_rejected():
    with pytest.raises(ValueError):
        wc.create_challenge({}, "", RP, NOW)


def test_zero_ttl_is_rejected():
    with pytest.raises(ValueError):
        wc.create_challenge({}, "alice", RP, NOW, 0)


def test_store_must_be_dict():
    with pytest.raises(ValueError):
        wc.create_challenge([], "alice", RP, NOW)


def test_unknown_challenge_is_rejected():
    with pytest.raises(ValueError):
        wc.verify({}, "nope", "alice", ORIGIN, RP, 1, NOW)


def test_wrong_user_is_rejected():
    store = {}
    challenge = wc.create_challenge(store, "alice", RP, NOW)
    with pytest.raises(ValueError):
        wc.verify(store, challenge, "bob", ORIGIN, RP, 1, NOW)


def test_wrong_origin_is_rejected():
    store = {}
    challenge = wc.create_challenge(store, "alice", RP, NOW)
    with pytest.raises(ValueError):
        wc.verify(store, challenge, "alice", "https://evil.example", RP, 1, NOW)


def test_wrong_rp_id_is_rejected():
    store = {}
    challenge = wc.create_challenge(store, "alice", RP, NOW)
    with pytest.raises(ValueError):
        wc.verify(store, challenge, "alice", ORIGIN, "evil.example", 1, NOW)


def test_expired_challenge_is_rejected():
    store = {}
    challenge = wc.create_challenge(store, "alice", RP, NOW, 300)
    with pytest.raises(ValueError):
        wc.verify(store, challenge, "alice", ORIGIN, RP, 1, 1301)


def test_reused_challenge_is_rejected():
    store = {}
    challenge = wc.create_challenge(store, "alice", RP, NOW)
    wc.verify(store, challenge, "alice", ORIGIN, RP, 1, NOW)
    with pytest.raises(ValueError):
        wc.verify(store, challenge, "alice", ORIGIN, RP, 2, NOW)


def test_sign_count_must_increase():
    store = {}
    challenge = wc.create_challenge(store, "alice", RP, NOW)
    with pytest.raises(ValueError):
        wc.verify(store, challenge, "alice", ORIGIN, RP, 0, NOW)


def test_non_integer_sign_count_is_rejected():
    store = {}
    challenge = wc.create_challenge(store, "alice", RP, NOW)
    with pytest.raises(ValueError):
        wc.verify(store, challenge, "alice", ORIGIN, RP, "1", NOW)


def test_empty_challenge_is_rejected():
    store = {}
    wc.create_challenge(store, "alice", RP, NOW)
    with pytest.raises(ValueError):
        wc.verify(store, "", "alice", ORIGIN, RP, 1, NOW)


def test_http_origin_is_rejected():
    store = {}
    challenge = wc.create_challenge(store, "alice", RP, NOW)
    with pytest.raises(ValueError):
        wc.verify(store, challenge, "alice", "http://app.example", RP, 1, NOW)


def test_challenge_is_long_enough():
    store = {}
    challenge = wc.create_challenge(store, "alice", RP, NOW)
    assert len(challenge) >= 32


def test_concurrent_verification_only_one_succeeds():
    store = {}
    challenge = wc.create_challenge(store, "alice", RP, NOW)
    results = []

    def worker():
        try:
            wc.verify(store, challenge, "alice", ORIGIN, RP, 1, NOW)
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
