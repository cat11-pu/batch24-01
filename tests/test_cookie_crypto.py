import threading

import pytest

import cookie_crypto as cc

KEYS = {"k1": "s" * 32}


def test_empty_token_is_rejected():
    with pytest.raises(ValueError):
        cc.open_token("", KEYS, 1000)


def test_none_token_is_rejected():
    with pytest.raises(ValueError):
        cc.open_token(None, KEYS, 1000)


def test_malformed_token_is_rejected():
    with pytest.raises(ValueError):
        cc.open_token("x", KEYS, 1000)


def test_wrong_key_is_rejected():
    token = cc.seal({"a": 1}, KEYS, 1000)
    with pytest.raises(ValueError):
        cc.open_token(token, {"k1": "z" * 32}, 1000)


def test_tampered_token_is_rejected():
    token = cc.seal({"a": 1}, KEYS, 1000)
    with pytest.raises(ValueError):
        cc.open_token(token + "x", KEYS, 1000)


def test_expired_token_is_rejected():
    token = cc.seal({"a": 1}, KEYS, 1000)
    with pytest.raises(ValueError):
        cc.open_token(token, KEYS, 2000, 300)


def test_future_token_is_rejected():
    token = cc.seal({"a": 1}, KEYS, 2000)
    with pytest.raises(ValueError):
        cc.open_token(token, KEYS, 1000, 300)


def test_non_dict_payload_is_rejected():
    with pytest.raises(ValueError):
        cc.seal([1, 2], KEYS, 1000)


def test_empty_keys_are_rejected():
    with pytest.raises(ValueError):
        cc.seal({"a": 1}, {}, 1000)


def test_unknown_kid_is_rejected():
    token = cc.seal({"a": 1}, KEYS, 1000)
    with pytest.raises(ValueError):
        cc.open_token(token, {}, 1000)


def test_missing_signature_is_rejected():
    with pytest.raises(ValueError):
        cc.open_token("abc.def", KEYS, 1000)


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        cc.open_token("x", KEYS, "now")


def test_extra_segments_are_rejected():
    token = cc.seal({"a": 1}, KEYS, 1000)
    with pytest.raises(ValueError):
        cc.open_token(token + ".x", KEYS, 1000)


def test_concurrent_seals_are_unique():
    values = []
    lock = threading.Lock()

    def worker():
        value = cc.seal({"a": 1}, KEYS, 1000)
        with lock:
            values.append(value)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(values)) == 2


def test_non_string_token_is_rejected():
    with pytest.raises(ValueError):
        cc.open_token(123, KEYS, 1000)
