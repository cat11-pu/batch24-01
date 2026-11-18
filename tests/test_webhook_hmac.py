import hashlib
import hmac

import pytest

from webhook_hmac import verify

SECRET = "s" * 32
BODY = b'{"a":1}'


def sign(body, secret, ts="1000"):
    digest = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return {"x-signature": "sha256=" + digest, "x-timestamp": ts}


def rejected(headers, body=BODY, secret=SECRET, now=1000, cache=None):
    try:
        assert verify(headers, body, secret, now, {} if cache is None else cache, 300) is False
    except ValueError:
        return


def test_missing_signature_is_rejected():
    rejected({"x-timestamp": "1000"})


def test_malformed_signature_is_rejected():
    rejected({"x-signature": "bad", "x-timestamp": "1000"})


def test_wrong_signature_is_rejected():
    headers = sign(BODY, "x" * 32)
    rejected(headers)


def test_old_timestamp_is_rejected():
    headers = sign(BODY, SECRET, "699")
    rejected(headers)


def test_future_timestamp_is_rejected():
    headers = sign(BODY, SECRET, "1301")
    rejected(headers)


def test_replay_is_rejected():
    headers = sign(BODY, SECRET)
    cache = {headers["x-signature"]: True}
    rejected(headers, cache=cache)


def test_empty_secret_is_rejected():
    with pytest.raises(ValueError):
        verify(sign(BODY, SECRET), BODY, "", 1000, {}, 300)


def test_body_must_be_bytes():
    with pytest.raises(ValueError):
        verify(sign(BODY, SECRET), "body", SECRET, 1000, {}, 300)


def test_cache_must_be_dict():
    with pytest.raises(ValueError):
        verify(sign(BODY, SECRET), BODY, SECRET, 1000, [], 300)


def test_missing_timestamp_is_rejected():
    rejected({"x-signature": "sha256=" + "0" * 64})


def test_non_integer_timestamp_is_rejected():
    headers = sign(BODY, SECRET, "now")
    rejected(headers)


def test_wrong_algorithm_prefix_is_rejected():
    headers = sign(BODY, SECRET)
    headers["x-signature"] = "md5=" + headers["x-signature"].split("=")[1]
    rejected(headers)


def test_tampered_body_is_rejected():
    headers = sign(BODY, SECRET)
    rejected(headers, body=b'{"a":2}')


def test_headers_must_be_dict():
    with pytest.raises(ValueError):
        verify("headers", BODY, SECRET, 1000, {}, 300)


def test_concurrent_replay_only_one_succeeds():
    import threading

    headers = sign(BODY, SECRET)
    cache = {}
    results = []

    def worker():
        try:
            assert verify(headers, BODY, SECRET, 1000, cache, 300) is True
            results.append(True)
        except (ValueError, AssertionError):
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
