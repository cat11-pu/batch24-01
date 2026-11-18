import hashlib
import hmac
import threading

import pytest

import hotp_window as hw


def hotp(secret, counter, digits=6):
    digest = hmac.new(secret.encode(), counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def test_empty_code_is_rejected():
    with pytest.raises(ValueError):
        hw.verify("", "secret", 5, set(), 3, 6)


def test_none_code_is_rejected():
    with pytest.raises(ValueError):
        hw.verify(None, "secret", 5, set(), 3, 6)


def test_non_string_code_is_rejected():
    with pytest.raises(ValueError):
        hw.verify(123456, "secret", 5, set(), 3, 6)


def test_short_code_is_rejected():
    with pytest.raises(ValueError):
        hw.verify("12345", "secret", 5, set(), 3, 6)


def test_non_digit_code_is_rejected():
    with pytest.raises(ValueError):
        hw.verify("abcdef", "secret", 5, set(), 3, 6)


def test_wrong_code_is_rejected():
    with pytest.raises(ValueError):
        hw.verify("999999", "secret", 5, set(), 3, 6)


def test_negative_counter_is_rejected():
    with pytest.raises(ValueError):
        hw.verify(hotp("secret", 5), "secret", -1, set(), 3, 6)


def test_zero_window_is_rejected():
    with pytest.raises(ValueError):
        hw.verify(hotp("secret", 5), "secret", 5, set(), 0, 6)


def test_empty_secret_is_rejected():
    with pytest.raises(ValueError):
        hw.verify(hotp("secret", 5), "", 5, set(), 3, 6)


def test_invalid_digits_are_rejected():
    with pytest.raises(ValueError):
        hw.verify(hotp("secret", 5), "secret", 5, set(), 3, 0)


def test_valid_code_returns_next_counter():
    assert hw.verify(hotp("secret", 5), "secret", 5, set(), 3, 6) == 6


def test_lookahead_code_is_accepted():
    assert hw.verify(hotp("secret", 7), "secret", 5, set(), 3, 6) == 8


def test_used_counter_cannot_be_replayed():
    code = hotp("secret", 5)
    next_counter = hw.verify(code, "secret", 5, set(), 3, 6)
    with pytest.raises(ValueError):
        hw.verify(code, "secret", 5, {next_counter - 1}, 3, 6)


def test_concurrent_same_code_only_one_succeeds():
    code = hotp("secret", 5)
    used = set()
    results = []

    def worker():
        try:
            value = hw.verify(code, "secret", 5, used, 3, 6)
            results.append(value >= 0)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_non_set_used_is_rejected():
    with pytest.raises(ValueError):
        hw.verify(hotp("secret", 5), "secret", 5, [], 3, 6)
