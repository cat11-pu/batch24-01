import threading

import pytest

import password_vault as pv


def test_hash_format_has_four_parts():
    parts = pv.hash_password("Secret123456!").split("$")
    assert len(parts) == 4


def test_same_password_gets_different_salts():
    assert pv.hash_password("Secret123456!") != pv.hash_password("Secret123456!")


def test_wrong_password_fails():
    stored = pv.hash_password("Secret123456!")
    assert pv.verify_password("Wrong123456!", stored) is False


def test_empty_password_is_rejected():
    with pytest.raises(ValueError):
        pv.hash_password("")


def test_short_password_is_rejected():
    with pytest.raises(ValueError):
        pv.hash_password("short")


def test_overlong_password_is_rejected():
    with pytest.raises(ValueError):
        pv.hash_password("a" * 200)


def test_non_string_password_is_rejected():
    with pytest.raises(ValueError):
        pv.hash_password(123)


def test_malformed_hash_fails_verification():
    assert pv.verify_password("Secret123456!", "x") is False


def test_empty_hash_fails_verification():
    assert pv.verify_password("Secret123456!", "") is False


def test_old_iterations_need_rehash():
    assert pv.needs_rehash("pbkdf2_sha256$1000$salt$hash") is True


def test_malformed_hash_needs_rehash():
    assert pv.needs_rehash("x") is True


def test_iteration_count_is_high_enough():
    parts = pv.hash_password("Secret123456!").split("$")
    assert int(parts[1]) >= 100000


def test_salt_is_long_enough():
    parts = pv.hash_password("Secret123456!").split("$")
    assert len(parts[2]) >= 16


def test_concurrent_hashes_are_unique():
    values = []
    lock = threading.Lock()

    def worker():
        value = pv.hash_password("Secret123456!")
        with lock:
            values.append(value)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(values)) == 2


def test_tampered_hash_fails_verification():
    stored = pv.hash_password("Secret123456!")
    tampered = stored[:-1] + ("0" if stored[-1] != "0" else "1")
    assert pv.verify_password("Secret123456!", tampered) is False
