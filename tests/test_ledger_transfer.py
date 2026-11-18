import threading

import pytest

import ledger_transfer as lt


def books():
    return {"alice": 100, "bob": 0, "carol": 0}


def test_unknown_source_is_rejected():
    with pytest.raises(ValueError):
        lt.transfer(books(), {}, "nobody", "bob", 10, "k1")


def test_unknown_destination_is_rejected():
    with pytest.raises(ValueError):
        lt.transfer(books(), {}, "alice", "nobody", 10, "k1")


def test_same_account_is_rejected():
    with pytest.raises(ValueError):
        lt.transfer(books(), {}, "alice", "alice", 10, "k1")


def test_zero_amount_is_rejected():
    with pytest.raises(ValueError):
        lt.transfer(books(), {}, "alice", "bob", 0, "k1")


def test_negative_amount_is_rejected():
    with pytest.raises(ValueError):
        lt.transfer(books(), {}, "alice", "bob", -1, "k1")


def test_float_amount_is_rejected():
    with pytest.raises(ValueError):
        lt.transfer(books(), {}, "alice", "bob", 1.5, "k1")


def test_insufficient_funds_are_rejected():
    with pytest.raises(ValueError):
        lt.transfer(books(), {}, "alice", "bob", 101, "k1")


def test_empty_key_is_rejected():
    with pytest.raises(ValueError):
        lt.transfer(books(), {}, "alice", "bob", 10, "")


def test_non_string_key_is_rejected():
    with pytest.raises(ValueError):
        lt.transfer(books(), {}, "alice", "bob", 10, 123)


def test_ledger_must_be_dict():
    with pytest.raises(ValueError):
        lt.transfer([], {}, "alice", "bob", 10, "k1")


def test_idem_must_be_dict():
    with pytest.raises(ValueError):
        lt.transfer(books(), [], "alice", "bob", 10, "k1")


def test_concurrent_transfers_do_not_overdraw():
    ledger = {"alice": 100, "bob": 0}
    idem = {}
    results = []

    def worker():
        try:
            lt.transfer(ledger, idem, "alice", "bob", 80, "k1")
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_same_key_with_different_payload_conflicts():
    ledger = {"alice": 100, "bob": 0, "carol": 0}
    idem = {}
    lt.transfer(ledger, idem, "alice", "bob", 10, "k1")
    with pytest.raises(ValueError):
        lt.transfer(ledger, idem, "alice", "carol", 10, "k1")


def test_bool_amount_is_rejected():
    with pytest.raises(ValueError):
        lt.transfer(books(), {}, "alice", "bob", True, "k1")


def test_non_integer_amount_is_rejected():
    with pytest.raises(ValueError):
        lt.transfer(books(), {}, "alice", "bob", "10", "k1")
