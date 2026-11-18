import threading

import pytest

import payment_reconciliation as pr


def test_local_must_be_dict():
    with pytest.raises(ValueError):
        pr.reconcile([], {"t1": 1}, 1000)


def test_remote_must_be_dict():
    with pytest.raises(ValueError):
        pr.reconcile({"t1": 1}, [], 1000)


def test_negative_amount_is_rejected():
    with pytest.raises(ValueError):
        pr.reconcile({"t1": -1}, {"t1": -1}, 1000)


def test_float_amount_is_rejected():
    with pytest.raises(ValueError):
        pr.reconcile({"t1": 1.5}, {"t1": 1}, 1000)


def test_empty_transaction_id_is_rejected():
    with pytest.raises(ValueError):
        pr.reconcile({"": 1}, {"": 1}, 1000)


def test_non_string_transaction_id_is_rejected():
    with pytest.raises(ValueError):
        pr.reconcile({1: 1}, {1: 1}, 1000)


def test_missing_local_is_reported():
    out = pr.reconcile({"t1": 100}, {"t1": 100, "t2": 200}, 1000)
    assert out["missing_local"] == ["t2"]


def test_missing_remote_is_reported():
    out = pr.reconcile({"t1": 100, "t2": 200}, {"t1": 100}, 1000)
    assert out["missing_remote"] == ["t2"]


def test_mismatched_amount_is_reported():
    out = pr.reconcile({"t1": 100}, {"t1": 200}, 1000)
    assert out["mismatched"] == ["t1"]


def test_matched_count_is_correct():
    out = pr.reconcile({"t1": 100, "t2": 200}, {"t1": 100, "t2": 200}, 1000)
    assert out["matched"] == 2


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        pr.reconcile({"t1": 1}, {"t1": 1}, "now")


def test_bool_amount_is_rejected():
    with pytest.raises(ValueError):
        pr.reconcile({"t1": True}, {"t1": 1}, 1000)


def test_string_amount_is_rejected():
    with pytest.raises(ValueError):
        pr.reconcile({"t1": "100"}, {"t1": 100}, 1000)


def test_multiple_differences_are_sorted():
    out = pr.reconcile({"t1": 1, "t2": 2}, {"t1": 9, "t3": 3}, 1000)
    assert out["mismatched"] == ["t1"]
    assert out["missing_local"] == ["t3"]
    assert out["missing_remote"] == ["t2"]


def test_concurrent_reconciliation_is_consistent():
    results = []

    def worker():
        results.append(pr.reconcile({"t1": 100}, {"t1": 100}, 1000)["matched"])

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [1, 1]
