import threading

import pytest

import refund_workflow as rw

PAID = {"status": "paid", "captured": 1000, "refunded": 0, "currency": "USD", "requester": "alice", "approvals": []}


def test_request_on_created_order_is_rejected():
    with pytest.raises(ValueError):
        rw.apply({"status": "created", "captured": 1000, "refunded": 0, "requester": "alice", "approvals": []}, "request", 100, "alice")


def test_zero_refund_is_rejected():
    with pytest.raises(ValueError):
        rw.apply(dict(PAID), "request", 0, "alice")


def test_refund_over_remaining_is_rejected():
    with pytest.raises(ValueError):
        rw.apply(dict(PAID), "request", 1001, "alice")


def test_empty_actor_is_rejected():
    with pytest.raises(ValueError):
        rw.apply(dict(PAID), "request", 100, "")


def test_requester_cannot_approve_own_refund():
    requested = rw.apply(dict(PAID), "request", 100, "alice")
    with pytest.raises(ValueError):
        rw.apply(requested, "approve", 0, "alice")


def test_execute_without_approval_is_rejected():
    requested = rw.apply(dict(PAID), "request", 100, "alice")
    with pytest.raises(ValueError):
        rw.apply(requested, "execute", 0, "bob")


def test_reject_after_refund_is_rejected():
    state = {"status": "refunded", "captured": 1000, "refunded": 1000, "requester": "alice", "approvals": []}
    with pytest.raises(ValueError):
        rw.apply(state, "reject", 0, "bob")


def test_unknown_event_is_rejected():
    with pytest.raises(ValueError):
        rw.apply(dict(PAID), "chargeback", 0, "bob")


def test_non_dict_state_is_rejected():
    with pytest.raises(ValueError):
        rw.apply("paid", "request", 100, "alice")


def test_missing_status_is_rejected():
    with pytest.raises(ValueError):
        rw.apply({"captured": 1000, "refunded": 0, "requester": "alice", "approvals": []}, "request", 100, "alice")


def test_unknown_status_is_rejected():
    with pytest.raises(ValueError):
        rw.apply({"status": "weird", "captured": 1000, "refunded": 0, "requester": "alice", "approvals": []}, "request", 100, "alice")


def test_double_execute_is_rejected():
    state = rw.apply(dict(PAID), "request", 100, "alice")
    state = rw.apply(state, "approve", 0, "bob")
    state = rw.apply(state, "execute", 0, "bob")
    with pytest.raises(ValueError):
        rw.apply(state, "execute", 0, "bob")


def test_concurrent_execute_only_one_succeeds():
    state = rw.apply(dict(PAID), "request", 100, "alice")
    state = rw.apply(state, "approve", 0, "bob")
    results = []

    def worker():
        try:
            rw.apply(state, "execute", 0, "bob")
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_duplicate_approver_is_rejected():
    state = rw.apply(dict(PAID), "request", 600, "alice")
    state = rw.apply(state, "approve", 0, "bob")
    with pytest.raises(ValueError):
        rw.apply(state, "approve", 0, "bob")


def test_float_amount_is_rejected():
    with pytest.raises(ValueError):
        rw.apply(dict(PAID), "request", 1.5, "alice")
