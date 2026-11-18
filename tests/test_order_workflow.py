import threading

import pytest

import order_workflow as ow

CREATED = {"status": "created", "amount": 1000, "paid": False, "shipped": False}


def test_ship_before_pay_is_rejected():
    with pytest.raises(ValueError):
        ow.apply(dict(CREATED), "ship", "bob")


def test_deliver_before_ship_is_rejected():
    paid = {"status": "paid", "amount": 1000, "paid": True, "shipped": False}
    with pytest.raises(ValueError):
        ow.apply(paid, "deliver", "bob")


def test_cancel_after_ship_is_rejected():
    shipped = {"status": "shipped", "amount": 1000, "paid": True, "shipped": True}
    with pytest.raises(ValueError):
        ow.apply(shipped, "cancel", "bob")


def test_refund_before_pay_is_rejected():
    with pytest.raises(ValueError):
        ow.apply(dict(CREATED), "refund", "bob", 1000)


def test_pay_twice_is_rejected():
    paid = {"status": "paid", "amount": 1000, "paid": True, "shipped": False}
    with pytest.raises(ValueError):
        ow.apply(paid, "pay", "bob", 1000)


def test_unknown_event_is_rejected():
    with pytest.raises(ValueError):
        ow.apply(dict(CREATED), "teleport", "bob")


def test_empty_actor_is_rejected():
    with pytest.raises(ValueError):
        ow.apply(dict(CREATED), "pay", "", 1000)


def test_non_dict_state_is_rejected():
    with pytest.raises(ValueError):
        ow.apply("created", "pay", "bob", 1000)


def test_missing_status_is_rejected():
    with pytest.raises(ValueError):
        ow.apply({"amount": 1000, "paid": False, "shipped": False}, "pay", "bob", 1000)


def test_unknown_status_is_rejected():
    with pytest.raises(ValueError):
        ow.apply({"status": "weird", "amount": 1000, "paid": False, "shipped": False}, "pay", "bob", 1000)


def test_payment_amount_mismatch_is_rejected():
    with pytest.raises(ValueError):
        ow.apply(dict(CREATED), "pay", "bob", 999)


def test_concurrent_payment_only_one_succeeds():
    state = dict(CREATED)
    results = []

    def worker():
        try:
            ow.apply(state, "pay", "bob", 1000)
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_cancel_after_delivery_is_rejected():
    delivered = {"status": "delivered", "amount": 1000, "paid": True, "shipped": True}
    with pytest.raises(ValueError):
        ow.apply(delivered, "cancel", "bob")


def test_deliver_twice_is_rejected():
    delivered = {"status": "delivered", "amount": 1000, "paid": True, "shipped": True}
    with pytest.raises(ValueError):
        ow.apply(delivered, "deliver", "bob")


def test_non_integer_amount_is_rejected():
    with pytest.raises(ValueError):
        ow.apply(dict(CREATED), "pay", "bob", "1000")
