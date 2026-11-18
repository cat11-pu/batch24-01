import threading

import pytest

import subscription_billing as sb

GOOD = {"status": "active", "plan_price": 1000, "currency": "USD", "period_start": 0, "period_end": 30, "last_billed": None}


def test_canceled_subscription_is_rejected():
    with pytest.raises(ValueError):
        sb.bill({**GOOD, "status": "canceled"}, 30)


def test_past_due_subscription_is_rejected():
    with pytest.raises(ValueError):
        sb.bill({**GOOD, "status": "past_due"}, 30)


def test_billing_before_period_end_is_rejected():
    with pytest.raises(ValueError):
        sb.bill(GOOD, 29)


def test_same_period_cannot_be_billed_twice():
    sub = sb.bill(GOOD, 30)
    with pytest.raises(ValueError):
        sb.bill(sub, 30)


def test_non_dict_subscription_is_rejected():
    with pytest.raises(ValueError):
        sb.bill("sub", 30)


def test_missing_period_end_is_rejected():
    bad = {k: v for k, v in GOOD.items() if k != "period_end"}
    with pytest.raises(ValueError):
        sb.bill(bad, 30)


def test_negative_price_is_rejected():
    with pytest.raises(ValueError):
        sb.bill({**GOOD, "plan_price": -1}, 30)


def test_float_price_is_rejected():
    with pytest.raises(ValueError):
        sb.bill({**GOOD, "plan_price": 1.5}, 30)


def test_bad_currency_is_rejected():
    with pytest.raises(ValueError):
        sb.bill({**GOOD, "currency": "usd"}, 30)


def test_last_billed_in_future_is_rejected():
    with pytest.raises(ValueError):
        sb.bill({**GOOD, "last_billed": 100}, 30)


def test_concurrent_billing_only_one_invoice():
    sub = dict(GOOD)
    results = []

    def worker():
        try:
            sb.bill(sub, 30)
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_period_start_after_end_is_rejected():
    with pytest.raises(ValueError):
        sb.bill({**GOOD, "period_start": 40, "period_end": 30}, 40)


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        sb.bill(GOOD, "now")


def test_zero_price_is_rejected():
    with pytest.raises(ValueError):
        sb.bill({**GOOD, "plan_price": 0}, 30)


def test_missing_currency_is_rejected():
    bad = {k: v for k, v in GOOD.items() if k != "currency"}
    with pytest.raises(ValueError):
        sb.bill(bad, 30)
