import threading

import pytest

import payment_state as ps

AUTH = {"status": "authorized", "amount": 100, "currency": "USD"}


def test_duplicate_capture_is_rejected():
    paid = ps.apply_event(dict(AUTH), "capture", 100, "USD")
    with pytest.raises(ValueError):
        ps.apply_event(paid, "capture", 100, "USD")


def test_refund_before_capture_is_rejected():
    with pytest.raises(ValueError):
        ps.apply_event(dict(AUTH), "refund", 10, "USD")


def test_void_after_capture_is_rejected():
    paid = ps.apply_event(dict(AUTH), "capture", 100, "USD")
    with pytest.raises(ValueError):
        ps.apply_event(paid, "void")


def test_currency_mismatch_is_rejected():
    with pytest.raises(ValueError):
        ps.apply_event(dict(AUTH), "capture", 100, "EUR")


def test_capture_amount_mismatch_is_rejected():
    with pytest.raises(ValueError):
        ps.apply_event(dict(AUTH), "capture", 90, "USD")


def test_negative_refund_is_rejected():
    paid = ps.apply_event(dict(AUTH), "capture", 100, "USD")
    with pytest.raises(ValueError):
        ps.apply_event(paid, "refund", -1, "USD")


def test_refund_over_captured_is_rejected():
    paid = ps.apply_event(dict(AUTH), "capture", 100, "USD")
    with pytest.raises(ValueError):
        ps.apply_event(paid, "refund", 101, "USD")


def test_unknown_event_is_rejected():
    with pytest.raises(ValueError):
        ps.apply_event(dict(AUTH), "chargeback", 10, "USD")


def test_empty_event_is_rejected():
    with pytest.raises(ValueError):
        ps.apply_event(dict(AUTH), "", 10, "USD")


def test_non_dict_state_is_rejected():
    with pytest.raises(ValueError):
        ps.apply_event("authorized", "capture", 100, "USD")


def test_missing_status_is_rejected():
    with pytest.raises(ValueError):
        ps.apply_event({"amount": 100, "currency": "USD"}, "capture", 100, "USD")


def test_unknown_status_is_rejected():
    with pytest.raises(ValueError):
        ps.apply_event({"status": "weird", "amount": 100, "currency": "USD"}, "capture", 100, "USD")


def test_non_string_currency_is_rejected():
    with pytest.raises(ValueError):
        ps.apply_event(dict(AUTH), "capture", 100, 123)


def test_double_refund_over_captured_is_rejected():
    paid = ps.apply_event(dict(AUTH), "capture", 100, "USD")
    once = ps.apply_event(paid, "refund", 60, "USD")
    with pytest.raises(ValueError):
        ps.apply_event(once, "refund", 50, "USD")


def test_concurrent_capture_only_one_succeeds():
    results = []

    def worker():
        try:
            ps.apply_event(dict(AUTH), "capture", 100, "USD")
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
