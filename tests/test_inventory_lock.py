import threading

import pytest

import inventory_lock as inv


def test_empty_sku_is_rejected():
    with pytest.raises(ValueError):
        inv.reserve({"A": 10}, {}, "", 1, 1000)


def test_zero_quantity_is_rejected():
    with pytest.raises(ValueError):
        inv.reserve({"A": 10}, {}, "A", 0, 1000)


def test_negative_quantity_is_rejected():
    with pytest.raises(ValueError):
        inv.reserve({"A": 10}, {}, "A", -1, 1000)


def test_float_quantity_is_rejected():
    with pytest.raises(ValueError):
        inv.reserve({"A": 10}, {}, "A", 1.5, 1000)


def test_unknown_sku_is_rejected():
    with pytest.raises(ValueError):
        inv.reserve({}, {}, "A", 1, 1000)


def test_stock_must_be_dict():
    with pytest.raises(ValueError):
        inv.reserve([], {}, "A", 1, 1000)


def test_reservations_must_be_dict():
    with pytest.raises(ValueError):
        inv.reserve({"A": 10}, [], "A", 1, 1000)


def test_non_positive_ttl_is_rejected():
    with pytest.raises(ValueError):
        inv.reserve({"A": 10}, {}, "A", 1, 1000, 0)


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        inv.reserve({"A": 10}, {}, "A", 1, "now")


def test_oversell_is_rejected():
    with pytest.raises(ValueError):
        inv.reserve({"A": 5}, {}, "A", 6, 1000)


def test_expired_reservation_is_released():
    reservations = {"A": [{"id": "old", "qty": 5, "expires": 900}]}
    rid = inv.reserve({"A": 5}, reservations, "A", 5, 1000)
    assert len(rid) >= 16


def test_concurrent_oversell_only_one_succeeds():
    results = []

    def worker():
        try:
            inv.reserve({"A": 10}, {}, "A", 6, 1000)
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_active_reservations_reduce_available():
    reservations = {"A": [{"id": "live", "qty": 8, "expires": 2000}]}
    with pytest.raises(ValueError):
        inv.reserve({"A": 10}, reservations, "A", 3, 1000)


def test_reservation_ids_are_unique():
    assert inv.reserve({"A": 10}, {}, "A", 1, 1000) != inv.reserve({"A": 10}, {}, "A", 1, 1001)


def test_bool_quantity_is_rejected():
    with pytest.raises(ValueError):
        inv.reserve({"A": 10}, {}, "A", True, 1000)
