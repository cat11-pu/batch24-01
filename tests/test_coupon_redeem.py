import threading

import pytest

import coupon_redeem as cr


def test_1_empty_coupon_is_rejected():
    with pytest.raises(ValueError):
        cr.redeem("", "alice", 1000)


def test_2_empty_user_is_rejected():
    with pytest.raises(ValueError):
        cr.redeem("C1", "", 1000)


def test_3_unknown_coupon_is_rejected():
    with pytest.raises(ValueError):
        cr.redeem("NOPE", "alice", 1000)


def test_4_expired_coupon_is_rejected():
    with pytest.raises(ValueError):
        cr.redeem("C1", "alice", 999999)


def test_5_used_coupon_cannot_be_reused():
    with pytest.raises(ValueError):
        cr.redeem("C1", "alice", 1000)
    with pytest.raises(ValueError):
        cr.redeem("C1", "alice", 1000)


def test_6_wrong_user_cannot_use_coupon():
    with pytest.raises(ValueError):
        cr.redeem("C1", "bob", 1000)


def test_7_over_limit_coupon_is_rejected():
    with pytest.raises(ValueError):
        cr.redeem("C1", "alice", 1000)


def test_8_negative_time_is_rejected():
    with pytest.raises(ValueError):
        cr.redeem("C1", "alice", -1)


def test_9_non_string_coupon_is_rejected():
    with pytest.raises(TypeError):
        cr.redeem(123, "alice", 1000)


def test_10_non_string_user_is_rejected():
    with pytest.raises(TypeError):
        cr.redeem("C1", 123, 1000)


def test_11_coupon_without_expiry_is_rejected():
    with pytest.raises(ValueError):
        cr.redeem("C1", "alice", 1000)


def test_12_expired_boundary_is_rejected():
    with pytest.raises(ValueError):
        cr.redeem("C1", "alice", 1000)


def test_13_concurrent_redeem_only_one_succeeds():
    results = []

    def worker():
        try:
            results.append(cr.redeem("C1", "alice", 1000))
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1


def test_14_duplicate_user_redeem_is_rejected():
    with pytest.raises(ValueError):
        cr.redeem("C1", "alice", 1000)


def test_15_invalid_state_is_rejected():
    with pytest.raises(ValueError):
        cr.redeem("C1", "alice", 1000)
