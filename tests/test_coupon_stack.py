import threading

import pytest

import coupon_stack as cs

NOW = 2000
CART = {"total": 1000, "items": [{"sku": "A1", "category": "book", "price": 600}, {"sku": "B2", "category": "game", "price": 400}]}
USER = {"id": "u1", "redeemed": {}}
C1 = {"code": "C1", "type": "percent", "value": 10, "min_spend": 500, "scope": "all", "expires": 3000, "exclusive": False, "per_user": 3}
C2 = {"code": "C2", "type": "fixed", "value": 100, "min_spend": 300, "scope": "all", "expires": 3000, "exclusive": False, "per_user": 3}


def test_empty_coupon_list_is_rejected():
    with pytest.raises(ValueError):
        cs.redeem([], CART, USER, NOW)


def test_more_than_two_coupons_is_rejected():
    with pytest.raises(ValueError):
        cs.redeem([C1, C2, {**C1, "code": "C3", "type": "gift"}], CART, USER, NOW)


def test_duplicate_type_is_rejected():
    with pytest.raises(ValueError):
        cs.redeem([C1, {**C1, "code": "C4"}], CART, USER, NOW)


def test_expired_coupon_is_rejected():
    with pytest.raises(ValueError):
        cs.redeem([{**C1, "expires": 1999}], CART, USER, NOW)


def test_min_spend_is_enforced():
    with pytest.raises(ValueError):
        cs.redeem([{**C1, "min_spend": 5000}], CART, USER, NOW)


def test_product_scope_is_enforced():
    with pytest.raises(ValueError):
        cs.redeem([{**C1, "scope": "sku:Z9"}], CART, USER, NOW)


def test_category_scope_is_enforced():
    with pytest.raises(ValueError):
        cs.redeem([{**C1, "scope": "category:movie"}], CART, USER, NOW)


def test_per_user_limit_is_enforced():
    user = {"id": "u1", "redeemed": {"C1": 3}}
    with pytest.raises(ValueError):
        cs.redeem([C1], CART, user, NOW)


def test_exclusive_coupon_cannot_stack():
    with pytest.raises(ValueError):
        cs.redeem([{**C1, "exclusive": True}, C2], CART, USER, NOW)


def test_negative_cart_total_is_rejected():
    with pytest.raises(ValueError):
        cs.redeem([C1], {**CART, "total": -1}, USER, NOW)


def test_unknown_coupon_is_rejected():
    with pytest.raises(ValueError):
        cs.redeem([{**C1, "code": ""}], CART, USER, NOW)


def test_coupons_must_be_list():
    with pytest.raises(ValueError):
        cs.redeem(C1, CART, USER, NOW)


def test_discount_cannot_exceed_total():
    with pytest.raises(ValueError):
        cs.redeem([{**C1, "value": 2000}], CART, USER, NOW)


def test_valid_stack_returns_discount():
    assert cs.redeem([C1, C2], CART, USER, NOW) == 200


def test_concurrent_redeem_respects_per_user_limit():
    user = {"id": "u1", "redeemed": {"C1": 2}}
    results = []

    def worker():
        try:
            cs.redeem([C1], CART, user, NOW)
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
