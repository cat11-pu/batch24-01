import pytest

from pricing_engine import quote

RULES = {"currency": "USD", "tax_bps": 1000, "discount_bps": 500, "max_discount": 1000, "min_total": 100}
GOOD = [{"sku": "A", "qty": 2, "unit_price": 500, "category": "book"}]


def test_empty_items_is_rejected():
    with pytest.raises(ValueError):
        quote([], RULES)


def test_non_list_items_is_rejected():
    with pytest.raises(ValueError):
        quote({"sku": "A"}, RULES)


def test_zero_quantity_is_rejected():
    with pytest.raises(ValueError):
        quote([{**GOOD[0], "qty": 0}], RULES)


def test_quantity_over_limit_is_rejected():
    with pytest.raises(ValueError):
        quote([{**GOOD[0], "qty": 1000}], RULES)


def test_float_quantity_is_rejected():
    with pytest.raises(ValueError):
        quote([{**GOOD[0], "qty": 1.5}], RULES)


def test_negative_price_is_rejected():
    with pytest.raises(ValueError):
        quote([{**GOOD[0], "unit_price": -1}], RULES)


def test_float_price_is_rejected():
    with pytest.raises(ValueError):
        quote([{**GOOD[0], "unit_price": 1.5}], RULES)


def test_duplicate_sku_is_rejected():
    with pytest.raises(ValueError):
        quote([GOOD[0], {**GOOD[0]}], RULES)


def test_bad_currency_is_rejected():
    with pytest.raises(ValueError):
        quote(GOOD, {**RULES, "currency": "usd"})


def test_tax_rate_over_limit_is_rejected():
    with pytest.raises(ValueError):
        quote(GOOD, {**RULES, "tax_bps": 10001})


def test_negative_discount_is_rejected():
    with pytest.raises(ValueError):
        quote(GOOD, {**RULES, "discount_bps": -1})


def test_negative_max_discount_is_rejected():
    with pytest.raises(ValueError):
        quote(GOOD, {**RULES, "max_discount": -1})


def test_below_minimum_total_is_rejected():
    with pytest.raises(ValueError):
        quote(GOOD, {**RULES, "min_total": 5000})


def test_total_overflow_is_rejected():
    with pytest.raises(ValueError):
        quote([{**GOOD[0], "qty": 999, "unit_price": 1000000000}], RULES)


def test_valid_order_returns_exact_totals():
    out = quote(GOOD, RULES)
    assert out == {"subtotal": 1000, "discount": 50, "tax": 95, "total": 1045}
