import pytest

from order_total import total

BAD_ORDERS = [
    ({"a": -1}, {"a": 100}),
    ({"a": 0}, {"a": 100}),
    ({"a": 1.5}, {"a": 100}),
    ({"a": "2"}, {"a": 100}),
    ({"a": True}, {"a": 100}),
    ({"a": None}, {"a": 100}),
    ({"a": 1000}, {"a": 100}),
    ({"a": 1}, {"a": -100}),
    ({"a": 1}, {"a": 1.5}),
    ({"a": 1}, {"a": "100"}),
    ({"a": 1}, {}),
    ({"a": 1, "b": 2}, {"a": 100}),
    ({}, {"a": 100}),
    ([], {"a": 100}),
    ({"a": 1}, {"a": 10000000000}),
]


@pytest.mark.parametrize("items,prices", BAD_ORDERS)
def test_bad_order_is_rejected(items, prices):
    with pytest.raises(ValueError):
        total(items, prices, 999, 1000000)
