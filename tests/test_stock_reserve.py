import pytest

from stock_reserve import reserve

BAD_CASES = [
    (-1, 1),
    (1, -1),
    (1, 0),
    (1, 1.5),
    (1, "1"),
    (1, True),
    (1, None),
    (1, 2),
    (1.5, 1),
    ("1", 1),
    (None, 1),
    (True, 1),
    (1, 101),
    (1, 1),
]


@pytest.mark.parametrize("stock,qty", BAD_CASES)
def test_bad_stock_or_quantity_is_rejected(stock, qty):
    with pytest.raises(ValueError):
        reserve(stock, qty, {}, 100)


def test_reservations_must_be_dict():
    with pytest.raises(ValueError):
        reserve(10, 1, [], 100)
