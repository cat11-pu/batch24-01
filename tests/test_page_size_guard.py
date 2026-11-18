import pytest

from page_size_guard import paginate

BAD_CASES = [
    (100, 1, 0),
    (100, 1, -1),
    (100, 1, 101),
    (100, 1, 10000),
    (100, 1, 1.5),
    (100, 1, "10"),
    (100, 0, 10),
    (100, -1, 10),
    (100, 1.5, 10),
    (100, "1", 10),
    (-1, 1, 10),
    (1000000000, 1, 10),
    (1.5, 1, 10),
    (None, 1, 10),
    (100, 1, True),
]


@pytest.mark.parametrize("total,page,size", BAD_CASES)
def test_bad_pagination_is_rejected(total, page, size):
    with pytest.raises(ValueError):
        paginate(total, page, size, 100, 1000000)
