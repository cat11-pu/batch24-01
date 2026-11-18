import pytest

from zip_bomb_guard import validate_archive

BAD_ARCHIVES = [
    (1, 1000, 1, 0),
    (1, 100000000, 1, 0),
    (100, 1000000000, 1, 0),
    (1000, 1000, 100000, 0),
    (0, 0, 0, 0),
    (-1, 100, 1, 0),
    (1, -1, 1, 0),
    (1, 100, -1, 0),
    (1, 100, 1, -1),
    (1, 100, 1, 1),
    (1, 10000000, 1, 0),
    (1, 1, 1000000, 0),
    (1, 100, 1, 0),
    (100, 100000, 10000, 0),
    (1, 100, 1, 1),
]


@pytest.mark.parametrize("value", BAD_ARCHIVES)
def test_bad_archive_is_rejected(value):
    with pytest.raises(ValueError):
        validate_archive(*value)
