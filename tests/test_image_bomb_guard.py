import pytest

from image_bomb_guard import validate_image

BAD_CASES = [
    (0, 100, 1000),
    (100, 0, 1000),
    (-1, 100, 1000),
    (100, -1, 1000),
    (100, 100, -1),
    (20001, 100, 1000),
    (100, 20001, 1000),
    (10000, 10000, 1000),
    (1.5, 100, 1000),
    (100, 1.5, 1000),
    (100, 100, 1.5),
    ("100", 100, 1000),
    (100, None, 1000),
    (True, 100, 1000),
    (100, 100, 10000001),
]


@pytest.mark.parametrize("width,height,size", BAD_CASES)
def test_bad_image_is_rejected(width, height, size):
    with pytest.raises(ValueError):
        validate_image(width, height, size, 20000, 50000000, 10000000)
