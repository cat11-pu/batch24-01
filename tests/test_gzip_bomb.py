import pytest

from gzip_bomb import validate_gzip

BAD_CASES = [
    (0, 0),
    (0, 100),
    (-1, 100),
    (100, -1),
    (1, 101),
    (1, 1000),
    (1000, 100000000),
    (1, 50000001),
    (1.5, 100),
    (1, 1.5),
    ("1", 100),
    (1, None),
    (True, 100),
    (1, True),
    (1, 10000000000),
]


@pytest.mark.parametrize("compressed,uncompressed", BAD_CASES)
def test_bad_gzip_size_is_rejected(compressed, uncompressed):
    with pytest.raises(ValueError):
        validate_gzip(compressed, uncompressed, 100, 50000000)
