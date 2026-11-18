import pytest

from chunked_limit import check_chunked

BAD_CHUNKS = [
    [-1],
    [0],
    [1.5],
    ["1"],
    [None],
    [True],
    [100001],
    [100000, 100000, 100000, 100000, 100000, 100000, 100000, 100000, 100000, 100000, 100001],
    [],
    [1] * 1001,
    [1, 2, 3, -1],
    None,
    "abc",
    123,
    [1, 2**40],
]


@pytest.mark.parametrize("chunks", BAD_CHUNKS)
def test_bad_chunk_sequence_is_rejected(chunks):
    with pytest.raises(ValueError):
        check_chunked(chunks, 1000000, 100000, 1000)
