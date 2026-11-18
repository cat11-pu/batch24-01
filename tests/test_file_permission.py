import pytest

from file_permission import check_mode

BAD_MODES = [
    0o777,
    0o666,
    0o622,
    0o755,
    0o744,
    0o4755,
    0o2755,
    0o1755,
    -1,
    1.5,
    "644",
    None,
    True,
    0o100000,
    0o602,
]


@pytest.mark.parametrize("mode", BAD_MODES)
def test_unsafe_file_mode_is_rejected(mode):
    with pytest.raises(ValueError):
        check_mode(mode, "/srv/uploads/a.txt", 0o600)
