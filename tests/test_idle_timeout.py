import pytest

from idle_timeout import check_session

BAD_STATES = [
    (0, 800, 901, 900, 28800),
    (0, 0, 901, 900, 28800),
    (0, 800, 100000, 900, 28800),
    (0, 900, 800, 900, 28800),
    (-1, 0, 10, 900, 28800),
    (None, 0, 10, 900, 28800),
    (0, None, 10, 900, 28800),
    (0, 0, None, 900, 28800),
    (0.0, 0, 10, 900, 28800),
    (0, 0.0, 10, 900, 28800),
    (0, 0, 10.0, 900, 28800),
    ("0", 0, 10, 900, 28800),
    (0, 0, 10, 0, 28800),
    (0, 0, 10, 900, 0),
    (True, 0, 10, 900, 28800),
]


@pytest.mark.parametrize("created,seen,now,idle,absolute", BAD_STATES)
def test_bad_session_state_is_rejected_or_expired(created, seen, now, idle, absolute):
    try:
        result = check_session(created, seen, now, idle, absolute)
    except ValueError:
        return
    assert result is False
