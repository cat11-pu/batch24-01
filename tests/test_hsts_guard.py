import pytest

from hsts_guard import hsts_header

BAD_CASES = [
    (0, False, False),
    (-1, False, False),
    (15551999, False, False),
    (1.5, False, False),
    ("31536000", False, False),
    (None, False, False),
    (True, False, False),
    (31536000, "yes", False),
    (31536000, False, "yes"),
    (31536000, False, True),
    (63072001, True, False),
    (31536000, 1, False),
    (31536000, False, 1),
    (31536000, None, False),
    (31536000, False, None),
]


@pytest.mark.parametrize("age,subs,preload", BAD_CASES)
def test_bad_hsts_policy_is_rejected(age, subs, preload):
    with pytest.raises(ValueError):
        hsts_header(age, subs, preload, 15552000, 63072000)
