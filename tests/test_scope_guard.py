import pytest

from scope_guard import check_scope

BAD_CASES = [
    ([], ["read"]),
    (["read"], ["write"]),
    (["read"], ["read", "write"]),
    (["*"], ["admin"]),
    (["read:*"], ["read:users"]),
    (["admin"], ["ADMIN"]),
    ([""], ["read"]),
    (["read"], [""]),
    ("read", ["read"]),
    (["read"], "read"),
    (None, ["read"]),
    (["read"], None),
    ([123], ["read"]),
    (["read"], [123]),
    (["read", "read"], ["read"]),
]


@pytest.mark.parametrize("granted,required", BAD_CASES)
def test_scope_escalation_is_rejected(granted, required):
    with pytest.raises(ValueError):
        check_scope(granted, required)
