import pytest

from nosql_guard import sanitize_filter

BAD_FILTERS = [
    {"$ne": None},
    {"$gt": ""},
    {"$or": [{"user": "admin"}, {"user": "root"}]},
    {"$where": "this.password == 'x'"},
    {"$regex": ".*"},
    {"$exists": True},
    {"$in": ["admin", "root"]},
    {"$nin": ["guest"]},
    {"$expr": {"$eq": ["$role", "admin"]}},
    {"user": {"$ne": None}},
    {"user": ["admin", "root"]},
    {"$comment": "x"},
    {"$mod": [2, 1]},
    {"$text": {"$search": "admin"}},
    {"user": {"nested": {"$ne": None}}},
]


@pytest.mark.parametrize("value", BAD_FILTERS)
def test_operator_injection_is_rejected(value):
    with pytest.raises(ValueError):
        sanitize_filter(value)
