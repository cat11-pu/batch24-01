import pytest

from hpp_guard import parse_query

BAD_QUERIES = [
    "a=1&a=2",
    "a=1&a=1",
    "a[]=1&a[]=2",
    "a=1&b=2&a=3",
    "a=1&a",
    "a=1&&a=2",
    "a[b]=1&a[b]=2",
    "a=1&%61=2",
    "a=1&a=2&a=3",
    "a=1;b=2",
    "?a=1&a=2",
    "a=1&a=2#x",
    "a=1&a=2\n",
    "a=1&a=2\x00",
    "a=1&a=%32",
]


@pytest.mark.parametrize("qs", BAD_QUERIES)
def test_duplicate_or_ambiguous_query_is_rejected(qs):
    with pytest.raises(ValueError):
        parse_query(qs)
