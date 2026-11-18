import pytest

from graphql_guard import validate_query

BAD_QUERIES = [
    "{ a { b { c { d { e { f } } } } } }",
    "{" + " ".join(f"a{i}: user" for i in range(200)) + "}",
    "fragment A on User { ...A } { user { ...A } }",
    "{ __schema { types { name } } }",
    "{ __type(name: \"User\") { fields { name } } }",
    "query " + "a" * 10001 + " { user }",
    "",
    "query A { user } query A { user }",
    "query($a:String,$b:String,$c:String,$d:String,$e:String){user}",
    "{ user @include(if: true) @include(if: true) @include(if: true) }",
    "{ user { ...F } } fragment F on User { ...G } fragment G on User { ...F }",
    "{ a { b { c { d { e { f { g { h { i { j } } } } } } } } } }",
    "{ user { posts { comments { author { posts { comments { id } } } } } } }",
    "{ " + " ".join(f"f{i}" for i in range(500)) + " }",
    123,
]


@pytest.mark.parametrize("query", BAD_QUERIES)
def test_bad_graphql_query_is_rejected(query):
    with pytest.raises((ValueError, TypeError)):
        validate_query(query)
