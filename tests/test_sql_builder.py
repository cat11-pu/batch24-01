import pytest

from sql_builder import build_query

SCHEMA = {"users": ["id", "name", "email"]}


def test_unknown_table_is_rejected():
    with pytest.raises(ValueError):
        build_query("postgres", SCHEMA, "orders", ["id"], {})


def test_unknown_column_is_rejected():
    with pytest.raises(ValueError):
        build_query("postgres", SCHEMA, "users", ["password"], {})


def test_unknown_dialect_is_rejected():
    with pytest.raises(ValueError):
        build_query("oracle", SCHEMA, "users", ["id"], {})


def test_injection_in_order_by_is_rejected():
    with pytest.raises(ValueError):
        build_query("postgres", SCHEMA, "users", ["id"], {}, "name; DROP TABLE users")


def test_bad_order_direction_is_rejected():
    with pytest.raises(ValueError):
        build_query("postgres", SCHEMA, "users", ["id"], {}, "name", "sideways", 10)


def test_empty_columns_is_rejected():
    with pytest.raises(ValueError):
        build_query("postgres", SCHEMA, "users", [], {})


def test_unknown_filter_key_is_rejected():
    with pytest.raises(ValueError):
        build_query("postgres", SCHEMA, "users", ["id"], {"role": "admin"})


def test_filter_value_is_parameterized():
    sql, params = build_query("postgres", SCHEMA, "users", ["name"], {"name": "x' OR '1'='1"})
    assert "x' OR '1'='1" not in sql
    assert params == ["x' OR '1'='1"]


def test_like_wildcards_are_escaped():
    sql, params = build_query("postgres", SCHEMA, "users", ["name"], {"name__like": "a%b"})
    assert params == ["a\\%b"]


def test_postgres_identifiers_are_quoted():
    sql, params = build_query("postgres", SCHEMA, "users", ["name"], {})
    assert '"users"' in sql and '"name"' in sql


def test_mysql_identifiers_are_quoted():
    sql, params = build_query("mysql", SCHEMA, "users", ["name"], {})
    q = chr(96)
    assert (q + "users" + q) in sql and (q + "name" + q) in sql


def test_empty_column_name_is_rejected():
    with pytest.raises(ValueError):
        build_query("postgres", SCHEMA, "users", [""], {})


def test_non_string_table_is_rejected():
    with pytest.raises(ValueError):
        build_query("postgres", SCHEMA, 123, ["id"], {})


def test_negative_limit_is_rejected():
    with pytest.raises(ValueError):
        build_query("postgres", SCHEMA, "users", ["id"], {}, None, "asc", -1)


def test_column_injection_is_rejected():
    with pytest.raises(ValueError):
        build_query("postgres", SCHEMA, "users", ["id; DROP TABLE users"], {})
