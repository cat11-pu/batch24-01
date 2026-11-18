import pytest

from sql_guard import build_query

BAD_TABLES = [
    "users; DROP TABLE users",
    "users--",
    "users/*x*/",
    "users UNION SELECT password FROM users",
    "",
    None,
    123,
]

BAD_COLUMNS = [
    ["name,password"],
    ["*"],
    ["name;--"],
]


@pytest.mark.parametrize("table", BAD_TABLES)
def test_bad_table_is_rejected(table):
    with pytest.raises(ValueError):
        build_query(table, ["name"])


@pytest.mark.parametrize("columns", BAD_COLUMNS)
def test_bad_column_is_rejected(columns):
    with pytest.raises(ValueError):
        build_query("users", columns)


def test_injection_key_is_rejected():
    with pytest.raises(ValueError):
        build_query("users", ["name"], {"id OR 1=1": "x"})


def test_comment_key_is_rejected():
    with pytest.raises(ValueError):
        build_query("users", ["name"], {"id--": "x"})


def test_value_is_parameterized():
    sql, params = build_query("users", ["name"], {"name": "x' OR '1'='1"})
    assert "x' OR '1'='1" not in sql
    assert params == ["x' OR '1'='1"]


def test_empty_columns_is_rejected():
    with pytest.raises(ValueError):
        build_query("users", [])


def test_columns_must_be_list():
    with pytest.raises(ValueError):
        build_query("users", "name")
