import pytest

from ldap_guard import escape_filter


def test_1_star_is_escaped():
    assert escape_filter("*") == r"\2a"


def test_2_open_paren_is_escaped():
    assert escape_filter("(") == r"\28"


def test_3_close_paren_is_escaped():
    assert escape_filter(")") == r"\29"


def test_4_backslash_is_escaped():
    assert escape_filter("\\") == r"\5c"


def test_5_nul_is_escaped():
    assert escape_filter("\x00") == r"\00"


def test_6_filter_injection_payload_is_escaped():
    assert escape_filter("*)(uid=*") == r"\2a\29\28uid=\2a"


def test_7_empty_value_is_rejected():
    with pytest.raises(ValueError):
        escape_filter("")


def test_8_non_string_value_is_rejected():
    with pytest.raises(TypeError):
        escape_filter(123)


def test_9_prefix_wildcard_is_escaped():
    assert escape_filter("admin*") == r"admin\2a"


def test_10_parentheses_inside_value_are_escaped():
    assert escape_filter("a(b)c") == r"a\28b\29c"


def test_11_backslash_star_is_escaped():
    assert escape_filter("\\*") == r"\5c\2a"


def test_12_newline_is_escaped():
    assert escape_filter("\n") == r"\0a"


def test_13_carriage_return_is_escaped():
    assert escape_filter("\r") == r"\0d"


def test_14_nested_filter_payload_is_escaped():
    assert escape_filter(")(cn=*))(|(cn=*") == r"\29\28cn=\2a\29\29\28|\28cn=\2a"


def test_15_uid_wildcard_is_escaped():
    assert escape_filter("uid=*") == r"uid=\2a"
