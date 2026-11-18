import pytest

from host_guard import build_cache_key, validate_host


def test_1_empty_host_is_rejected():
    with pytest.raises(ValueError):
        validate_host("")


def test_2_non_standard_port_is_rejected():
    with pytest.raises(ValueError):
        validate_host("api.example.com:8080")


def test_3_userinfo_is_rejected():
    with pytest.raises(ValueError):
        validate_host("user@api.example.com")


def test_4_host_suffix_spoof_is_rejected():
    with pytest.raises(ValueError):
        validate_host("api.example.com.evil.com")


def test_5_unlisted_host_is_rejected():
    with pytest.raises(ValueError):
        validate_host("evil.example.com")


def test_6_ipv4_literal_is_rejected():
    with pytest.raises(ValueError):
        validate_host("127.0.0.1")


def test_7_ipv6_literal_is_rejected():
    with pytest.raises(ValueError):
        validate_host("[::1]")


def test_8_newline_is_rejected():
    with pytest.raises(ValueError):
        validate_host("api.example.com\nX-Evil: 1")


def test_9_nul_is_rejected():
    with pytest.raises(ValueError):
        validate_host("api.example.com\x00evil")


def test_10_tab_is_rejected():
    with pytest.raises(ValueError):
        validate_host("api.example.com\tevil")


def test_11_backslash_is_rejected():
    with pytest.raises(ValueError):
        validate_host("api.example.com\\evil")


def test_12_leading_dot_is_rejected():
    with pytest.raises(ValueError):
        validate_host(".api.example.com")


def test_13_double_trailing_dot_is_rejected():
    with pytest.raises(ValueError):
        validate_host("api.example.com..")


def test_14_non_string_host_is_rejected():
    with pytest.raises(TypeError):
        validate_host(123)


def test_15_cache_key_uses_normalized_host():
    assert build_cache_key("API.EXAMPLE.COM", "/x") == "api.example.com/x"
