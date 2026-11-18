import pytest

from url_guard import validate_url


def test_1_file_scheme_is_rejected():
    with pytest.raises(ValueError):
        validate_url("file:///etc/passwd")


def test_2_gopher_scheme_is_rejected():
    with pytest.raises(ValueError):
        validate_url("gopher://api.example.com/_test")


def test_3_ftp_scheme_is_rejected():
    with pytest.raises(ValueError):
        validate_url("ftp://api.example.com/file")


def test_4_localhost_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://localhost/admin")


def test_5_loopback_ip_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://127.0.0.1/admin")


def test_6_private_ip_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://10.0.0.1/admin")


def test_7_metadata_ip_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://169.254.169.254/latest/meta-data")


def test_8_ipv6_loopback_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://[::1]/admin")


def test_9_decimal_ip_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://2130706433/admin")


def test_10_hex_ip_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://0x7f000001/admin")


def test_11_userinfo_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://user:pass@api.example.com/admin")


def test_12_host_suffix_spoof_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://api.example.com.evil.com/admin")


def test_13_unlisted_host_is_rejected():
    with pytest.raises(ValueError):
        validate_url("http://evil.example.com/admin")


def test_14_non_standard_port_is_rejected():
    with pytest.raises(ValueError):
        validate_url("https://api.example.com:8443/admin")


def test_15_empty_url_is_rejected():
    with pytest.raises(ValueError):
        validate_url("")
