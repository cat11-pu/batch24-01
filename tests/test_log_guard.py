import pytest

from log_guard import sanitize_log


def test_1_lf_is_escaped():
    assert sanitize_log("\n") == r"\n"


def test_2_cr_is_escaped():
    assert sanitize_log("\r") == r"\r"


def test_3_crlf_is_escaped():
    assert sanitize_log("\r\n") == r"\r\n"


def test_4_tab_is_escaped():
    assert sanitize_log("\t") == r"\t"


def test_5_nul_is_escaped():
    assert sanitize_log("\x00") == r"\0"


def test_6_ansi_escape_is_escaped():
    assert sanitize_log("\x1b[31mred") == r"\x1b[31mred"


def test_7_vertical_tab_is_escaped():
    assert sanitize_log("\x0b") == r"\x0b"


def test_8_form_feed_is_escaped():
    assert sanitize_log("\x0c") == r"\x0c"


def test_9_backspace_is_escaped():
    assert sanitize_log("\x08") == r"\x08"


def test_10_bell_is_escaped():
    assert sanitize_log("\x07") == r"\x07"


def test_11_fake_log_line_is_escaped():
    assert sanitize_log("admin\n127.0.0.1 login ok") == r"admin\n127.0.0.1 login ok"


def test_12_empty_value_is_rejected():
    with pytest.raises(ValueError):
        sanitize_log("")


def test_13_non_string_value_is_rejected():
    with pytest.raises(TypeError):
        sanitize_log(123)


def test_14_multiple_controls_are_escaped():
    assert sanitize_log("\x00\n\r\t") == r"\0\n\r\t"


def test_15_del_is_escaped():
    assert sanitize_log("\x7f") == r"\x7f"
