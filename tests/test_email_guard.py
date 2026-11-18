import pytest

from email_guard import validate_email


def test_1_lf_in_recipient_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@example.com\nBcc: evil@example.com", "hello")


def test_2_crlf_in_recipient_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@example.com\r\nBcc: evil@example.com", "hello")


def test_3_lf_in_subject_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@example.com", "hello\nBcc: evil@example.com")


def test_4_cr_in_subject_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@example.com", "hello\rBcc: evil@example.com")


def test_5_lf_in_cc_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@example.com", "hello", cc="bob@example.com\nBcc: evil@example.com")


def test_6_cr_in_bcc_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@example.com", "hello", bcc="bob@example.com\rBcc: evil@example.com")


def test_7_empty_recipient_is_rejected():
    with pytest.raises(ValueError):
        validate_email("", "hello")


def test_8_empty_subject_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@example.com", "")


def test_9_invalid_recipient_without_at_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice.example.com", "hello")


def test_10_recipient_with_two_at_signs_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@@example.com", "hello")


def test_11_nul_in_recipient_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@example.com\x00Bcc: evil@example.com", "hello")


def test_12_invalid_cc_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@example.com", "hello", cc="not-an-email")


def test_13_invalid_bcc_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@example.com", "hello", bcc="not-an-email")


def test_14_newline_in_display_name_is_rejected():
    with pytest.raises(ValueError):
        validate_email("Alice\nBcc: evil@example.com <alice@example.com>", "hello")


def test_15_tab_control_character_is_rejected():
    with pytest.raises(ValueError):
        validate_email("alice@example.com\tBcc: evil@example.com", "hello")
