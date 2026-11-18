import pytest

from totp_guard import verify_totp

BAD_CODES = [
    "",
    "12345",
    "1234567",
    "abcdef",
    "12 456",
    "12345\n",
    "123456\r",
    "123456 ",
    " 123456",
    "123456\t",
    "123456\x7f",
    "12345\x00",
    "１２３４５６",
    "-12345",
]


@pytest.mark.parametrize("code", BAD_CODES)
def test_invalid_totp_code_is_rejected(code):
    assert verify_totp("secret", code, 1000) is False


def test_totp_code_cannot_be_replayed():
    assert verify_totp("secret", "123456", 1000) is True
    assert verify_totp("secret", "123456", 1000) is False
