import pytest

from oauth_device import check_device_code

GOOD = ("device-code-123456", "ABCD-1234", "client-1", "client-1", 2000, 1000)

BAD_CASES = [
    ("", "ABCD-1234", "client-1", "client-1", 2000, 1000),
    ("device-code-123456", "", "client-1", "client-1", 2000, 1000),
    ("device-code-123456", "ABCD-1234", "", "client-1", 2000, 1000),
    ("device-code-123456", "ABCD-1234", "client-1", "client-2", 2000, 1000),
    ("short", "ABCD-1234", "client-1", "client-1", 2000, 1000),
    ("device-code-123456", "AB CD", "client-1", "client-1", 2000, 1000),
    ("device-code-123456", "ABCD-1234", "client-1", "client-1", 1000, 1000),
    ("device-code-123456", "ABCD-1234", "client-1", "client-1", 999, 1000),
    ("device-code-123456", "ABCD-1234", "client-1", "client-1", None, 1000),
    ("device-code-123456", "ABCD-1234", "client-1", "client-1", 2000, None),
    (None, "ABCD-1234", "client-1", "client-1", 2000, 1000),
    ("device-code-123456", None, "client-1", "client-1", 2000, 1000),
    ("device-code-123456", "ABCD-1234", None, "client-1", 2000, 1000),
    ("device-code-123456", "ABCD-1234", 123, "client-1", 2000, 1000),
    ("device-code-123456", "ABCD_1234", "client-1", "client-1", 2000, 1000),
]


@pytest.mark.parametrize("code,user_code,client,approved,expires,now", BAD_CASES)
def test_bad_device_code_is_rejected(code, user_code, client, approved, expires, now):
    with pytest.raises(ValueError):
        check_device_code(code, user_code, client, approved, expires, now)
