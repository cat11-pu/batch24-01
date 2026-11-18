import pytest

from log_redaction import redact

CASES = [
    ("password=hunter2", "hunter2"),
    ("token: abc123", "abc123"),
    ("Authorization: Bearer xyz789", "xyz789"),
    ("api_key=SECRETVALUE", "SECRETVALUE"),
    ("secret = topsecret", "topsecret"),
    ("card=4111111111111111", "4111111111111111"),
    ("ssn=123-45-6789", "123-45-6789"),
    ("Cookie: session=abc", "session=abc"),
    ("/cb?access_token=abc", "abc"),
    ("password='hunter2'", "hunter2"),
    ("pwd=hunter2", "hunter2"),
    ("passwd=hunter2", "hunter2"),
    ("key=abc\nnext", "abc"),
    ("token=abc\x00", "abc"),
    ("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig", "eyJhbGciOiJIUzI1NiJ9"),
]


@pytest.mark.parametrize("message,secret", CASES)
def test_secret_is_removed_from_log(message, secret):
    out = redact(message)
    assert secret not in out
