import pytest

from accept_guard import negotiate

SUPPORTED = ["application/json", "text/html"]

BAD_HEADERS = [
    "",
    None,
    123,
    "*/*",
    "text/*",
    "application/json;q=0",
    "application/json;q=abc",
    "application/json;q=1.5",
    "application/json;q=-1",
    "application/json,",
    ",application/json",
    "application/json;",
    "application/json; q=0.5; q=0.6",
    "APPLICATION/JSON",
    "application/json\n",
]


@pytest.mark.parametrize("header", BAD_HEADERS)
def test_bad_accept_header_is_rejected(header):
    with pytest.raises(ValueError):
        negotiate(header, SUPPORTED)
