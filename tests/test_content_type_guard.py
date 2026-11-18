import pytest

from content_type_guard import check_content_type

BAD_HEADERS = [
    "",
    None,
    123,
    "text/plain",
    "application/json; charset=utf-16",
    "application/json;charset=utf-8 ",
    "application/json, text/plain",
    "application/json; boundary=x",
    "APPLICATION/JSON",
    "application/json\n",
    "application/json\x00",
    "application/json-patch+json",
    "application/xml",
    "multipart/form-data",
    " application/json",
]


@pytest.mark.parametrize("header", BAD_HEADERS)
def test_bad_content_type_is_rejected(header):
    with pytest.raises(ValueError):
        check_content_type(header, ("application/json",))
