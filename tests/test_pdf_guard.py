import pytest

from pdf_guard import scan_pdf

BAD_FILES = [
    b"",
    None,
    "str",
    b"%PDF-1.4\n/JavaScript",
    b"/JS",
    b"/Launch",
    b"/OpenAction",
    b"/EmbeddedFile",
    b"/RichMedia",
    b"/AA",
    b"/SubmitForm",
    b"/ImportData",
    b"/GoToR",
    b"/XFA",
    b"a" * 10000001,
]


@pytest.mark.parametrize("data", BAD_FILES)
def test_dangerous_pdf_is_rejected(data):
    with pytest.raises(ValueError):
        scan_pdf(data, 10000000)
