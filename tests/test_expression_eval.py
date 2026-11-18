import pytest

from expression_eval import evaluate

BAD_EXPRESSIONS = [
    "",
    None,
    123,
    "a+1",
    "__import__('os')",
    "1;2",
    "1 if 1 else 2",
    "[1]",
    "1/0",
    "2**10000",
    "(" * 30 + "1" + ")" * 30,
    "1+",
    "0x10",
    "1e999",
    "lambda: 1",
]


@pytest.mark.parametrize("expr", BAD_EXPRESSIONS)
def test_dangerous_expression_is_rejected(expr):
    with pytest.raises(ValueError):
        evaluate(expr, 20, 200)
