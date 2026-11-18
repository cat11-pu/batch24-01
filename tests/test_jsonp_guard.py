import pytest

from jsonp_guard import wrap_jsonp

BAD_CALLBACKS = [
    "",
    None,
    123,
    "alert(1)",
    "a.b",
    "a-b",
    "a b",
    "a;",
    "a/**/",
    "__proto__",
    "constructor",
    "$.ajax",
    "a\nb",
    "a\x00",
    "a" * 300,
]


@pytest.mark.parametrize("callback", BAD_CALLBACKS)
def test_bad_jsonp_callback_is_rejected(callback):
    with pytest.raises(ValueError):
        wrap_jsonp(callback, {"ok": True}, 64)
