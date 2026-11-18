import pytest

from config_merge_guard import merge_config

DANGEROUS = {"__proto__", "constructor", "prototype"}
BASE = {"name": "app", "limits": {"cpu": 1}, "tags": ["a"]}

BAD_PATCHES = [
    {"__proto__": {"admin": True}},
    {"constructor": {"prototype": {"admin": True}}},
    {"prototype": {}},
    {"limits": {"__proto__": {}}},
    {"limits": {"constructor": {}}},
    {"limits": {"b": {"__proto__": 1}}},
    {"limits": {"cpu": {"nested": 1}}},
    {"tags": {"x": 1}},
    {"name": {"x": 1}},
    "not-a-dict",
    None,
    ["__proto__"],
    {"__PROTO__": 1},
    {" name": 1},
    {"bad\x00key": 1},
]


@pytest.mark.parametrize("patch", BAD_PATCHES)
def test_bad_config_patch_is_rejected(patch):
    with pytest.raises(ValueError):
        merge_config(BASE, patch, DANGEROUS)
