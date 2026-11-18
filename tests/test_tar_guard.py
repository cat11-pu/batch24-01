import pytest

from tar_guard import validate

BAD_VALUES = [
  [
    "link",
    "symlink",
    "/etc/passwd"
  ],
  [
    "link",
    "symlink",
    "../../etc/passwd"
  ],
  [
    "link",
    "hardlink",
    "/etc/passwd"
  ],
  [
    "link",
    "symlink",
    "C:\\Windows\\win.ini"
  ],
  [
    "dev",
    "char",
    ""
  ],
  [
    "dev",
    "block",
    ""
  ],
  [
    "link",
    "symlink",
    ""
  ],
  [
    "link",
    "symlink",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  ],
  [
    "..",
    "file",
    ""
  ],
  [
    "/etc/passwd",
    "file",
    ""
  ],
  [
    "a/../../etc/passwd",
    "file",
    ""
  ],
  [
    "link",
    "symlink",
    "..\\..\\etc"
  ],
  [
    "link",
    "hardlink",
    "a/../../etc/passwd"
  ],
  [
    "",
    "symlink",
    "x"
  ],
  [
    "link",
    "symlink",
    "x\u0000y"
  ]
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_value_is_rejected(value):
    with pytest.raises((ValueError, TypeError)):
        validate(value)
