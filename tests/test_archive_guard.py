import pytest

from archive_guard import validate_entry

DEST = "/tmp/extract"


def test_1_parent_entry_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("../evil", DEST)


def test_2_nested_parent_entry_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("a/../../evil", DEST)


def test_3_absolute_entry_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("/etc/passwd", DEST)


def test_4_windows_drive_entry_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("C:\\evil", DEST)


def test_5_backslash_traversal_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("..\\evil", DEST)


def test_6_null_byte_entry_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("a\x00b", DEST)


def test_7_encoded_traversal_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("%2e%2e%2fevil", DEST)


def test_8_symlink_entry_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("link", DEST, is_symlink=True)


def test_9_empty_entry_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("", DEST)


def test_10_non_string_entry_is_rejected():
    with pytest.raises(TypeError):
        validate_entry(123, DEST)


def test_11_non_string_destination_is_rejected():
    with pytest.raises(TypeError):
        validate_entry("file", 123)


def test_12_dot_dot_entry_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("..", DEST)


def test_13_double_dot_with_extra_slashes_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("....//evil", DEST)


def test_14_trailing_parent_component_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("a/..", DEST)


def test_15_deep_escape_is_rejected():
    with pytest.raises(ValueError):
        validate_entry("a/b/../../../evil", DEST)
