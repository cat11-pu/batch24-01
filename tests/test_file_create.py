import os

import pytest

from file_create import create_file

BASE = "/srv/uploads"


def test_parent_traversal_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "../x", b"data", 0o600)


def test_absolute_name_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "/etc/passwd", b"data", 0o600)


def test_slash_in_name_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "a/b", b"data", 0o600)


def test_empty_name_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "", b"data", 0o600)


def test_none_name_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), None, b"data", 0o600)


def test_non_bytes_data_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "x", "data", 0o600)


def test_world_writable_mode_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "x", b"data", 0o777)


def test_existing_file_is_rejected(tmp_path):
    target = tmp_path / "x"
    target.write_bytes(b"old")
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "x", b"data", 0o600)


def test_symlink_target_is_rejected(tmp_path):
    target = tmp_path / "x"
    target.symlink_to("/etc/passwd")
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "x", b"data", 0o600)


def test_nul_in_name_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "x\x00y", b"data", 0o600)


def test_overlong_name_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "a" * 300, b"data", 0o600)


def test_base_must_be_directory(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path / "missing"), "x", b"data", 0o600)


def test_float_mode_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "x", b"data", float(0o600))


def test_dot_name_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), ".", b"data", 0o600)


def test_dotdot_name_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        create_file(str(tmp_path), "..", b"data", 0o600)
