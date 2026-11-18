import pytest

from dependency_guard import verify

POLICY = {"allowed": {"requests": {"hash": "ab" * 32, "min_version": "2.0.0"}, "urllib3": {"hash": "cd" * 32, "min_version": "1.0.0"}}, "banned": ["evilpkg"]}
LOCK = {"requests": {"version": "2.31.0", "hash": "ab" * 32}}


def test_lockfile_must_be_dict():
    with pytest.raises(ValueError):
        verify([], POLICY)


def test_policy_must_be_dict():
    with pytest.raises(ValueError):
        verify(LOCK, "policy")


def test_unknown_package_is_rejected():
    with pytest.raises(ValueError):
        verify({**LOCK, "leftpad": {"version": "1.0.0", "hash": "ab" * 32}}, POLICY)


def test_hash_mismatch_is_rejected():
    with pytest.raises(ValueError):
        verify({"requests": {"version": "2.31.0", "hash": "zz" * 32}}, POLICY)


def test_banned_package_is_rejected():
    with pytest.raises(ValueError):
        verify({"evilpkg": {"version": "1.0.0", "hash": "ab" * 32}}, POLICY)


def test_version_below_minimum_is_rejected():
    with pytest.raises(ValueError):
        verify({"requests": {"version": "1.0.0", "hash": "ab" * 32}}, POLICY)


def test_missing_hash_is_rejected():
    with pytest.raises(ValueError):
        verify({"requests": {"version": "2.31.0"}}, POLICY)


def test_empty_package_name_is_rejected():
    with pytest.raises(ValueError):
        verify({"": {"version": "2.31.0", "hash": "ab" * 32}}, POLICY)


def test_non_string_version_is_rejected():
    with pytest.raises(ValueError):
        verify({"requests": {"version": 231, "hash": "ab" * 32}}, POLICY)


def test_unpinned_version_is_rejected():
    with pytest.raises(ValueError):
        verify({"requests": {"version": ">=2.0.0", "hash": "ab" * 32}}, POLICY)


def test_non_hex_hash_is_rejected():
    with pytest.raises(ValueError):
        verify({"requests": {"version": "2.31.0", "hash": "nothex"}}, POLICY)


def test_empty_allowed_list_is_rejected():
    with pytest.raises(ValueError):
        verify(LOCK, {"allowed": {}, "banned": []})


def test_lookalike_package_is_rejected():
    with pytest.raises(ValueError):
        verify({"request": {"version": "2.31.0", "hash": "ab" * 32}}, POLICY)


def test_invalid_min_version_is_rejected():
    with pytest.raises(ValueError):
        verify(LOCK, {"allowed": {"requests": {"hash": "ab" * 32, "min_version": "x"}}, "banned": []})


def test_banned_list_must_be_list():
    with pytest.raises(ValueError):
        verify(LOCK, {**POLICY, "banned": "evilpkg"})
