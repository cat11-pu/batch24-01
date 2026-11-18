import pytest

from mask_fields import project

SCHEMA = {
    "name": {"read": ["user"], "write": ["user"]},
    "email": {"read": ["user"], "write": ["user"]},
    "password_hash": {"read": [], "write": []},
    "role": {"read": ["admin"], "write": ["admin"]},
    "profile": {"read": ["user"], "write": ["user"], "fields": {
        "ssn": {"read": [], "write": []},
        "bio": {"read": ["user"], "write": ["user"]},
    }},
}
RECORD = {"name": "a", "email": "e", "password_hash": "x", "role": "user", "profile": {"ssn": "1", "bio": "b"}}


def test_password_hash_is_never_readable():
    assert "password_hash" not in project(RECORD, "user", "read", SCHEMA)


def test_admin_only_field_is_hidden_from_user():
    assert "role" not in project(RECORD, "user", "read", SCHEMA)


def test_nested_sensitive_field_is_hidden():
    out = project(RECORD, "user", "read", SCHEMA)
    assert "ssn" not in out.get("profile", {})


def test_unknown_role_is_rejected():
    with pytest.raises(ValueError):
        project(RECORD, "ghost", "read", SCHEMA)


def test_invalid_direction_is_rejected():
    with pytest.raises(ValueError):
        project(RECORD, "user", "delete", SCHEMA)


def test_non_dict_record_is_rejected():
    with pytest.raises(ValueError):
        project("record", "user", "read", SCHEMA)


def test_non_dict_schema_is_rejected():
    with pytest.raises(ValueError):
        project(RECORD, "user", "read", "schema")


def test_empty_role_is_rejected():
    with pytest.raises(ValueError):
        project(RECORD, "", "read", SCHEMA)


def test_write_to_sensitive_field_is_rejected():
    with pytest.raises(ValueError):
        project(RECORD, "user", "write", SCHEMA)


def test_user_cannot_write_admin_field():
    with pytest.raises(ValueError):
        project(RECORD, "user", "write", SCHEMA)


def test_wildcard_still_hides_password_hash():
    out = project(RECORD, "*", "read", SCHEMA)
    assert "password_hash" not in out


def test_malformed_field_policy_is_rejected():
    bad = {"name": {"read": ["user"]}}
    with pytest.raises(ValueError):
        project(RECORD, "user", "read", bad)


def test_nested_policy_must_be_dict():
    bad = {**SCHEMA, "profile": {"read": ["user"], "write": ["user"], "fields": "nope"}}
    with pytest.raises(ValueError):
        project(RECORD, "user", "read", bad)


def test_roles_must_be_list():
    bad = {**SCHEMA, "name": {"read": "user", "write": ["user"]}}
    with pytest.raises(ValueError):
        project(RECORD, "user", "read", bad)


def test_list_record_is_rejected():
    with pytest.raises(ValueError):
        project([RECORD], "user", "read", SCHEMA)
