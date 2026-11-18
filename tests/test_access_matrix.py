import pytest

from access_matrix import authorize

POLICY = {
    "roles": {"admin": ["editor"], "editor": ["viewer"], "viewer": []},
    "grants": [
        {"role": "viewer", "action": "read", "resource": "doc"},
        {"role": "editor", "action": "write", "resource": "doc"},
        {"role": "admin", "action": "delete", "resource": "doc"},
    ],
    "denies": [
        {"role": "editor", "action": "delete", "resource": "doc"},
    ],
}
USER = {"id": "u1", "roles": ["editor"], "tenant": "t1"}
DOC = {"type": "doc", "owner": "u2", "tenant": "t1", "deleted": False}


def test_unknown_role_is_rejected():
    with pytest.raises(ValueError):
        authorize(POLICY, {"id": "u1", "roles": ["ghost"], "tenant": "t1"}, "read", DOC)


def test_unknown_action_is_rejected():
    with pytest.raises(ValueError):
        authorize(POLICY, USER, "fly", DOC)


def test_unknown_resource_type_is_rejected():
    with pytest.raises(ValueError):
        authorize(POLICY, USER, "read", {"type": "widget", "tenant": "t1"})


def test_deleted_resource_is_denied():
    assert authorize(POLICY, USER, "read", {**DOC, "deleted": True}) is False


def test_cross_tenant_is_denied():
    assert authorize(POLICY, USER, "read", {**DOC, "tenant": "t2"}) is False


def test_explicit_deny_beats_allow():
    assert authorize(POLICY, {"id": "u1", "roles": ["admin"], "tenant": "t1"}, "delete", DOC) is False


def test_viewer_cannot_write():
    assert authorize(POLICY, {"id": "u1", "roles": ["viewer"], "tenant": "t1"}, "write", DOC) is False


def test_user_without_roles_is_denied():
    assert authorize(POLICY, {"id": "u1", "roles": [], "tenant": "t1"}, "read", DOC) is False


def test_owner_cannot_write_deleted_document():
    assert authorize(POLICY, {"id": "u2", "roles": ["viewer"], "tenant": "t1"}, "write", {**DOC, "owner": "u2", "deleted": True}) is False


def test_role_cycle_is_rejected():
    bad = {"roles": {"a": ["b"], "b": ["a"]}, "grants": [], "denies": []}
    with pytest.raises(ValueError):
        authorize(bad, {"id": "u1", "roles": ["a"], "tenant": "t1"}, "read", DOC)


def test_missing_roles_key_is_rejected():
    with pytest.raises(ValueError):
        authorize({"grants": [], "denies": []}, USER, "read", DOC)


def test_non_dict_user_is_rejected():
    with pytest.raises(ValueError):
        authorize(POLICY, "u1", "read", DOC)


def test_non_dict_resource_is_rejected():
    with pytest.raises(ValueError):
        authorize(POLICY, USER, "read", "doc")


def test_non_string_action_is_rejected():
    with pytest.raises(ValueError):
        authorize(POLICY, USER, 1, DOC)


def test_deny_on_parent_role_applies_to_child():
    bad = {
        "roles": {"admin": ["editor"], "editor": []},
        "grants": [{"role": "editor", "action": "read", "resource": "doc"}],
        "denies": [{"role": "editor", "action": "read", "resource": "doc"}],
    }
    assert authorize(bad, {"id": "u1", "roles": ["admin"], "tenant": "t1"}, "read", DOC) is False
