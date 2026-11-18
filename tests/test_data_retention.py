import pytest

from data_retention import decide

POLICY = {"orders": {"days": 30, "action": "purge", "pii": False}, "profiles": {"days": 30, "action": "anonymize", "pii": True}}


def test_record_must_be_dict():
    with pytest.raises(ValueError):
        decide("record", POLICY, 1000)


def test_policy_must_be_dict():
    with pytest.raises(ValueError):
        decide({"category": "orders", "created_at": 0, "tenant": "t1", "legal_hold": False}, "policy", 1000)


def test_unknown_category_is_rejected():
    with pytest.raises(ValueError):
        decide({"category": "ghost", "created_at": 0, "tenant": "t1", "legal_hold": False}, POLICY, 1000)


def test_negative_age_is_rejected():
    with pytest.raises(ValueError):
        decide({"category": "orders", "created_at": 2000, "tenant": "t1", "legal_hold": False}, POLICY, 1000)


def test_expired_non_pii_is_purged():
    assert decide({"category": "orders", "created_at": 0, "tenant": "t1", "legal_hold": False}, POLICY, 1000) == "purge"


def test_expired_pii_is_anonymized():
    assert decide({"category": "profiles", "created_at": 0, "tenant": "t1", "legal_hold": False}, POLICY, 1000) == "anonymize"


def test_cross_tenant_is_rejected():
    with pytest.raises(ValueError):
        decide({"category": "orders", "created_at": 0, "tenant": "t2", "legal_hold": False}, POLICY, 1000)


def test_non_integer_now_is_rejected():
    with pytest.raises(ValueError):
        decide({"category": "orders", "created_at": 0, "tenant": "t1", "legal_hold": False}, POLICY, "now")


def test_non_integer_created_at_is_rejected():
    with pytest.raises(ValueError):
        decide({"category": "orders", "created_at": "0", "tenant": "t1", "legal_hold": False}, POLICY, 1000)


def test_policy_missing_action_is_rejected():
    with pytest.raises(ValueError):
        decide({"category": "orders", "created_at": 0, "tenant": "t1", "legal_hold": False}, {"orders": {"days": 30}}, 1000)


def test_invalid_action_is_rejected():
    with pytest.raises(ValueError):
        decide({"category": "orders", "created_at": 0, "tenant": "t1", "legal_hold": False}, {"orders": {"days": 30, "action": "delete", "pii": False}}, 1000)


def test_empty_category_is_rejected():
    with pytest.raises(ValueError):
        decide({"category": "", "created_at": 0, "tenant": "t1", "legal_hold": False}, POLICY, 1000)


def test_policy_entry_must_be_dict():
    with pytest.raises(ValueError):
        decide({"category": "orders", "created_at": 0, "tenant": "t1", "legal_hold": False}, {"orders": "keep"}, 1000)


def test_negative_retention_is_rejected():
    with pytest.raises(ValueError):
        decide({"category": "orders", "created_at": 0, "tenant": "t1", "legal_hold": False}, {"orders": {"days": -1, "action": "purge", "pii": False}}, 1000)


def test_missing_created_at_is_rejected():
    with pytest.raises(ValueError):
        decide({"category": "orders", "tenant": "t1", "legal_hold": False}, POLICY, 1000)
