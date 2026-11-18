import pytest

from approval_chain import decide

POLICY = {"max_amount": 10000, "roles": {"manager": 5000, "director": 10000}}


def req(**kw):
    base = {"amount": 1000, "requester": "alice", "approvals": [{"actor": "bob", "role": "manager"}], "rejected": False}
    base.update(kw)
    return base


def test_negative_amount_is_rejected():
    with pytest.raises(ValueError):
        decide(req(amount=-1), POLICY)


def test_zero_amount_is_rejected():
    with pytest.raises(ValueError):
        decide(req(amount=0), POLICY)


def test_float_amount_is_rejected():
    with pytest.raises(ValueError):
        decide(req(amount=1.5), POLICY)


def test_empty_requester_is_rejected():
    with pytest.raises(ValueError):
        decide(req(requester=""), POLICY)


def test_self_approval_is_rejected():
    with pytest.raises(ValueError):
        decide(req(approvals=[{"actor": "alice", "role": "manager"}]), POLICY)


def test_manager_cannot_approve_large_amount():
    assert decide(req(amount=6000), POLICY) == "pending"


def test_no_approvals_is_pending():
    assert decide(req(amount=1000, approvals=[]), POLICY) == "pending"


def test_duplicate_approver_is_rejected():
    with pytest.raises(ValueError):
        decide(req(amount=6000, approvals=[{"actor": "bob", "role": "manager"}, {"actor": "bob", "role": "manager"}]), POLICY)


def test_unknown_role_is_rejected():
    with pytest.raises(ValueError):
        decide(req(approvals=[{"actor": "bob", "role": "ghost"}]), POLICY)


def test_approvals_must_be_list():
    with pytest.raises(ValueError):
        decide(req(approvals="bob"), POLICY)


def test_policy_must_be_dict():
    with pytest.raises(ValueError):
        decide(req(), "policy")


def test_request_must_be_dict():
    with pytest.raises(ValueError):
        decide("request", POLICY)


def test_amount_over_limit_is_rejected():
    with pytest.raises(ValueError):
        decide(req(amount=10001), POLICY)


def test_rejected_request_returns_rejected():
    assert decide(req(rejected=True), POLICY) == "rejected"


def test_amount_string_is_rejected():
    with pytest.raises(ValueError):
        decide(req(amount="1000"), POLICY)
