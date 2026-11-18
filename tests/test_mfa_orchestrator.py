import threading

import pytest

import mfa_orchestrator as mf

BASE = {"status": "pending", "user": "alice", "factors": ["password"], "failed": 0, "locked": False, "expires": 2000}


def test_totp_before_password_is_rejected():
    with pytest.raises(ValueError):
        mf.step(dict(BASE), "verify_totp", "totp", 1000, "123456")


def test_empty_code_is_rejected():
    with pytest.raises(ValueError):
        mf.step(dict(BASE), "verify_password", "password", 1000, "")


def test_non_digit_totp_is_rejected():
    with pytest.raises(ValueError):
        mf.step({**BASE, "factors": ["password", "totp"]}, "verify_totp", "totp", 1000, "abcdef")


def test_bad_backup_code_length_is_rejected():
    with pytest.raises(ValueError):
        mf.step({**BASE, "factors": ["password", "backup"]}, "verify_backup", "backup", 1000, "short")


def test_expired_flow_is_rejected():
    with pytest.raises(ValueError):
        mf.step(dict(BASE), "verify_password", "password", 2001, "secret")


def test_locked_flow_is_rejected():
    with pytest.raises(ValueError):
        mf.step({**BASE, "locked": True}, "verify_password", "password", 1000, "secret")


def test_unknown_event_is_rejected():
    with pytest.raises(ValueError):
        mf.step(dict(BASE), "skip", "password", 1000, "secret")


def test_non_dict_state_is_rejected():
    with pytest.raises(ValueError):
        mf.step("state", "verify_password", "password", 1000, "secret")


def test_missing_status_is_rejected():
    bad = {k: v for k, v in BASE.items() if k != "status"}
    with pytest.raises(ValueError):
        mf.step(bad, "verify_password", "password", 1000, "secret")


def test_too_many_failures_locks():
    assert mf.step({**BASE, "failed": 3}, "verify_password", "password", 1000, "secret")["status"] == "locked"


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        mf.step(dict(BASE), "verify_password", "password", "now", "secret")


def test_empty_user_is_rejected():
    with pytest.raises(ValueError):
        mf.step({**BASE, "user": ""}, "verify_password", "password", 1000, "secret")


def test_factors_must_be_list():
    with pytest.raises(ValueError):
        mf.step({**BASE, "factors": "password"}, "verify_password", "password", 1000, "secret")


def test_reset_before_active_is_rejected():
    with pytest.raises(ValueError):
        mf.step(dict(BASE), "reset", "password", 1000, "secret")


def test_concurrent_totp_only_one_activation():
    state = {**BASE, "factors": ["password", "totp"]}
    results = []

    def worker():
        try:
            out = mf.step(state, "verify_totp", "totp", 1000, "123456")
            results.append(out["status"] == "active")
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
