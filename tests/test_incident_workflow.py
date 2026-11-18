import threading

import pytest

import incident_workflow as iw

DETECTED = {"status": "detected", "severity": "P2", "assignee": "", "sla_due": 2000, "lead": "alice"}


def test_invalid_severity_is_rejected():
    with pytest.raises(ValueError):
        iw.transition({**DETECTED, "severity": "P9"}, "triage", "bob", 1000)


def test_triage_without_assignee_is_rejected():
    with pytest.raises(ValueError):
        iw.transition(dict(DETECTED), "triage", "bob", 1000)


def test_contain_before_triage_is_rejected():
    with pytest.raises(ValueError):
        iw.transition(dict(DETECTED), "contain", "bob", 1000)


def test_close_before_recovery_is_rejected():
    with pytest.raises(ValueError):
        iw.transition({"status": "contained", "severity": "P2", "assignee": "bob", "sla_due": 2000, "lead": "alice"}, "close", "alice", 1000)


def test_close_by_non_lead_is_rejected():
    state = {"status": "recovered", "severity": "P2", "assignee": "bob", "sla_due": 2000, "lead": "alice"}
    with pytest.raises(ValueError):
        iw.transition(state, "close", "bob", 1000)


def test_unknown_event_is_rejected():
    with pytest.raises(ValueError):
        iw.transition(dict(DETECTED), "teleport", "bob", 1000)


def test_non_dict_state_is_rejected():
    with pytest.raises(ValueError):
        iw.transition("state", "triage", "bob", 1000)


def test_missing_status_is_rejected():
    bad = {k: v for k, v in DETECTED.items() if k != "status"}
    with pytest.raises(ValueError):
        iw.transition(bad, "triage", "bob", 1000)


def test_unknown_status_is_rejected():
    with pytest.raises(ValueError):
        iw.transition({**DETECTED, "status": "weird"}, "triage", "bob", 1000)


def test_p1_breach_escalates():
    state = {"status": "detected", "severity": "P1", "assignee": "", "sla_due": 1000, "lead": "alice"}
    assert iw.transition(state, "triage", "bob", 2000)["status"] == "escalated"


def test_empty_actor_is_rejected():
    with pytest.raises(ValueError):
        iw.transition(dict(DETECTED), "triage", "", 1000)


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        iw.transition(dict(DETECTED), "triage", "bob", "now")


def test_concurrent_contain_only_one_succeeds():
    state = {"status": "triaged", "severity": "P2", "assignee": "bob", "sla_due": 2000, "lead": "alice"}
    results = []

    def worker():
        try:
            iw.transition(state, "contain", "bob", 1000)
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_recover_before_contain_is_rejected():
    state = {"status": "triaged", "severity": "P2", "assignee": "bob", "sla_due": 2000, "lead": "alice"}
    with pytest.raises(ValueError):
        iw.transition(state, "recover", "bob", 1000)


def test_duplicate_close_is_rejected():
    state = {"status": "closed", "severity": "P2", "assignee": "bob", "sla_due": 2000, "lead": "alice"}
    with pytest.raises(ValueError):
        iw.transition(state, "close", "alice", 1000)
