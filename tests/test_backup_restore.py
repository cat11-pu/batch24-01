import threading

import pytest

import backup_restore as br

BACKUP = {"id": "b1", "checksum": "abc", "expected_checksum": "abc", "encrypted": True, "created_at": 900, "expires": 2000, "size": 100}
REQUEST = {"requester": "alice", "approver": "bob", "reason": "restore", "target": "db-1"}


def test_backup_must_be_dict():
    with pytest.raises(ValueError):
        br.plan("backup", REQUEST, 1000)


def test_request_must_be_dict():
    with pytest.raises(ValueError):
        br.plan(BACKUP, "request", 1000)


def test_missing_checksum_is_rejected():
    bad = {k: v for k, v in BACKUP.items() if k != "checksum"}
    with pytest.raises(ValueError):
        br.plan(bad, REQUEST, 1000)


def test_checksum_mismatch_is_rejected():
    with pytest.raises(ValueError):
        br.plan({**BACKUP, "checksum": "bad"}, REQUEST, 1000)


def test_unencrypted_backup_is_rejected():
    with pytest.raises(ValueError):
        br.plan({**BACKUP, "encrypted": False}, REQUEST, 1000)


def test_expired_backup_is_rejected():
    with pytest.raises(ValueError):
        br.plan({**BACKUP, "expires": 900}, REQUEST, 1000)


def test_oversized_backup_is_rejected():
    with pytest.raises(ValueError):
        br.plan({**BACKUP, "size": 1000000000}, REQUEST, 1000)


def test_requester_cannot_approve_own_restore():
    with pytest.raises(ValueError):
        br.plan(BACKUP, {**REQUEST, "approver": "alice"}, 1000)


def test_empty_reason_is_rejected():
    with pytest.raises(ValueError):
        br.plan(BACKUP, {**REQUEST, "reason": ""}, 1000)


def test_unknown_target_is_rejected():
    with pytest.raises(ValueError):
        br.plan(BACKUP, {**REQUEST, "target": "evil-db"}, 1000)


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        br.plan(BACKUP, REQUEST, "now")


def test_negative_size_is_rejected():
    with pytest.raises(ValueError):
        br.plan({**BACKUP, "size": -1}, REQUEST, 1000)


def test_concurrent_restore_only_one_approved():
    results = []

    def worker():
        try:
            br.plan(BACKUP, REQUEST, 1000)
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_missing_approver_is_rejected():
    bad = {k: v for k, v in REQUEST.items() if k != "approver"}
    with pytest.raises(ValueError):
        br.plan(BACKUP, bad, 1000)


def test_created_in_future_is_rejected():
    with pytest.raises(ValueError):
        br.plan({**BACKUP, "created_at": 1100}, REQUEST, 1000)
