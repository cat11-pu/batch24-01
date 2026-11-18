import threading

import pytest

import account_recovery as ar

ANSWERS = {"mother": "x", "school": "y", "city": "z"}


def test_empty_user_is_rejected():
    with pytest.raises(ValueError):
        ar.submit({}, "", ANSWERS, 1000)


def test_answers_must_be_dict():
    with pytest.raises(ValueError):
        ar.submit({}, "alice", ["x", "y", "z"], 1000)


def test_too_few_answers_are_rejected():
    with pytest.raises(ValueError):
        ar.submit({}, "alice", {"a": "x"}, 1000)


def test_empty_answer_is_rejected():
    with pytest.raises(ValueError):
        ar.submit({}, "alice", {"a": "", "b": "y", "c": "z"}, 1000)


def test_duplicate_submission_in_cooldown_is_rejected():
    store = {}
    ar.submit(store, "alice", ANSWERS, 1000)
    with pytest.raises(ValueError):
        ar.submit(store, "alice", ANSWERS, 1001)


def test_unknown_case_is_rejected():
    with pytest.raises(ValueError):
        ar.review({}, "missing", "bob", "approve", 1000)


def test_requester_cannot_review_own_case():
    store = {}
    case = ar.submit(store, "alice", ANSWERS, 1000)
    with pytest.raises(ValueError):
        ar.review(store, case, "alice", "approve", 1000)


def test_invalid_decision_is_rejected():
    store = {}
    case = ar.submit(store, "alice", ANSWERS, 1000)
    with pytest.raises(ValueError):
        ar.review(store, case, "bob", "maybe", 1000)


def test_expired_case_returns_expired():
    store = {}
    case = ar.submit(store, "alice", ANSWERS, 1000)
    store[case]["expires"] = 1000
    assert ar.review(store, case, "bob", "approve", 2000) == "expired"


def test_decided_case_cannot_be_reviewed_again():
    store = {}
    case = ar.submit(store, "alice", ANSWERS, 1000)
    ar.review(store, case, "bob", "approve", 1000)
    with pytest.raises(ValueError):
        ar.review(store, case, "carol", "reject", 1000)


def test_store_must_be_dict():
    with pytest.raises(ValueError):
        ar.submit([], "alice", ANSWERS, 1000)


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        ar.submit({}, "alice", ANSWERS, "now")


def test_concurrent_review_only_one_succeeds():
    store = {}
    case = ar.submit(store, "alice", ANSWERS, 1000)
    results = []

    def worker():
        try:
            ar.review(store, case, "bob", "approve", 1000)
            results.append(True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_empty_case_id_is_rejected():
    with pytest.raises(ValueError):
        ar.review({}, "", "bob", "approve", 1000)


def test_non_string_answers_are_rejected():
    with pytest.raises(ValueError):
        ar.submit({}, "alice", {"a": 1, "b": "y", "c": "z"}, 1000)
