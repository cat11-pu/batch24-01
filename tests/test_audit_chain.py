import threading

import pytest

import audit_chain as ac

SECRET = "s" * 32


def test_first_entry_has_sequence_one():
    chain = []
    entry = ac.append(chain, {"a": 1}, SECRET)
    assert entry["seq"] == 1


def test_second_entry_has_sequence_two():
    chain = []
    ac.append(chain, {"a": 1}, SECRET)
    entry = ac.append(chain, {"a": 2}, SECRET)
    assert entry["seq"] == 2


def test_tampered_event_fails_verification():
    chain = []
    ac.append(chain, {"a": 1}, SECRET)
    ac.append(chain, {"a": 2}, SECRET)
    chain[0]["event"]["a"] = 99
    assert ac.verify(chain, SECRET) is False


def test_broken_previous_hash_fails_verification():
    chain = []
    ac.append(chain, {"a": 1}, SECRET)
    ac.append(chain, {"a": 2}, SECRET)
    chain[1]["prev_hash"] = "bad"
    assert ac.verify(chain, SECRET) is False


def test_wrong_secret_fails_verification():
    chain = []
    ac.append(chain, {"a": 1}, SECRET)
    assert ac.verify(chain, "z" * 32) is False


def test_deleted_middle_entry_fails_verification():
    chain = []
    ac.append(chain, {"a": 1}, SECRET)
    ac.append(chain, {"a": 2}, SECRET)
    ac.append(chain, {"a": 3}, SECRET)
    del chain[1]
    assert ac.verify(chain, SECRET) is False


def test_reordered_entries_fail_verification():
    chain = []
    ac.append(chain, {"a": 1}, SECRET)
    ac.append(chain, {"a": 2}, SECRET)
    chain[0], chain[1] = chain[1], chain[0]
    assert ac.verify(chain, SECRET) is False


def test_empty_event_is_rejected():
    with pytest.raises(ValueError):
        ac.append([], {}, SECRET)


def test_non_list_chain_is_rejected():
    with pytest.raises(ValueError):
        ac.append("chain", {"a": 1}, SECRET)


def test_empty_secret_is_rejected():
    with pytest.raises(ValueError):
        ac.append([], {"a": 1}, "")


def test_verify_non_list_is_rejected():
    with pytest.raises(ValueError):
        ac.verify("chain", SECRET)


def test_empty_chain_is_invalid():
    assert ac.verify([], SECRET) is False


def test_missing_hash_field_fails_verification():
    chain = [{"seq": 1, "event": {"a": 1}, "prev_hash": "0", "hash": "x"}]
    assert ac.verify(chain, SECRET) is False


def test_non_dict_event_is_rejected():
    with pytest.raises(ValueError):
        ac.append([], "event", SECRET)


def test_concurrent_appends_have_unique_sequences():
    chain = []

    def worker():
        ac.append(chain, {"x": 1}, SECRET)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(e["seq"] for e in chain) == [1, 2]
