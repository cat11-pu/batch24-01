import threading

import pytest

import session_fixation as sf


def test_1_login_returns_new_session_id():
    sid = sf.login("alice", "attacker-fixed")
    assert sid != "attacker-fixed"


def test_2_new_session_id_has_enough_entropy():
    sid = sf.login("alice", "attacker-fixed")
    assert len(sid) >= 32


def test_3_two_logins_get_different_ids():
    first = sf.login("alice")
    second = sf.login("alice")
    assert first != second


def test_4_default_id_is_not_predictable():
    sid = sf.login("alice")
    assert sid != "session-fixed"


def test_5_old_id_is_invalid_after_login():
    old = "attacker-fixed"
    sf.login("alice", old)
    assert sf.is_valid(old) is False


def test_6_new_id_is_bound_to_user():
    sid = sf.login("alice", "attacker-fixed")
    assert sf.is_valid(sid, "bob") is False


def test_7_logout_invalidates_session():
    sid = sf.login("alice")
    sf.logout(sid)
    assert sf.is_valid(sid) is False


def test_8_empty_user_is_rejected():
    with pytest.raises(ValueError):
        sf.login("")


def test_9_non_string_user_is_rejected():
    with pytest.raises(TypeError):
        sf.login(123)


def test_10_repeated_login_rotates_again():
    first = sf.login("alice")
    second = sf.login("alice")
    assert first != second


def test_11_old_session_invalid_after_second_login():
    first = sf.login("alice")
    sf.login("alice")
    assert sf.is_valid(first) is False


def test_12_attacker_preset_id_is_not_reused():
    sid = sf.login("alice", "preset-by-attacker")
    assert sid != "preset-by-attacker"


def test_13_empty_user_with_preset_is_rejected():
    with pytest.raises(ValueError):
        sf.login("", "preset-by-attacker")


def test_14_logout_user_invalidates_all_sessions():
    first = sf.login("alice")
    second = sf.login("alice")
    sf.logout_user("alice")
    assert sf.is_valid(first) is False
    assert sf.is_valid(second) is False


def test_15_concurrent_login_gets_unique_ids():
    results = []

    def worker():
        results.append(sf.login("alice", "shared-preset"))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(set(results)) == 2
