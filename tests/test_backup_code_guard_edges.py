import threading

import pytest

from backup_code_guard import (
    MAX_FAILED_ATTEMPTS,
    BackupCodeGuard,
    BackupCodeLockedError,
    InvalidBackupCodeError,
    validate,
)


def make_guard(**kwargs):
    return BackupCodeGuard(
        max_failed_attempts=kwargs.pop("max_failed_attempts", 5),
        window_seconds=kwargs.pop("window_seconds", 10.0),
        verifier=kwargs.pop("verifier", lambda code: code == "246810"),
        **kwargs,
    )


def test_validate_accepts_sample_below_threshold():
    assert validate([1, "123456"]) is True
    assert validate([MAX_FAILED_ATTEMPTS - 1, "999998"]) is True


def test_validate_rejects_zero_attempts():
    with pytest.raises(ValueError):
        validate([0, "123456"])


def test_validate_rejects_negative_attempts():
    with pytest.raises(ValueError):
        validate([-1, "123456"])


def test_validate_rejects_non_int_attempts():
    for bad in (1.0, "1", True, None, [1]):
        with pytest.raises((TypeError, ValueError)):
            validate([bad, "123456"])


def test_validate_rejects_attempts_at_and_over_threshold():
    for attempts in (MAX_FAILED_ATTEMPTS, MAX_FAILED_ATTEMPTS + 1, 100):
        with pytest.raises(ValueError):
            validate([attempts, "123456"])


def test_validate_rejects_empty_and_malformed_codes():
    for bad in ("", "12345", "1234567", "abcdef", "123456\n",
                "123456\u0000", " 123456", "123456 ", "000000"):
        with pytest.raises(ValueError):
            validate([1, bad])


def test_validate_rejects_non_string_codes():
    for bad in (123456, None, b"123456", ["123456"], 0):
        with pytest.raises((TypeError, ValueError)):
            validate([1, bad])


def test_validate_rejects_wrong_container_shapes():
    for bad in (None, "123456", 123456, [1], [1, "123456", 3], (1,)):
        with pytest.raises((TypeError, ValueError)):
            validate(bad)


def test_threshold_is_configurable_not_hardcoded():
    guard = make_guard(max_failed_attempts=3)
    assert guard.remaining_attempts("u") == 3
    guard.validate("u", "111111")
    guard.validate("u", "111111")
    assert guard.remaining_attempts("u") == 1
    with pytest.raises(BackupCodeLockedError):
        guard.validate("u", "111111")
    assert guard.is_locked("u")


def test_counters_are_per_user():
    guard = make_guard(max_failed_attempts=5)
    for _ in range(4):
        assert guard.validate("alice", "111111") is False
    assert guard.remaining_attempts("bob") == 5
    assert guard.validate("bob", "246810") is True
    assert guard.remaining_attempts("alice") == 1


def test_lock_blocks_even_correct_code():
    guard = make_guard(max_failed_attempts=5)
    for _ in range(4):
        guard.validate("u", "111111")
    with pytest.raises(BackupCodeLockedError):
        guard.validate("u", "111111")
    assert guard.is_locked("u")
    with pytest.raises(BackupCodeLockedError):
        guard.validate("u", "246810")


def test_success_resets_window():
    guard = make_guard(max_failed_attempts=5)
    for _ in range(3):
        guard.validate("u", "111111")
    assert guard.remaining_attempts("u") == 2
    assert guard.validate("u", "246810") is True
    assert guard.remaining_attempts("u") == 5


def test_window_expiry_unlocks_and_resets_counter():
    clock = {"t": 1000.0}
    window = 10.0
    guard = make_guard(window_seconds=window, clock=lambda: clock["t"])
    for _ in range(4):
        guard.validate("u", "111111")
    with pytest.raises(BackupCodeLockedError):
        guard.validate("u", "111111")
    assert guard.is_locked("u")
    clock["t"] += window - 1
    assert guard.is_locked("u")
    clock["t"] += window + 1
    assert not guard.is_locked("u")
    assert guard.remaining_attempts("u") == 5
    assert guard.validate("u", "246810") is True


def test_negative_elapsed_time_does_not_unlock():
    ticks = [1000.0]
    window = 10.0
    guard = make_guard(window_seconds=window, clock=lambda: ticks[0])
    for _ in range(4):
        guard.validate("u", "111111")
    with pytest.raises(BackupCodeLockedError):
        guard.validate("u", "111111")
    # Clock jumps backwards into the past: the lock must survive.
    ticks[0] = 0.0
    assert guard.is_locked("u")
    with pytest.raises(BackupCodeLockedError):
        guard.validate("u", "246810")
    # Even a later-but-still-before-window-start reading stays locked.
    ticks[0] = 999.0
    assert guard.is_locked("u")
    assert guard.remaining_attempts("u") == 0
    # Just before the window ends the lock is still in force.
    ticks[0] = 1000.0 + window - 0.5
    assert guard.is_locked("u")
    with pytest.raises(BackupCodeLockedError):
        guard.validate("u", "246810")
    # Once the window (and therefore the lock) really expires, fresh budget.
    ticks[0] = 1000.0 + window + 0.5
    assert not guard.is_locked("u")
    assert guard.remaining_attempts("u") == 5


def test_malformed_input_is_not_counted():
    guard = make_guard(max_failed_attempts=5)
    for bad in ("", "12345", 123456, None, "000000"):
        with pytest.raises((TypeError, ValueError)):
            guard.validate("u", bad)
    assert guard.remaining_attempts("u") == 5


def test_guard_rejects_invalid_constructor_arguments():
    with pytest.raises(ValueError):
        BackupCodeGuard(max_failed_attempts=0)
    with pytest.raises(ValueError):
        BackupCodeGuard(max_failed_attempts=-2)
    with pytest.raises(ValueError):
        BackupCodeGuard(window_seconds=0)
    with pytest.raises(ValueError):
        BackupCodeGuard(window_seconds=-1)
    with pytest.raises(TypeError):
        BackupCodeGuard(clock=123)


def test_reset_clears_user_state():
    guard = make_guard()
    guard.validate("u", "111111")
    guard.reset("u")
    assert guard.remaining_attempts("u") == 5
    guard.validate("u", "111111")
    guard.reset()
    assert guard.remaining_attempts("u") == 5


def test_concurrent_wrong_guesses_never_exceed_threshold():
    threshold = 5
    guard = make_guard(max_failed_attempts=threshold)
    threads = 32
    barrier = threading.Barrier(threads)
    results = {"false": 0, "locked": 0, "other": 0}

    def worker():
        barrier.wait()
        try:
            outcome = guard.validate("shared-user", "111111")
            results["false" if outcome is False else "other"] += 1
        except BackupCodeLockedError:
            results["locked"] += 1

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()

    assert results["other"] == 0
    assert results["false"] == threshold - 1
    assert results["locked"] == threads - (threshold - 1)
    assert guard.is_locked("shared-user")
    assert guard.remaining_attempts("shared-user") == 0


def test_concurrent_attempts_against_many_users_are_isolated():
    guard = make_guard(max_failed_attempts=4)
    errors = []

    def worker(user_id):
        try:
            for _ in range(3):
                guard.validate(user_id, "111111")
            if guard.remaining_attempts(user_id) != 1:
                errors.append("wrong budget for %s" % user_id)
        except BackupCodeLockedError as exc:
            errors.append(str(exc))

    threads = [
        threading.Thread(target=worker, args=("user-%d" % i,))
        for i in range(32)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []


def test_invalid_backup_code_error_is_value_error():
    with pytest.raises(ValueError):
        validate([1, ""])
    with pytest.raises(InvalidBackupCodeError):
        validate([1, "nope"])
