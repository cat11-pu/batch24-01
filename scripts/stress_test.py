"""Brute-force resistance stress test for BackupCodeGuard.

Runs three checks and exits non-zero on any failure:

1. 1000 randomized sequential attempts checked against an independent
   reference model (window expiry, negative clock jumps, per-user counters,
   malformed input, correct codes).
2. 1000 randomized attempts spread over 32 threads against a locked user --
   the lock must never be bypassed.
3. 50 rounds of 32-thread concurrent hammering on fresh users -- the
   threshold must never be overshot.

Usage:  python scripts/stress_test.py [seed]
"""

import random
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backup_code_guard import (  # noqa: E402
    BackupCodeGuard,
    BackupCodeLockedError,
)

THREADS = 32
RANDOM_TRIALS = 1000
CONCURRENT_ROUNDS = 50
THRESHOLD = 5
WINDOW = 10.0


def random_code(rng):
    if rng.random() < 0.2:
        return rng.choice(
            ["", "12345", "1234567", "abcdef", "000000", 123456, None,
             " 123456", "123456\n", "123456\u0000"]
        )
    return "".join(str(rng.randrange(10)) for _ in range(6))


def sequential_fuzz(rng):
    clock = {"t": 1000.0}
    guard = BackupCodeGuard(
        max_failed_attempts=THRESHOLD,
        window_seconds=WINDOW,
        verifier=lambda code: code == "246810",
        clock=lambda: clock["t"],
    )
    users = ["alice", "bob", "carol", "dave", "erin"]

    # Independent reference state machine mirroring the guard's semantics.
    ref = {}

    def ref_state(user, now):
        """Apply lazy expiry exactly like BackupCodeGuard._get_state."""
        state = ref.get(user)
        if state is None:
            state = {"failures": 0, "start": None, "locked_until": 0.0}
            ref[user] = state
            return state
        window_elapsed = (
            state["start"] is not None
            and max(0.0, now - state["start"]) >= WINDOW
        )
        if window_elapsed:
            state["failures"] = 0
            state["start"] = None
            state["locked_until"] = 0.0
        return state

    def ref_is_locked(user, now):
        state = ref_state(user, now)
        return now < state["locked_until"]

    for trial in range(RANDOM_TRIALS):
        user = rng.choice(users)
        roll = rng.random()
        if roll < 0.08:
            clock["t"] += rng.uniform(-5.0, 12.0)
        else:
            clock["t"] += rng.uniform(0.0, 0.01)
        now = clock["t"]

        ref_locked = ref_is_locked(user, now)
        assert guard.is_locked(user) == ref_locked, (
            "trial %d: lock state mismatch for %s" % (trial, user)
        )
        state = ref_state(user, now)
        assert guard.remaining_attempts(user) == max(
            0, THRESHOLD - state["failures"]
        )

        code = rng.choice([random_code(rng), "246810"])
        well_formed = (
            isinstance(code, str)
            and len(code) == 6
            and all(ch in "0123456789" for ch in code)
            and code != "000000"
        )
        try:
            result = guard.validate(user, code)
        except BackupCodeLockedError:
            state = ref_state(user, now)
            if now < state["locked_until"]:
                continue
            # The threshold-reaching attempt itself raises and locks.
            assert well_formed and code != "246810", (
                "trial %d: locked without a wrong guess" % trial
            )
            state["failures"] += 1
            if state["start"] is None:
                state["start"] = now
            assert state["failures"] == THRESHOLD
            state["locked_until"] = now + WINDOW
            state["start"] = state["locked_until"] - WINDOW
            continue
        except (TypeError, ValueError):
            state = ref_state(user, now)
            assert not (now < state["locked_until"]) and not well_formed, (
                "trial %d: valid input rejected" % trial
            )
            continue

        state = ref_state(user, now)
        assert not (now < state["locked_until"]), (
            "trial %d: lock bypassed" % trial
        )
        if code == "246810":
            assert result is True
            state["failures"] = 0
            state["start"] = None
            state["locked_until"] = 0.0
        else:
            assert well_formed, "trial %d: malformed code accepted" % trial
            assert result is False
            state["failures"] += 1
            if state["start"] is None:
                state["start"] = now
            if state["failures"] >= THRESHOLD:
                state["locked_until"] = now + WINDOW


def locked_user_burst(rng):
    guard = BackupCodeGuard(
        max_failed_attempts=THRESHOLD,
        window_seconds=WINDOW,
        verifier=lambda code: code == "246810",
        clock=time.monotonic,
    )
    for _ in range(THRESHOLD - 1):
        assert guard.validate("victim", "111111") is False
    try:
        guard.validate("victim", "111111")
    except BackupCodeLockedError:
        pass
    else:
        raise AssertionError("threshold attempt did not lock the user")
    assert guard.is_locked("victim")

    outcomes = []
    outcome_lock = threading.Lock()
    barrier = threading.Barrier(THREADS)
    per_thread = RANDOM_TRIALS // THREADS
    extra = RANDOM_TRIALS - per_thread * THREADS

    def worker():
        local = []
        barrier.wait()
        for _ in range(per_thread):
            code = rng.choice([random_code(rng), "246810", "111111", ""])
            try:
                guard.validate("victim", code)
                local.append("ok")
            except BackupCodeLockedError:
                local.append("locked")
            except (TypeError, ValueError):
                local.append("invalid")
        with outcome_lock:
            outcomes.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Distribute the remainder onto the first workers, still under lock.
    for _ in range(extra):
        try:
            guard.validate("victim", random_code(rng))
            outcomes.append("ok")
        except BackupCodeLockedError:
            outcomes.append("locked")
        except (TypeError, ValueError):
            outcomes.append("invalid")

    assert len(outcomes) == RANDOM_TRIALS
    assert set(outcomes) == {"locked"}, (
        "lock bypassed: %s"
        % {kind: outcomes.count(kind) for kind in set(outcomes)}
    )


def concurrent_threshold_rounds():
    guard = BackupCodeGuard(
        max_failed_attempts=THRESHOLD,
        window_seconds=WINDOW,
        verifier=lambda code: code == "246810",
    )
    for round_index in range(CONCURRENT_ROUNDS):
        user = "round-%d" % round_index
        barrier = threading.Barrier(THREADS)
        counts = {"false": 0, "locked": 0}
        counts_lock = threading.Lock()

        def worker():
            barrier.wait()
            try:
                result = guard.validate(user, "111111")
                kind = "false" if result is False else "other"
            except BackupCodeLockedError:
                kind = "locked"
            with counts_lock:
                counts[kind] = counts.get(kind, 0) + 1

        threads = [threading.Thread(target=worker) for _ in range(THREADS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert counts.get("other", 0) == 0
        assert counts["false"] == THRESHOLD - 1, counts
        assert counts["locked"] == THREADS - (THRESHOLD - 1), counts
        assert guard.is_locked(user)
        assert guard.remaining_attempts(user) == 0


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 4210
    start = time.monotonic()

    sequential_fuzz(random.Random(seed))
    print("[1/3] %d randomized sequential attempts: OK" % RANDOM_TRIALS)

    locked_user_burst(random.Random(seed + 1))
    print(
        "[2/3] %d attempts over %d threads on locked user: OK"
        % (RANDOM_TRIALS, THREADS)
    )

    concurrent_threshold_rounds()
    print(
        "[3/3] %d concurrent rounds x %d threads: OK"
        % (CONCURRENT_ROUNDS, THREADS)
    )
    print("all stress checks passed in %.2fs" % (time.monotonic() - start))


if __name__ == "__main__":
    main()
