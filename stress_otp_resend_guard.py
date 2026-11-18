"""Concurrency stress check for otp_resend_guard.validate.

Generates boundary cases plus 1000 random timestamp pairs and hammers
validate() from 32 threads, asserting that the cooldown / hourly limit
can never be bypassed and that results are deterministic under concurrency.

Run: python3 stress_otp_resend_guard.py
"""

import random
import threading
import time

from otp_resend_guard import (
    COOLDOWN_SECONDS,
    MAX_SENDS_PER_WINDOW,
    WINDOW_SECONDS,
    validate,
)

THREADS = 32
RANDOM_CASES = 1000


def expect_allowed(pair, now_ref):
    if not isinstance(pair, (list, tuple)) or len(pair) != 2:
        return False
    last, now = pair
    for item in (last, now):
        if isinstance(item, bool) or not isinstance(item, int):
            return False
    if last < 0 or now < 0 or now < last or now > now_ref:
        return False
    elapsed = now - last
    return elapsed > COOLDOWN_SECONDS and elapsed > WINDOW_SECONDS * MAX_SENDS_PER_WINDOW


def build_cases(now_ref):
    boundaries = [
        [0, 0],          # 0-second boundary
        [0, 59],         # 59 seconds, inside cooldown
        [0, 60],         # 60 seconds, cooldown boundary
        [0, 61],         # just past cooldown, still inside hourly window
        [0, -1],         # negative timestamp
        [-1, 0],         # negative last send
        [1000, 999],     # time going backwards
        ["", 0],         # empty value (empty number)
        ["", -1],
        [0, None],
        [0, 1.5],
        [True, 0],
        [0, WINDOW_SECONDS],                    # hourly limit boundary
        [1000, 1000 + WINDOW_SECONDS],          # hourly limit boundary
        [0, WINDOW_SECONDS + 1],                # just past the window: allowed
        [now_ref - 2 * WINDOW_SECONDS, now_ref],  # valid resend: allowed
        [now_ref, now_ref + 2 * WINDOW_SECONDS],  # future timestamp
        [now_ref + WINDOW_SECONDS, now_ref + 2 * WINDOW_SECONDS],  # future
    ]
    rng = random.Random(20261119)
    random_cases = []
    for _ in range(RANDOM_CASES):
        last = rng.randint(-100, now_ref)
        delta = rng.choice((
            rng.randint(-100, 100),
            rng.randint(0, COOLDOWN_SECONDS * 2),
            rng.randint(0, WINDOW_SECONDS * 3),
        ))
        random_cases.append([last, last + delta])
    return boundaries + random_cases


def main():
    now_ref = int(time.time())
    cases = build_cases(now_ref)
    expected = {i: expect_allowed(pair, now_ref) for i, pair in enumerate(cases)}

    failures = []
    lock = threading.Lock()

    def worker(chunk):
        local = []
        for index in chunk:
            pair = cases[index]
            try:
                result = validate(pair)
                allowed = result is True
            except (ValueError, TypeError):
                allowed = False
            except Exception as exc:  # unexpected exception type
                local.append("case %r raised unexpected %r" % (pair, exc))
                continue
            if allowed != expected[index]:
                local.append("case %r: expected %s, got %s"
                             % (pair, expected[index], allowed))
        with lock:
            failures.extend(local)

    chunks = [list(range(len(cases)))[i::THREADS] for i in range(THREADS)]
    threads = [threading.Thread(target=worker, args=(chunk,)) for chunk in chunks]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    rejected = sum(1 for ok in expected.values() if not ok)
    allowed = sum(1 for ok in expected.values() if ok)
    print("threads=%d cases=%d rejected=%d allowed=%d failures=%d"
          % (THREADS, len(cases), rejected, allowed, len(failures)))
    for failure in failures[:20]:
        print("FAIL:", failure)
    if allowed == 0:
        print("FAIL: guard accepted nothing at all")
        raise SystemExit(1)
    if failures:
        raise SystemExit(1)
    print("OK: cooldown and hourly limit held under concurrency")


if __name__ == "__main__":
    main()
