"""Rotation drill: 1300 random scenarios executed by 25 worker threads.

Run with:  python rotation_drill.py

The drill drives ``secret_rotation.rotate`` / ``active_secrets`` through
valid rotations, every documented validation failure, secret-reuse
attempts, contended rotations (exactly one winner) and overlap/expiry
checks.

Two kinds of workloads run concurrently:

* Normal scenarios share one store. A single re-entrant lock wraps every
  "module call + verification" block so the store never changes between
  the call and the check.
* Contention scenarios use a private, isolated store each. Their worker
  threads race lock-free against the module's own rotation lock, which is
  the only thing allowed to serialize them. Exactly one thread may win.
"""

import queue
import random
import string
import threading

import secret_rotation as sr

SCENARIO_COUNT = 1300
THREAD_COUNT = 25
SERVICES = ["api", "auth", "billing", "search", "cache"]
RANDOM_LIMITS = [60, 300, 900, 3600, 86400]

rng = random.Random(20261119)
drill_lock = threading.RLock()


def make_secret(pool=None):
    pool = set() if pool is None else pool
    secret = "".join(
        rng.choice(string.ascii_letters + string.digits)
        for _ in range(rng.randint(sr.SECRET_MIN_LENGTH, 48))
    )
    while secret in pool:
        secret = "".join(
            rng.choice(string.ascii_letters + string.digits)
            for _ in range(rng.randint(sr.SECRET_MIN_LENGTH, 48))
        )
    pool.add(secret)
    return secret


def build_scenarios():
    pool = set()
    scenarios = []
    for index in range(SCENARIO_COUNT):
        kind = index % 10
        service = rng.choice(SERVICES)
        if kind in (0, 1, 2):
            limit = rng.choice(RANDOM_LIMITS)
            scenarios.append(
                (
                    "valid",
                    service,
                    make_secret(pool),
                    rng.randint(0, 10_000_000),
                    rng.randint(0, limit),
                    limit,
                )
            )
        elif kind in (3, 4):
            scenarios.append(("query", service, rng.randint(0, 10_000_000)))
        elif kind == 5:
            scenarios.append(("reuse", service, rng.randint(0, 10_000_000)))
        elif kind == 6:
            limit = rng.choice(RANDOM_LIMITS)
            scenarios.append(
                (
                    "contention",
                    make_secret(),
                    rng.randint(0, 10_000_000),
                    rng.randint(0, limit),
                    limit,
                    rng.randint(2, 6),
                )
            )
        elif kind in (7, 8):
            scenarios.append(("invalid_rotate", rng.randint(0, 11)))
        else:
            scenarios.append(("invalid_query", rng.randint(0, 2)))
    rng.shuffle(scenarios)
    return scenarios


def fresh_store():
    return {"api": {"current": "a" * 32, "history": []}}


INVALID_ROTATE_CASES = [
    lambda: sr.rotate({}, "api", "b" * 32, 1000),
    lambda: sr.rotate(fresh_store(), "", "b" * 32, 1000),
    lambda: sr.rotate(fresh_store(), 7, "b" * 32, 1000),
    lambda: sr.rotate(fresh_store(), "api", "", 1000),
    lambda: sr.rotate(fresh_store(), "api", "short", 1000),
    lambda: sr.rotate(fresh_store(), "api", "b" * 31 + "!", 1000),
    lambda: sr.rotate(fresh_store(), "api", 123, 1000),
    lambda: sr.rotate(fresh_store(), "api", "b" * 32, "now"),
    lambda: sr.rotate(fresh_store(), "api", "b" * 32, 1000, -1),
    lambda: sr.rotate(fresh_store(), "api", "b" * 32, 1000, 100000, 300),
    lambda: sr.rotate([], "api", "b" * 32, 1000),
    lambda: sr.rotate(
        {"api": {"current": "a" * 32, "history": "x"}},
        "api",
        "b" * 32,
        1000,
    ),
]


def run_invalid_rotate(case_index):
    INVALID_ROTATE_CASES[case_index]()


def run_invalid_query(case_index):
    if case_index == 0:
        sr.active_secrets({}, "api", 1000)
    elif case_index == 1:
        sr.active_secrets(fresh_store(), "api", "now")
    else:
        sr.active_secrets([], "api", 1000)


def verify_against_store(store, service, now):
    active = sr.active_secrets(store, service, now)
    entry = store[service]
    if active[0] != entry["current"]:
        raise AssertionError("current secret missing from active list")
    if len(active) != len(set(active)):
        raise AssertionError("active list contains duplicates")
    for secret, expires_at in entry["history"]:
        if now < expires_at:
            if secret not in active:
                raise AssertionError("overlap secret disappeared early")
        elif secret in active:
            raise AssertionError("expired secret still active")


def run_contention(secret, now, overlap, limit, thread_count):
    store = fresh_store()
    initial = store["api"]["current"]
    barrier = threading.Barrier(thread_count)
    outcomes = []

    def contender():
        barrier.wait()
        try:
            result = sr.rotate(store, "api", secret, now, overlap, limit)
            outcomes.append(("ok", result))
        except ValueError:
            outcomes.append(("rejected", None))

    threads = [threading.Thread(target=contender) for _ in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    winners = [item for item in outcomes if item[0] == "ok"]
    if len(winners) != 1:
        raise AssertionError("contended rotation had %d winners" % len(winners))
    result = winners[0][1]
    if store["api"]["current"] != secret:
        raise AssertionError("winning secret did not become current")
    if result["previous"] != initial:
        raise AssertionError("winner did not retire the original secret")
    if store["api"]["history"] != [(initial, now + overlap)]:
        raise AssertionError("history does not match the single rotation")
    verify_against_store(store, "api", now)
    verify_against_store(store, "api", now + overlap)


class Drill:
    def __init__(self):
        secret_pool = set()
        self.store = {
            service: {
                "current": make_secret(secret_pool),
                "history": [],
            }
            for service in SERVICES
        }
        self.counters = {
            "valid": 0,
            "query": 0,
            "reuse_rejected": 0,
            "contention": 0,
            "invalid": 0,
        }
        self.errors = []

    def record(self, name):
        self.counters[name] += 1

    def handle_valid(self, service, secret, now, overlap, limit):
        with drill_lock:
            previous = self.store[service]["current"]
            result = sr.rotate(self.store, service, secret, now, overlap, limit)
            if result["current"] != secret:
                raise AssertionError("rotate did not install new secret")
            if result["previous"] != previous:
                raise AssertionError("rotate did not retire the old secret")
            if result["expires_at"] != now + overlap:
                raise AssertionError("expiry timestamp mismatch")
            if self.store[service]["history"][-1] != (previous, now + overlap):
                raise AssertionError("store did not record the retired secret")
            verify_against_store(self.store, service, now)
            verify_against_store(self.store, service, now + overlap)
            self.record("valid")

    def handle_query(self, service, now):
        with drill_lock:
            verify_against_store(self.store, service, now)
            self.record("query")

    def handle_reuse(self, service, now):
        with drill_lock:
            before = self.store[service]["current"]
            try:
                sr.rotate(self.store, service, before, now)
            except ValueError:
                self.record("reuse_rejected")
            else:
                raise AssertionError("reused secret was accepted")
            if self.store[service]["current"] != before:
                raise AssertionError("rejected rotation changed the store")

    def handle_contention(self, secret, now, overlap, limit, thread_count):
        run_contention(secret, now, overlap, limit, thread_count)
        with drill_lock:
            self.record("contention")

    def handle_invalid_rotate(self, case_index):
        with drill_lock:
            try:
                run_invalid_rotate(case_index)
            except ValueError:
                self.record("invalid")
            else:
                raise AssertionError("invalid rotation was accepted")

    def handle_invalid_query(self, case_index):
        with drill_lock:
            try:
                run_invalid_query(case_index)
            except ValueError:
                self.record("invalid")
            else:
                raise AssertionError("invalid query was accepted")

    def run(self, scenarios):
        task_queue = queue.Queue()
        for scenario in scenarios:
            task_queue.put(scenario)

        def worker():
            while True:
                try:
                    scenario = task_queue.get_nowait()
                except queue.Empty:
                    return
                try:
                    kind = scenario[0]
                    if kind == "valid":
                        self.handle_valid(*scenario[1:])
                    elif kind == "query":
                        self.handle_query(*scenario[1:])
                    elif kind == "reuse":
                        self.handle_reuse(*scenario[1:])
                    elif kind == "contention":
                        self.handle_contention(*scenario[1:])
                    elif kind == "invalid_rotate":
                        self.handle_invalid_rotate(scenario[1])
                    else:
                        self.handle_invalid_query(scenario[1])
                except Exception as exc:  # noqa: BLE001 - drill reports all failures
                    with drill_lock:
                        self.errors.append((scenario, repr(exc)))
                finally:
                    task_queue.task_done()

        threads = [threading.Thread(target=worker) for _ in range(THREAD_COUNT)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        if self.errors:
            for scenario, error in self.errors[:10]:
                print("FAIL", scenario, error)
            raise SystemExit(
                "drill failed with %d error(s) out of %d scenarios"
                % (len(self.errors), SCENARIO_COUNT)
            )

        processed = sum(self.counters.values())
        if processed != SCENARIO_COUNT:
            raise SystemExit(
                "only processed %d of %d scenarios" % (processed, SCENARIO_COUNT)
            )
        print("drill ok: %d scenarios, %d threads" % (SCENARIO_COUNT, THREAD_COUNT))
        for name in sorted(self.counters):
            print("  %-15s %d" % (name, self.counters[name]))


if __name__ == "__main__":
    Drill().run(build_scenarios())
