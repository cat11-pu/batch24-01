"""Fuzz and concurrency verification for ``error_guard.validate``.

Generates 1000 random messages (malicious fragments plus benign traffic),
then validates them from 32 worker threads. Every malicious sample must be
rejected with the generic wording only, and no fragment of the input may
appear in the raised exception.
"""

import os
import random
import string
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from error_guard import GENERIC_ERROR_MESSAGE, validate

TOTAL_SAMPLES = 1000
THREAD_COUNT = 32

BAD_FRAGMENTS = [
    'Traceback (most recent call last): File "/app/main.py", line 7',
    "Traceback\n  at handler(RequestHandler.java:128)",
    '  File "/srv/app/db.py", line 42, in query',
    "sqlite3.OperationalError: no such table: sessions",
    "psycopg2.errors.UndefinedTable: relation does not exist",
    "SELECT id, email FROM users WHERE token = 'x'",
    "select * from orders where id = 1; drop table audit;",
    "INSERT INTO logs (msg) VALUES ('boom')",
    "UPDATE accounts SET balance = 0 WHERE uid = 9",
    "DELETE FROM sessions WHERE expired = 1",
    "/home/cat/app/config.py",
    "/etc/nginx/conf.d/default.conf",
    "/var/log/app/error.log",
    "C:\\Users\\admin\\secrets\\key.pem",
    "D:/workspace/service/src/main.py",
    "10.0.0.12:5432 connection refused",
    "cannot reach 192.168.1.1",
    "dial tcp 172.16.4.9:6379 i/o timeout",
    "loopback at 127.0.0.1:8080",
    "host fe80::1c2a:3bff:fe44:5d6e unreachable",
    "fd00::1 refused",
    "token=eyJhbGciOiJIUzI1NiJ9.payload.sig",
    "password=hunter2",
    "secret = s3cr3t-value",
    "access_key=AKIAIOSFODNN7EXAMPLE",
    "api_key: sk-live-1234567890abcdef",
    "Authorization: Bearer abcdef0123456789",
    "postgresql://user:pass@db.internal/app",
    "redis://10.0.0.5:6379/0",
    "mongodb://admin:pw@mongo:27017",
    "amqp://guest:guest@rabbit/%2f",
]

GOOD_MESSAGES = [
    "Your request could not be completed. Please try again later.",
    "The service is temporarily unavailable.",
    "Invalid input. Please check the form and resubmit.",
    "Payment declined by the provider.",
    "Rate limit exceeded. Wait a moment before retrying.",
    "Subscription required to access this feature.",
    "The selected option is no longer available.",
    "Verification code expired. Request a new one.",
    "Your session has ended. Please sign in again.",
    "Operation canceled by the user.",
    "No results match the current filters.",
    "The upload did not finish. Try a smaller file.",
    "Settings saved successfully.",
    "We could not find that page.",
    "A network hiccup interrupted the download.",
    "Please confirm your email address first.",
    "The meeting room is already booked.",
    "Try refreshing the page to see updates.",
    "That username is taken. Pick another.",
    "All fields marked with a star are required.",
]


def random_string(rng, max_len):
    alphabet = string.ascii_letters + string.digits + " .,-_!?'"
    length = rng.randint(1, max_len)
    return "".join(rng.choice(alphabet) for _ in range(length))


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 20261119
    rng = random.Random(seed)
    samples = []
    for index in range(TOTAL_SAMPLES):
        is_bad = index % 10 < 7
        if is_bad:
            fragment = rng.choice(BAD_FRAGMENTS)
            style = rng.randrange(5)
            if style == 0:
                payload = fragment
            elif style == 1:
                payload = random_string(rng, 40) + " | " + fragment
            elif style == 2:
                payload = fragment + " :: " + random_string(rng, 40)
            elif style == 3:
                payload = "context: " + fragment + " (see logs)"
            else:
                payload = (
                    random_string(rng, 20)
                    + "\n"
                    + fragment
                    + "\n"
                    + random_string(rng, 20)
                )
        elif rng.random() < 0.8:
            payload = rng.choice(GOOD_MESSAGES)
        else:
            payload = random_string(rng, rng.randint(1, 200))
        samples.append((is_bad, payload))

    failures = []
    leak_hits = []
    counters = {"rejected": 0, "accepted": 0}
    lock = threading.Lock()
    queue = list(enumerate(samples))

    def worker():
        while True:
            with lock:
                if not queue:
                    return
                index, (is_bad, payload) = queue.pop()
            try:
                validate(payload)
                outcome = "accepted"
            except (ValueError, TypeError) as exc:
                outcome = "rejected"
                rendered = str(exc)
                if rendered != "INTERNAL_ERROR: " + GENERIC_ERROR_MESSAGE:
                    with lock:
                        failures.append((index, "non-generic exception: %r" % rendered))
                for needle in payload.split():
                    if len(needle) >= 6 and needle in rendered:
                        with lock:
                            leak_hits.append((index, needle))
                        break
            with lock:
                counters[outcome] += 1
                if is_bad and outcome != "rejected":
                    failures.append((index, "malicious sample accepted: %.80r" % payload))
                if not is_bad and outcome != "accepted":
                    failures.append((index, "benign sample rejected: %.80r" % payload))

    threads = [threading.Thread(target=worker) for _ in range(THREAD_COUNT)]
    start = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - start

    print("seed: %d" % seed)
    print("samples: %d (malicious=%d benign=%d)" % (
        TOTAL_SAMPLES,
        sum(1 for is_bad, _ in samples if is_bad),
        sum(1 for is_bad, _ in samples if not is_bad),
    ))
    print("threads: %d, elapsed: %.3fs" % (THREAD_COUNT, elapsed))
    print("rejected: %d, accepted: %d" % (counters["rejected"], counters["accepted"]))
    print("failures: %d, leaks: %d" % (len(failures), len(leak_hits)))
    for failure in failures[:10]:
        print("  FAIL", failure)
    for leak in leak_hits[:10]:
        print("  LEAK", leak)

    assert not failures and not leak_hits, "seed %d produced failures" % seed


if __name__ == "__main__":
    main()
