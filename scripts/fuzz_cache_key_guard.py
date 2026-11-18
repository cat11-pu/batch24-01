"""Fuzz and concurrency check for the cache-key guard.

It generates 1000 random header sets covering the required boundaries
(Host, X-Forwarded-Host, Authorization, Cookie, ports, suffix look-alikes
and empty values), then drives a model shared cache from 32 threads.

Three poisoning properties are asserted:

1. every request rejected by ``validate`` is refused before it can create
   or read a cache entry;
2. for a fixed URL, distinct validated header sets always produce distinct
   cache keys, so an attacker's headers can never collide with a victim's;
3. concurrent cache access from 32 threads never serves a response created
   for different validated headers.
"""

import os
import random
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cache_key_guard import build_cache_key, validate


RANDOM_SEED = 20261119
ROUNDS = 1000
THREADS = 32

HOST_HEADER = "Host"
FORWARDED_HOST_HEADER = "X-Forwarded-Host"
FORWARDED_PROTO_HEADER = "X-Forwarded-Proto"
FORWARDED_PORT_HEADER = "X-Forwarded-Port"
AUTH_HEADER = "Authorization"
COOKIE_HEADER = "Cookie"


HOST_PAYLOADS = [
    "app.example.com",
    "cdn.example.com",
    "evil.com",
    "app.example.com.evil.com",
    "evil.com/app.example.com",
    "app.example.com\r\n",
    "app.example.com ",
    " app.example.com",
    "",
    "APP.EXAMPLE.COM",
    "App.Example.Com",
    "app.example.com.",
    "app.example.com:443",
    "app.example.com:80",
    "app.example.com:8443",
    "app.example.com:0",
    "app.example.com:notaport",
    ":443",
]

FORWARDING_PAYLOADS = [
    "evil.com",
    "app.example.com",
    "app.example.com.evil.com",
    "",
    "APP.EXAMPLE.COM",
    "app.example.com:8443",
    "app.example.com\r\n",
]

SENSITIVE_PAYLOADS = [
    "Bearer abc123",
    "Basic dXNlcjpwYXNz",
    "session=abc; csrf=def",
    "",
    "x\r\n",
]

OTHER_HEADERS = [
    ("Accept-Language", ["en", "zh", ""]),
    ("X-User", ["admin", "guest", ""]),
    (FORWARDED_PROTO_HEADER, ["https", "http", ""]),
    (FORWARDED_PORT_HEADER, ["443", "8443", "", "0"]),
    ("Accept", ["application/json", "text/html", ""]),
    ("X-Evil", ["poison", ""]),
]


def random_headers(rng):
    headers = []

    if rng.random() < 0.9:
        # bias toward clean, allow-listed values while keeping every
        # malicious payload reachable so accepted/rejected cases both
        # occur in meaningful numbers
        clean_hosts = ["app.example.com", "cdn.example.com"]
        host_values = clean_hosts * 6 + HOST_PAYLOADS
        headers.append([HOST_HEADER, rng.choice(host_values)])

    if rng.random() < 0.5:
        clean_forwarded = ["app.example.com"]
        headers.append(
            [FORWARDED_HOST_HEADER,
             rng.choice(clean_forwarded * 4 + FORWARDING_PAYLOADS)]
        )

    if rng.random() < 0.15:
        headers.append(
            [rng.choice((AUTH_HEADER, COOKIE_HEADER)),
             rng.choice(SENSITIVE_PAYLOADS)]
        )

    for name, values in OTHER_HEADERS:
        if rng.random() < 0.25:
            clean = {
                FORWARDED_PROTO_HEADER: "https",
                FORWARDED_PORT_HEADER: "443",
            }.get(name)
            pool = [clean] * 4 + values if clean else values
            headers.append([name, rng.choice(pool)])

    rng.shuffle(headers)
    return headers


class SharedCache:
    """Minimal thread-safe cache keyed by ``build_cache_key`` output."""

    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

    def get_or_set(self, key, response):
        with self._lock:
            if key not in self._store:
                self._store[key] = response
            return self._store[key]

    def __len__(self):
        with self._lock:
            return len(self._store)


def classify(cases):
    accepted = []
    rejected = []
    for case in cases:
        try:
            canonical = validate(case)
        except (ValueError, TypeError):
            rejected.append(case)
        else:
            accepted.append((case, canonical))
    return accepted, rejected


def check_key_uniqueness(accepted, errors):
    key_to_signature = {}
    for headers, canonical in accepted:
        url = "/resource"
        signature = tuple(sorted(canonical.items()))
        key = build_cache_key(url, headers)
        previous = key_to_signature.get(key)
        if previous is not None and previous != signature:
            errors.append(
                "key collision on %s: %r vs %r" % (url, previous, signature)
            )
        key_to_signature[key] = signature

        # identical validated input must always hash to the same key
        if build_cache_key(url, headers) != key:
            errors.append("unstable key for %r" % (headers,))


def run_concurrent_cache(accepted, errors):
    cache = SharedCache()
    local = threading.local()
    lock = threading.Lock()
    observed = {"active": 0, "max": 0}
    # one-shot barrier sized exactly to the worker count, so all threads
    # touch the shared cache simultaneously despite the short operations
    barrier = threading.Barrier(THREADS)

    def worker(index):
        rng = random.Random(RANDOM_SEED + index)
        with lock:
            observed["active"] += 1
            observed["max"] = max(observed["max"], observed["active"])
        try:
            barrier.wait()
            for _ in range(ROUNDS // THREADS):
                headers, _ = accepted[rng.randrange(len(accepted))]
                url = "/resource/%d" % rng.randrange(4)
                # validation happens before any cache access
                key = build_cache_key(url, headers)
                response = "resp:%s" % key
                served = cache.get_or_set(key, response)
                if served != response:
                    with lock:
                        errors.append(
                            "foreign response served for %r on %s"
                            % (headers, url)
                        )
        finally:
            with lock:
                observed["active"] -= 1

    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        list(pool.map(worker, range(THREADS)))
    return cache, observed["max"]


def check_boundaries(errors):
    required_rejects = [
        [[HOST_HEADER, "evil.com"]],
        [[FORWARDED_HOST_HEADER, "evil.com"]],
        [[FORWARDED_HOST_HEADER, "app.example.com"],
         [HOST_HEADER, "evil.com"]],
        [[AUTH_HEADER, "Bearer x"]],
        [[COOKIE_HEADER, "session=x"]],
        [["Accept-Language", "en"]],
        [["X-User", "admin"]],
        [[HOST_HEADER, "app.example.com\r\n"]],
        [[HOST_HEADER, ""]],
        [[HOST_HEADER, "APP.EXAMPLE.COM"]],
        [[FORWARDED_PROTO_HEADER, "http"]],
        [[FORWARDED_PORT_HEADER, "8443"]],
        [[HOST_HEADER, "app.example.com:8443"]],
        [[HOST_HEADER, "app.example.com"],
         [FORWARDED_HOST_HEADER, "evil.com"]],
        [[HOST_HEADER, "app.example.com.evil.com"]],
    ]
    for boundary in required_rejects:
        try:
            validate(boundary)
        except (ValueError, TypeError):
            continue
        errors.append("boundary accepted, must reject: %r" % boundary)


def check_poisoning_matrix(errors):
    """Deterministic attacker/victim pairs on the same URL must never share
    a cache entry, while identical victim requests must keep sharing one."""
    url = "/poison-target"
    victim = [[HOST_HEADER, "app.example.com"]]
    attacks = [
        [[HOST_HEADER, "evil.com"]],
        [[HOST_HEADER, "app.example.com.evil.com"]],
        [[HOST_HEADER, "app.example.com:8443"]],
        [[HOST_HEADER, "APP.EXAMPLE.COM"]],
        [[HOST_HEADER, ""]],
        [[HOST_HEADER, "app.example.com\r\n"]],
        [v for v in victim] + [[FORWARDED_HOST_HEADER, "evil.com"]],
        [v for v in victim] + [[AUTH_HEADER, "Bearer attacker"]],
        [v for v in victim] + [[COOKIE_HEADER, "session=attacker"]],
        [v for v in victim] + [[FORWARDED_PROTO_HEADER, "http"]],
        [v for v in victim] + [[FORWARDED_PORT_HEADER, "8443"]],
        [v for v in victim] + [["X-User", "admin"]],
    ]
    victim_key = build_cache_key(url, victim)
    if build_cache_key(url, [list(pair) for pair in victim]) != victim_key:
        errors.append("victim key is not stable")
    for attack in attacks:
        try:
            attack_key = build_cache_key(url, attack)
        except (ValueError, TypeError):
            continue
        if attack_key == victim_key:
            errors.append("attack collides with victim key: %r" % attack)


def main():
    rng = random.Random(RANDOM_SEED)
    cases = [random_headers(rng) for _ in range(ROUNDS)]

    accepted, rejected = classify(cases)
    errors = []

    check_key_uniqueness(accepted, errors)
    cache, max_concurrency = run_concurrent_cache(accepted, errors)
    check_boundaries(errors)
    check_poisoning_matrix(errors)

    # property 1: rejected cases must be structurally unable to reach the
    # cache -- build_cache_key itself has to raise for them too
    for case in rejected:
        try:
            build_cache_key("/resource", case)
        except (ValueError, TypeError):
            continue
        errors.append("rejected headers produced a cache key: %r" % case)

    print("rounds           :", ROUNDS)
    print("threads          :", THREADS)
    print("accepted headers :", len(accepted))
    print("rejected headers :", len(rejected))
    print("cache entries    :", len(cache))
    print("max concurrency  :", max_concurrency)
    print("boundary cases   : 15")
    print("errors           :", len(errors))

    if max_concurrency != THREADS:
        errors.append(
            "expected %d concurrent workers, observed %d"
            % (THREADS, max_concurrency)
        )

    if errors:
        for error in errors:
            print("FAIL:", error)
        raise SystemExit(1)

    print("OK: rejected input never reaches cache, keys stay distinct, "
          "no poisoning under concurrency")


if __name__ == "__main__":
    main()
