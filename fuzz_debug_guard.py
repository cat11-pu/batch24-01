"""Fuzz verification for debug_guard (1000 random paths, 32 worker threads).

Blocked endpoint variants must always be rejected for public callers,
while ordinary benign paths must always pass.  The blocked set is derived
from the guard's own configured prefixes rather than hard-coded values.
"""

import concurrent.futures
import random

from debug_guard import DEFAULT_BLOCKED_PREFIXES, normalize_path, validate


RANDOM = random.Random(20261119)
SAMPLE_SIZE = 1000
THREADS = 32

BENIGN_WORDS = [
    "home", "orders", "products", "users", "billing", "catalog",
    "search", "health", "status", "api", "v2", "items", "cart",
    "login", "logout", "assets", "static", "images", "report",
]


def _percent_encode(segment, force=False):
    encoded = []
    for char in segment:
        if force or RANDOM.random() < 0.4:
            encoded.append("%" + "%".join(f"{byte:02X}" for byte in char.encode()))
        else:
            encoded.append(char)
    return "".join(encoded)


def _case_flip(segment):
    return "".join(
        char.swapcase() if RANDOM.random() < 0.6 else char for char in segment
    )


def _mutate(path):
    segments = path.split("/")
    segments = [_case_flip(segment) if segment else segment for segment in segments]
    if RANDOM.random() < 0.7:
        index = RANDOM.randrange(1, len(segments))
        segments[index] = _percent_encode(segments[index])
    if RANDOM.random() < 0.35:
        index = RANDOM.randrange(1, len(segments))
        segments[index] = _percent_encode(segments[index], force=True)
    mutated = "/".join(segments)
    if RANDOM.random() < 0.5:
        mutated = mutated.replace("/", "//", RANDOM.randrange(1, 4))
    if RANDOM.random() < 0.4:
        mutated += ";" + RANDOM.choice(["css", "json", "x=1"])
    if RANDOM.random() < 0.3:
        mutated += "/"
    if RANDOM.random() < 0.25:
        mutated = mutated.replace("/", "/./", 1)
    if RANDOM.random() < 0.2:
        mutated = "/".join(["", "debug", "..;"] + mutated.lstrip("/").split("/"))
    if RANDOM.random() < 0.2:
        mutated += "%00"
    return mutated


def _blocked_samples(count):
    samples = []
    suffixes = ("", "/", "/env", "/heapdump", "/info", "/123?x=1")
    for _ in range(count):
        prefix = RANDOM.choice(DEFAULT_BLOCKED_PREFIXES)
        samples.append(_mutate(prefix + RANDOM.choice(suffixes)))
    return samples


def _benign_samples(count):
    samples = []
    while len(samples) < count:
        depth = RANDOM.randint(1, 4)
        path = "/" + "/".join(RANDOM.sample(BENIGN_WORDS, depth))
        if RANDOM.random() < 0.5:
            path += "?" + "q=" + str(RANDOM.randrange(1000))
        normalized = normalize_path(path)
        if validate(normalized) != normalized:
            raise AssertionError("guard is not idempotent")
        samples.append(path)
    return samples


def _check_blocked(path):
    try:
        validate(path)
    except (ValueError, TypeError):
        return True
    return False


def _check_benign(path):
    try:
        return validate(path) == normalize_path(path)
    except (ValueError, TypeError):
        return False


def main():
    blocked_paths = _blocked_samples(600)
    benign_paths = _benign_samples(400)
    all_paths = [(path, True) for path in blocked_paths]
    all_paths += [(path, False) for path in benign_paths]
    RANDOM.shuffle(all_paths)
    assert len(all_paths) == SAMPLE_SIZE

    bypasses, false_positives = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {
            pool.submit(_check_blocked if blocked else _check_benign, path): (path, blocked)
            for path, blocked in all_paths
        }
        for future in concurrent.futures.as_completed(futures):
            path, blocked = futures[future]
            if blocked and not future.result():
                bypasses.append(path)
            if not blocked and not future.result():
                false_positives.append(path)

    print(f"samples={SAMPLE_SIZE} threads={THREADS}")
    print(f"blocked variants rejected: {600 - len(bypasses)}/600")
    print(f"benign paths allowed: {400 - len(false_positives)}/400")
    if bypasses:
        print("BYPASSES:", bypasses[:10])
    if false_positives:
        print("FALSE POSITIVES:", false_positives[:10])
    if bypasses or false_positives:
        raise SystemExit(1)
    print("OK: no debug endpoint bypass under concurrency")


if __name__ == "__main__":
    main()
