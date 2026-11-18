"""Fuzz + concurrency check for unicode_guard.validate.

Generates adversarial traversal paths built from Unicode confusables,
invisible/bidi controls and percent/double encoding, then runs validate()
from 32 threads. Every adversarial case must raise, benign cases must pass.
"""

import concurrent.futures
import random
import sys
import threading

sys.path.insert(0, "/home/cat/gsb/uid4194")
from unicode_guard import validate  # noqa: E402

rng = random.Random(20261119)

# Boundary codepoints required by the task, plus extra NFKC/confusable cases.
CONFUSABLES = [
    "\uff0f",  # fullwidth solidus
    "\u2215",  # division slash
    "\u2044",  # fraction slash
    "\u29f8",  # big solidus
    "\uff3c",  # fullwidth reverse solidus
    "\u2216",  # set minus (backslash lookalike)
    "\u2024",  # one dot leader
    "\u2025",  # two dot leader
    "\u2026",  # horizontal ellipsis
    "\u2043",  # hyphen bullet (NFKC -> '-')
]
INVISIBLE = [
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\ufeff",  # zero width no-break space
    "\u202e",  # right-to-left override (bidi)
    "\u2066",  # left-to-right isolate (bidi)
    "\u2067",  # right-to-left isolate (bidi)
    "\u202a",  # left-to-right embedding (bidi)
]
ASCII_SLASHES = ["/", "\\"]
DOTS = [".", "\u2024"]
SUFFIXES = ["etc/passwd", "etc\\passwd", "home/user/.ssh/id_rsa", "dir/file.txt"]


def pct_encoded(char):
    return "".join("%%%02x" % byte for byte in char.encode("utf-8"))


def make_adversarial():
    slash = rng.choice(ASCII_SLASHES + CONFUSABLES)
    dot = rng.choice(DOTS)
    prefix_parts = [dot, dot]
    if rng.random() < 0.5:
        prefix_parts.insert(rng.randrange(3), rng.choice(INVISIBLE))
    prefix = "".join(prefix_parts)
    body = prefix + slash + rng.choice(SUFFIXES)
    if rng.random() < 0.4:
        body = rng.choice(INVISIBLE) + body

    mode = rng.choice(
        ["raw", "raw", "pct_some", "pct_all", "double", "overlong_c0af", "overlong_e080af"]
    )
    if mode == "raw":
        return body
    if mode == "pct_some":
        return "".join(
            pct_encoded(ch) if (ord(ch) > 127 and rng.random() < 0.7) else ch for ch in body
        )
    if mode == "pct_all":
        return "".join(pct_encoded(ch) if ord(ch) > 127 else ch for ch in body)
    if mode == "double":
        once = "".join(pct_encoded(ch) if ord(ch) > 127 else ch for ch in body)
        return once.replace("%", "%25")
    if mode == "overlong_c0af":
        return body.replace(slash, "%c0%af", 1)
    return body.replace(slash, "%e0%80%af", 1)


BENIGN = [
    "etc/conf.d/app.cfg",
    "home/user/notes 2026.txt",
    "projects/repo-1/src/main.py",
    ".bashrc",
    "a/b/c/normal-path_name.dat",
    "100%25-done.txt",
    "report (final).pdf",
]


def is_rejected(value):
    try:
        validate(value)
    except (ValueError, TypeError):
        return True
    return False


def main():
    adversarial = [make_adversarial() for _ in range(1000)]
    required_codepoints = [
        "\uff0f", "\u2215", "\u2044", "\u29f8", "\u200b", "\u202e", "\u2066",
    ]
    for codepoint in required_codepoints:
        adversarial.append(".." + codepoint + "etc/passwd")
    adversarial.extend(
        [
            "%ef%bc%8f..%ef%bc%8fetc",
            "..%c0%afetc/passwd",
            "..%e0%80%afetc/passwd",
            "%252f%252e%252e",
        ]
    )

    errors = []
    lock = threading.Lock()

    def worker(sample):
        if not is_rejected(sample):
            with lock:
                errors.append(("BYPASS", repr(sample)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(worker, adversarial))

    benign_failures = [value for value in BENIGN if is_rejected(value)]
    if benign_failures:
        errors.append(("FALSE_POSITIVE", list(map(repr, benign_failures))))

    repeated = adversarial * 32
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(is_rejected, repeated))
    if not all(results):
        errors.append(("NONDETERMINISTIC", "concurrent results differed"))

    print("adversarial samples:", len(adversarial))
    print("concurrent validations:", len(repeated), "across 32 threads")
    print("benign samples accepted:", len(BENIGN) - len(benign_failures), "/", len(BENIGN))
    if errors:
        for kind, detail in errors:
            print("FAIL", kind, detail)
        sys.exit(1)
    print("OK: every adversarial path rejected, no bypass, benign paths accepted")


if __name__ == "__main__":
    main()
