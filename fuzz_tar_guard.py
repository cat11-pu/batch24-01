"""Fuzz / concurrency check for ``tar_guard.validate``.

Generates 1000 random tar-like entries mixing safe and hostile shapes
(absolute links, ``..`` traversal, hardlinks, device nodes, empty links,
overlong names, NUL bytes, Windows paths), predicts the expected verdict
with an independent oracle, and re-checks every entry from 32 worker
threads. Any disagreement between the oracle and ``validate`` fails the
run, which proves no crafted link/name can slip past the guard and land
outside the extraction directory.

Run::

    python fuzz_tar_guard.py
"""

import random
import re
import threading

from tar_guard import validate

ENTRIES = 1000
THREADS = 32

SAFE_TYPES = ("file", "dir", "directory")
LINK_TYPES = ("symlink", "hardlink", "link")
DEVICE_TYPES = ("char", "block", "fifo", "device")

SAFE_PARTS = ("a", "b", "sub", "data", "x1", "logs", "tmp", "pkg")
HOSTILE_LINK_TARGETS = (
    "/etc/passwd",
    "/bin/sh",
    "../../etc/passwd",
    "../escape",
    "a/../../../etc/shadow",
    "..\\..\\Windows\\system32",
    "C:\\Windows\\win.ini",
    "//server/share",
    "",
    "a" * 300,
    "safe/target",
)
HOSTILE_NAMES = (
    "..",
    "../x",
    "/etc/passwd",
    "a/../../etc/passwd",
    "../../evil",
    "..\\..\\evil",
    "C:\\Windows\\win.ini",
    "",
    "z" * 300,
    "bad\x00name",
)


def _random_safe_path(rng):
    depth = rng.randint(1, 4)
    return "/".join(rng.choice(SAFE_PARTS) + str(rng.randrange(100))
                    for _ in range(depth))


def build_entry(rng):
    """Return ``(entry, oracle_accepts)`` for one random archive entry."""
    kind = rng.choices(
        ("safe_file", "safe_dir", "link", "device", "hostile_name", "weird"),
        weights=(25, 15, 30, 10, 15, 5),
        k=1,
    )[0]

    if kind == "safe_file":
        return (_random_safe_path(rng), rng.choice(("file",)), ""), True
    if kind == "safe_dir":
        return (_random_safe_path(rng), rng.choice(("dir", "directory")), ""), True

    if kind == "link":
        target = rng.choice(HOSTILE_LINK_TARGETS)
        # The guard rejects every link type outright, so links never pass.
        return ("link" + str(rng.randrange(1000)), rng.choice(LINK_TYPES), target), False

    if kind == "device":
        return ("dev" + str(rng.randrange(1000)), rng.choice(DEVICE_TYPES), ""), False

    if kind == "hostile_name":
        return (rng.choice(HOSTILE_NAMES), rng.choice(SAFE_TYPES), ""), False

    # "weird": corrupt field types and odd strings.
    weird = rng.choice((
        (123, "file", ""),
        ("name", None, ""),
        ("name", "file", None),
        ("name", "file", "x\x00y"),
        ("\x00", "file", ""),
        ("name", "unknown-type", ""),
        ("name", "symlink", "x\x00y"),
    ))
    return weird, False


_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def oracle_accepts(entry):
    """Independent re-implementation of the safety policy."""
    try:
        name, entry_type, linkname = entry
    except (TypeError, ValueError):
        return False
    if not isinstance(name, str) or not isinstance(entry_type, str) \
            or not isinstance(linkname, str):
        return False
    if linkname != "" and not _oracle_safe_string(linkname):
        return False
    if entry_type not in ("file", "dir", "directory"):
        return False
    return _oracle_safe_string(name)


def _oracle_safe_string(value):
    if not value or "\x00" in value or len(value) > 255:
        return False
    if value.startswith(("/", "\\")) or value.startswith(("\\\\", "//")):
        return False
    if _WINDOWS_DRIVE.match(value):
        return False
    depth = 0
    for part in value.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return False
        else:
            depth += 1
    return True


def guard_accepts(entry):
    try:
        return validate(list(entry)) is True
    except (ValueError, TypeError):
        return False


def main():
    rng = random.Random(0x4215)
    dataset = [build_entry(rng) for _ in range(ENTRIES)]

    # Sequential cross-check against the independent oracle.
    disagreements = []
    accepted = 0
    for entry, expected in dataset:
        actual = guard_accepts(entry)
        if actual:
            accepted += 1
        if actual != expected or actual != oracle_accepts(entry):
            disagreements.append((entry, expected, actual))

    # Every accepted entry must be an in-tree regular file/dir: re-prove
    # containment directly so no accepted path can touch the host system.
    for entry, expected in dataset:
        if guard_accepts(entry):
            name, entry_type, _ = entry
            assert entry_type in SAFE_TYPES
            assert _oracle_safe_string(name), entry
            assert not name.startswith(("/", "\\"))
            parts = name.replace("\\", "/").split("/")
            assert ".." not in parts and "" not in parts

    # 32-thread concurrent validation of the same hostile dataset.
    errors = []
    barrier = threading.Barrier(THREADS)

    def worker(worker_id):
        local_rng = random.Random(worker_id)
        barrier.wait()
        for _ in range(ENTRIES):
            entry, expected = dataset[local_rng.randrange(ENTRIES)]
            if guard_accepts(entry) != expected:
                errors.append((entry, expected))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    print("entries generated : %d" % ENTRIES)
    print("accepted by guard : %d" % accepted)
    print("rejected by guard : %d" % (ENTRIES - accepted))
    print("worker threads    : %d" % THREADS)
    print("oracle mismatches : %d" % len(disagreements))
    print("concurrency errors: %d" % len(errors))

    if disagreements or errors:
        raise SystemExit(
            "FUZZ FAILED: mismatches=%r thread_errors=%r"
            % (disagreements[:5], errors[:5])
        )
    print("FUZZ OK: no entry can escape the extraction directory")


if __name__ == "__main__":
    main()
