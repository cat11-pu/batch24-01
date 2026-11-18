import os
import random
import string
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

from symlink_guard import safe_open, validate

RANDOM_CASES = 1000
THREADS = 32


def build_sandbox(root):
    os.makedirs(os.path.join(root, "sub", "deep"))
    good_files = [
        os.path.join(root, "a.txt"),
        os.path.join(root, "sub", "b.log"),
        os.path.join(root, "sub", "deep", "c.dat"),
    ]
    for path in good_files:
        with open(path, "w") as handle:
            handle.write("data")

    secret = os.path.join(root, "secret.txt")
    with open(secret, "w") as handle:
        handle.write("do-not-touch")

    os.symlink("/etc/passwd", os.path.join(root, "link_etc"))
    os.symlink(secret, os.path.join(root, "link_secret"))
    os.symlink("/tmp", os.path.join(root, "link_dir"))
    os.symlink("..", os.path.join(root, "sub", "link_parent"))
    os.symlink(os.path.join("..", "secret.txt"),
               os.path.join(root, "sub", "link_rel_secret"))
    os.mkdir(os.path.join(root, "real_dir"))
    return good_files, secret


def random_good_path(root):
    depth = random.randint(1, 4)
    parts = []
    for _ in range(depth - 1):
        parts.append("".join(random.choices(string.ascii_letters, k=random.randint(1, 8))))
    parts.append("".join(random.choices(string.ascii_lowercase, k=random.randint(1, 10))) + ".tmp")
    relative = os.path.join(*parts)
    absolute = os.path.join(root, relative)
    if random.random() < 0.5:
        os.makedirs(os.path.dirname(absolute), exist_ok=True)
        with open(absolute, "w") as handle:
            handle.write("x")
    return relative


def random_bad_value():
    tokens = [
        "/etc/passwd",
        "/tmp/" + "".join(random.choices(string.ascii_letters, k=6)),
        "../" * random.randint(1, 5) + "etc/passwd",
        "sub/../../" + "".join(random.choices(string.ascii_letters, k=4)),
        "x\x00",
        "name\x00/../etc",
        "",
        " ",
        " x",
        "x ",
        "x\n",
        "x\r",
        "x\t",
        "C:\\windows",
        "\\\\server\\share",
        "x" * random.randint(256, 400),
        "a/" + "b" * 256,
        "link_etc",
        "link_secret",
        "link_dir",
        os.path.join("sub", "link_parent"),
        os.path.join("sub", "link_rel_secret"),
        "real_dir",
        ".",
        "./",
        "sub/./../secret.txt",
    ]
    return random.choice(tokens)


def main():
    random.seed(20261119)
    failures = []
    lock = threading.Lock()

    with tempfile.TemporaryDirectory(prefix="symlink_guard_fuzz_") as root:
        sandbox_dir = os.path.join(root, "sandbox")
        os.makedirs(sandbox_dir)
        outside_dir = os.path.join(root, "outside")
        os.makedirs(outside_dir)
        good_files, secret = build_sandbox(sandbox_dir)
        outside_target = os.path.join(outside_dir, "outside_target.txt")
        with open(outside_target, "w") as handle:
            handle.write("pristine")
        outside_stat_before = os.stat(outside_target)
        passwd_stat_before = os.stat("/etc/passwd")
        escape_hits = []
        rejected_races = 0

        cases = []
        for _ in range(RANDOM_CASES):
            if random.random() < 0.5:
                cases.append(("bad", random_bad_value()))
            else:
                cases.append(("good", random_good_path(sandbox_dir)))

        fixed_bad = [
            ("bad", value) for value in (
                None, "/etc/passwd", "../x", "x\u0000", "", "x\n", "x\r",
                "x ", " x", "x/..", "x/../../etc", "C:\\x", "\\\\server\\x",
                "x" * 300, 123, b"bytes",
            )
        ]
        fixed_good = [("good", os.path.relpath(path, sandbox_dir)) for path in good_files]
        cases.extend(fixed_bad)
        cases.extend(fixed_good)
        random.shuffle(cases)

        def check(case):
            kind, value = case
            try:
                result = validate(value, base_dir=sandbox_dir)
            except (ValueError, TypeError):
                if kind == "good":
                    with lock:
                        failures.append(("good-rejected", repr(value)))
                return
            if kind == "bad":
                with lock:
                    failures.append(("bad-accepted", repr(value), result))
                return
            real = os.path.realpath(result)
            if os.path.commonpath([real, sandbox_dir]) != sandbox_dir:
                with lock:
                    failures.append(("escape", repr(value), result))
            if os.path.lexists(result) and os.path.islink(result):
                with lock:
                    failures.append(("symlink-returned", repr(value)))
            if os.path.lexists(result) and not os.path.isfile(result):
                with lock:
                    failures.append(("non-regular", repr(value)))

        with ThreadPoolExecutor(max_workers=THREADS) as pool:
            list(pool.map(check, cases))

        stop = threading.Event()

        def swap_symlink():
            target = os.path.join(sandbox_dir, "racer")
            while not stop.is_set():
                try:
                    if os.path.lexists(target):
                        os.unlink(target)
                    if random.random() < 0.7:
                        os.symlink(outside_target, target)
                    else:
                        with open(target, "w") as handle:
                            handle.write("plain")
                except FileNotFoundError:
                    pass
                except OSError:
                    pass

        def validate_racer():
            nonlocal rejected_races
            for _ in range(500):
                try:
                    with safe_open("racer", base_dir=sandbox_dir, mode="r+b") as handle:
                        handle.write(b"payload")
                except (ValueError, TypeError):
                    rejected_races += 1
                except OSError:
                    rejected_races += 1

        workers = [threading.Thread(target=swap_symlink)]
        validators = [threading.Thread(target=validate_racer)
                      for _ in range(THREADS - 1)]
        workers += validators
        for worker in workers:
            worker.start()
        for worker in validators:
            worker.join()
        stop.set()
        for worker in workers:
            worker.join(timeout=5)

        with open(secret) as handle:
            assert handle.read() == "do-not-touch"
        with open(outside_target) as handle:
            assert handle.read() == "pristine"
        outside_stat_after = os.stat(outside_target)
        passwd_stat_after = os.stat("/etc/passwd")
        assert (outside_stat_after.st_size, outside_stat_after.st_mtime_ns) == \
            (outside_stat_before.st_size, outside_stat_before.st_mtime_ns)
        assert passwd_stat_after.st_mtime_ns == passwd_stat_before.st_mtime_ns
        if escape_hits:
            failures.extend(escape_hits)
        assert rejected_races > 0, "race test never observed a swapped symlink"

    if failures:
        for failure in failures[:20]:
            print("FAIL:", failure)
        raise SystemExit("fuzz found %d failures" % len(failures))
    print("OK: %d random cases + fixed boundaries under %d threads; "
          "symlink swap race rejected %d times, no escape"
          % (len(cases), THREADS, rejected_races))


if __name__ == "__main__":
    main()
