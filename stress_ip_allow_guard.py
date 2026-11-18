"""Independent stress harness for ip_allow_guard.validate.

Builds its own parsing/membership oracle without importing ipaddress or any
helper from ip_allow_guard, then cross-checks the guard over 1000 random IPs
plus fixed bypass boundary cases under 32 worker threads.

Run:
    IP_ALLOW_LIST=10.0.0.0/8,192.168.1.0/24 \
        /tmp/tgvenv2/bin/python stress_ip_allow_guard.py
"""

import os
import random
import re
import sys
import threading

os.environ.setdefault("IP_ALLOW_LIST", "10.0.0.0/8,192.168.1.0/24")

from ip_allow_guard import validate

THREADS = 32
RANDOM_CASES = 1000

CANONICAL_OCTET = re.compile(r"\A(?:0|[1-9][0-9]{0,2})\Z")


def oracle_parse_canonical(value):
    """Return the 32-bit integer of a strictly canonical IPv4 string."""
    if not isinstance(value, str) or not value:
        return None
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value):
        return None
    parts = value.split(".")
    if len(parts) != 4:
        return None
    number = 0
    for part in parts:
        if not CANONICAL_OCTET.fullmatch(part):
            return None
        octet = int(part)
        if octet > 255:
            return None
        number = (number << 8) | octet
    return number


def oracle_networks(raw):
    networks = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        base_text, _, prefix_text = entry.partition("/")
        base = oracle_parse_canonical(base_text)
        if base is None or not prefix_text.isdigit():
            raise ValueError("bad test allowlist entry: " + entry)
        prefix = int(prefix_text)
        if not 0 <= prefix <= 32:
            raise ValueError("bad prefix length: " + entry)
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
        networks.append((base & mask, mask, prefix))
    if not networks:
        raise ValueError("allowlist must contain at least one network")
    return networks


def oracle_allows(value, networks):
    number = oracle_parse_canonical(value)
    if number is None:
        return False
    return any((number & mask) == base for base, mask, _ in networks)


def dotted(number):
    return ".".join(str((number >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def decimal_integer(ip):
    return str(sum(int(part) << (8 * (3 - index))
                   for index, part in enumerate(ip.split("."))))


def hex_integer(ip):
    return "0x" + format(
        sum(int(part) << (8 * (3 - index))
            for index, part in enumerate(ip.split("."))), "x")


def build_cases(networks, seed):
    rng = random.Random(seed)
    cases = []

    forced_bad = [
        "10.0.0.01", "10.0.0.001",
        "010.000.000.001", "010.0.0.1", "10.0.0", "10.0.0.1.2",
        "167772161", "2130706433", "0", "0x0a000001", "0x0A.0.0.1",
        "0177.0.0.1", "::ffff:10.0.0.1", "::ffff:a00:1", "::1", "2001:db8::1",
        "10.0.0.1:80", "10.0.0.1:65535", "10.0.0.1/", "10.0.0.1/8",
        "10.0.0.1\n", "10.0.0.1\r", "10.0.0.1\t", "10.0.0.1 ", " 10.0.0.1",
        "10.0.0.1\u0000", "10.0.0.1\u007f", "10.0.0.1\u200b", "10.0.0.1\u00a0",
        "10.0.0.1,10.0.0.2", "999.0.0.1", "256.0.0.1", "10.256.0.1",
        "10．0．0．1", "10.0.0.1a", "abc", "",
        10000001, None, b"10.0.0.1", 0x0A000001, True, ("10.0.0.1",),
    ]
    for value in forced_bad:
        cases.append((value, False))

    edge_canonical = [
        "9.255.255.255", "11.0.0.0", "10.0.0.0", "10.255.255.255",
        "192.168.0.255", "192.168.1.0", "192.168.1.255", "192.168.2.0",
        "0.0.0.0", "255.255.255.255",
    ]
    for value in edge_canonical:
        cases.append((value, None))

    for last_octet in range(4):
        ip = "10.0.0.%d" % last_octet
        for variant in (
            "0" + ip,
            ip + ":443",
            ip + "/32",
            " " + ip,
            ip + " ",
            ip + "\n",
            ip + "\x00",
            ip.replace(".", "．"),
            decimal_integer(ip),
            hex_integer(ip),
        ):
            cases.append((variant, False))

    for _ in range(RANDOM_CASES):
        cases.append((dotted(rng.randrange(1 << 32)), None))

    for _ in range(200):
        base, _, prefix = rng.choice(networks)
        host = rng.randrange(1 << (32 - prefix))
        cases.append((dotted(base | host), None))

    mutators = (
        lambda s: "0" + s,
        lambda s: s + ":80",
        lambda s: s + "/24",
        lambda s: " " + s,
        lambda s: s + " ",
        lambda s: s + "\t",
        lambda s: s.replace(".0.", ".00."),
        decimal_integer,
        hex_integer,
    )
    for _ in range(200):
        ip = dotted(rng.randrange(1 << 32))
        cases.append((rng.choice(mutators)(ip), False))

    return cases


def prefix_confusion_check():
    """The original bug: string-prefix match let 10.0.0.10 pass a /32 rule.

    Re-run the guard with narrow host/network allowlists and compare against
    the same independent oracle.
    """
    scenarios = (
        "10.0.0.1/32",
        "10.0.0.0/30",
        "192.168.1.7/32",
    )
    probes = [
        "10.0.0.1", "10.0.0.2", "10.0.0.10", "10.0.0.100", "10.0.0.123",
        "10.0.0.0", "10.0.0.3", "10.0.0.4", "192.168.1.7", "192.168.1.17",
        "192.168.1.70",
    ]
    failures = []
    saved = os.environ["IP_ALLOW_LIST"]
    try:
        for raw in scenarios:
            os.environ["IP_ALLOW_LIST"] = raw
            networks = oracle_networks(raw)
            for value in probes:
                try:
                    result = validate(value) is True
                except (ValueError, TypeError):
                    result = False
                expected = oracle_allows(value, networks)
                if result != expected:
                    failures.append(
                        (raw, value, "got %s expected %s" % (result, expected)))
    finally:
        os.environ["IP_ALLOW_LIST"] = saved
    return failures


def main():
    raw = os.environ["IP_ALLOW_LIST"]
    confusion_failures = prefix_confusion_check()
    networks = oracle_networks(raw)
    seed = int(os.environ.get("STRESS_SEED", "20261119"))
    cases = build_cases(networks, seed=seed)
    expected = [
        oracle_allows(value, networks) if want is None else want
        for value, want in cases
    ]

    failures = []
    lock = threading.Lock()

    def worker(chunk):
        local_failures = []
        for index in chunk:
            value, _ = cases[index]
            try:
                result = validate(value) is True
            except (ValueError, TypeError):
                result = False
            except Exception as exc:
                local_failures.append(
                    (value, "unexpected %s: %r" % (type(exc).__name__, exc)))
                continue
            if result != expected[index]:
                local_failures.append(
                    (value, "got %s expected %s" % (result, expected[index])))
        if local_failures:
            with lock:
                failures.extend(local_failures)

    all_indexes = list(range(len(cases)))
    chunks = [all_indexes[i::THREADS] for i in range(THREADS)]
    threads = [threading.Thread(target=worker, args=(chunk,)) for chunk in chunks]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    bypasses = [item for item in failures if item[1].startswith("got True")]
    confusion_bypasses = [
        item for item in confusion_failures if item[2].startswith("got True")]
    print("cases=%d threads=%d random=%d allowlist=%s"
          % (len(cases), THREADS, RANDOM_CASES, raw))
    if confusion_failures:
        print("FAIL prefix-confusion scenario: %d mismatch(es), %d bypass(es)"
              % (len(confusion_failures), len(confusion_bypasses)))
        for rule, value, reason in confusion_failures[:20]:
            print("  rule=%s %r -> %s" % (rule, value, reason))
    if failures or confusion_failures:
        print("FAIL %d mismatch(es), %d bypass(es)" % (len(failures), len(bypasses)))
        for value, reason in failures[:20]:
            print("  %r -> %s" % (value, reason))
        sys.exit(1)
    print("PASS: no bypass, every decision matches the independent oracle")


if __name__ == "__main__":
    main()
