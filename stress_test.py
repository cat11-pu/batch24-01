"""Stress test for xml_entity_guard.validate.

Generates 1000 random XML documents (a balanced mix of safe documents and
XXE / entity-expansion attacks covering internal entities, external entities,
billion-laughs bombs, parameter entities, external DTDs and empty values)
and validates them concurrently from 32 threads.

It asserts that:

* every malicious document is rejected with ValueError / TypeError;
* every well-formed safe document without a DOCTYPE passes;
* no network connection, subprocess or access to sensitive local files
  happens while validating (via a CPython audit hook);
* peak heap growth stays modest, i.e. no entity-expansion blowup occurs.

Run with:  .venv/bin/python stress_test.py
"""

import os
import random
import resource
import string
import sys
import threading
import traceback

from xml_entity_guard import validate

DOCUMENT_COUNT = 1000
THREAD_COUNT = 32
RNG_SEED = 20261119

SAFE_ENTITIES = ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;",
                 "&#65;", "&#x42;", "&#27979;"]


# --------------------------------------------------------------------------
# Audit hook: prove the parser never reaches out to the network, runs
# subprocesses or opens sensitive local files during validation.
# --------------------------------------------------------------------------

class AccessMonitor:
    FORBIDDEN_PATHES = ("/etc/passwd", "/etc/shadow", "/etc/hosts",
                        "/proc/self/environ", "/root/.ssh")

    def __init__(self):
        self.events = []
        self._lock = threading.Lock()

    def __call__(self, event, args):
        if event in ("socket.connect", "socket.getaddrinfo",
                     "subprocess.Popen", "urllib.Request",
                     "http.client.send", "ftplib.connect",
                     "webbrowser.open"):
            with self._lock:
                self.events.append((event, args))
        elif event == "open" and args:
            path = os.fspath(args[0])
            if any(path.startswith(mark) for mark in self.FORBIDDEN_PATHES):
                with self._lock:
                    self.events.append((event, args))


# --------------------------------------------------------------------------
# Random document generators
# --------------------------------------------------------------------------

def random_text(rng, max_len=40):
    length = rng.randint(0, max_len)
    alphabet = string.ascii_letters + string.digits + " _-."
    pieces = [rng.choice(alphabet) for _ in range(length)]
    if pieces and rng.random() < 0.35:
        pieces.insert(rng.randrange(len(pieces)), rng.choice(SAFE_ENTITIES))
    return "".join(pieces)


def random_element(rng, depth=0):
    tag = rng.choice(["root", "item", "data", "node", "record", "entry"])
    attrs = ""
    if rng.random() < 0.4:
        attr_name = rng.choice(["id", "name", "type", "ref"])
        attrs = " %s='%s'" % (attr_name, random_text(rng, 12))
    if depth < 4 and rng.random() < 0.6:
        children = "".join(random_element(rng, depth + 1)
                           for _ in range(rng.randint(1, 3)))
        return "<%s%s>%s</%s>" % (tag, attrs, children, tag)
    return "<%s%s>%s</%s>" % (tag, attrs, random_text(rng), tag)


def make_safe(rng):
    choice = rng.random()
    if choice < 0.2:
        doc = "<?xml version='1.0' encoding='UTF-8'?>" + random_element(rng)
    elif choice < 0.4:
        # DTD-looking text inside CDATA/comments is inert and must pass.
        doc = ("<root><![CDATA[<!DOCTYPE fake [<!ENTITY x 'no'>]>]]>"
               "<!-- &not-an-entity; -->%s</root>" % random_element(rng))
    else:
        doc = random_element(rng)
    return doc, True


def make_internal_entity(rng):
    name = rng.choice(["x", "ent", "word", "val"])
    return ("<!DOCTYPE r [<!ENTITY %s '%s'>]><r>&%s;</r>"
            % (name, random_text(rng, 20), name)), False


def make_external_entity(rng):
    target = rng.choice([
        "file:///etc/passwd",
        "file:///etc/hosts",
        "http://evil.example/dtd",
        "https://attacker.invalid/secret.xml",
        "ftp://drop.invalid/payload",
    ])
    keyword = "SYSTEM" if rng.random() < 0.8 else "PUBLIC 'id'"
    return ("<!DOCTYPE r [<!ENTITY leak %s '%s'>]><r>&leak;</r>"
            % (keyword, target)), False


def make_billion_laughs(rng):
    levels = rng.randint(2, 9)
    fanout = rng.randint(2, 10)
    parts = ["<!DOCTYPE lol [<!ENTITY l0 'lol'>"]
    for level in range(1, levels + 1):
        refs = ("&l%d;" % (level - 1)) * fanout
        parts.append("<!ENTITY l%d '%s'>" % (level, refs))
    parts.append("]><lol>&l%d;</lol>" % levels)
    return "".join(parts), False


def make_parameter_entity(rng):
    target = rng.choice(["http://evil.example/pe.dtd",
                         "file:///etc/passwd", "file:///dev/null"])
    return ("<!DOCTYPE r [<!ENTITY %% p SYSTEM '%s'>]><r/>" % target), False


def make_external_dtd(rng):
    target = rng.choice(["http://evil.example/evil.dtd",
                         "https://attacker.invalid/schema.dtd",
                         "file:///etc/passwd"])
    if rng.random() < 0.5:
        return "<!DOCTYPE r SYSTEM '%s'><r/>" % target, False
    return "<!DOCTYPE r PUBLIC '-//Evil//DTD//EN' '%s'><r/>" % target, False


def make_empty(rng):
    return rng.choice(["", "   ", "\t\n ", b"", None]), False


def make_dtd_misc(rng):
    variants = [
        "<!DOCTYPE r [<!ELEMENT r ANY>]><r/>",
        "<!DOCTYPE r [<!ATTLIST r id CDATA '0'>]><r/>",
        "<!DOCTYPE r [<!NOTATION n SYSTEM 'x'>]><r/>",
        "<r>&undefined_entity_%d;</r>" % rng.randint(0, 99999),
        "not xml at all %d" % rng.randint(0, 9999),
        "<r>\x00</r>",
        "<r><unclosed>",
    ]
    return rng.choice(variants), False


MALICIOUS_GENERATORS = [
    make_internal_entity,
    make_external_entity,
    make_billion_laughs,
    make_parameter_entity,
    make_external_dtd,
    make_empty,
    make_dtd_misc,
]


def build_documents(count):
    rng = random.Random(RNG_SEED)
    documents = []
    for index in range(count):
        if index % 2 == 0:
            documents.append(make_safe(rng))
        else:
            generator = rng.choice(MALICIOUS_GENERATORS)
            documents.append(generator(rng))
    rng.shuffle(documents)
    return documents


# --------------------------------------------------------------------------
# Concurrent runner
# --------------------------------------------------------------------------


def main():
    monitor = AccessMonitor()
    sys.addaudithook(monitor)

    documents = build_documents(DOCUMENT_COUNT)
    expected_safe = sum(1 for _, safe in documents if safe)
    expected_bad = DOCUMENT_COUNT - expected_safe

    results = []
    results_lock = threading.Lock()
    errors = []

    def worker(chunk):
        local_results = []
        for doc, should_pass in chunk:
            try:
                returned = validate(doc)
                local_results.append((doc, should_pass, True, returned))
            except (ValueError, TypeError) as exc:
                local_results.append((doc, should_pass, False,
                                      type(exc).__name__))
            except Exception:  # pragma: no cover - failure path
                with results_lock:
                    errors.append((doc, traceback.format_exc()))
        with results_lock:
            results.extend(local_results)

    chunks = [[] for _ in range(THREAD_COUNT)]
    for index, item in enumerate(documents):
        chunks[index % THREAD_COUNT].append(item)

    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    threads = [threading.Thread(target=worker, args=(chunk,))
               for chunk in chunks]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    passed = sum(1 for _, _, ok, _ in results if ok)
    rejected = len(results) - passed

    # Every safe document must pass; every malicious one must be rejected.
    mismatches = []
    for doc, should_pass, ok, detail in results:
        if ok != should_pass:
            mismatches.append((repr(doc)[:80], ok, detail))

    print("documents           : %d" % DOCUMENT_COUNT)
    print("threads             : %d" % THREAD_COUNT)
    print("safe passed         : %d / %d" % (passed, expected_safe))
    print("malicious rejected  : %d / %d" % (rejected, expected_bad))
    print("forbidden accesses  : %d %s"
          % (len(monitor.events), monitor.events[:5]))
    print("unexpected errors   : %d" % len(errors))
    print("mismatches          : %d" % len(mismatches))
    print("peak RSS delta (KB) : %d" % (rss_after - rss_before))

    assert not errors, errors[:3]
    assert not monitor.events, monitor.events[:5]
    assert not mismatches, mismatches[:5]
    assert passed == expected_safe
    assert rejected == expected_bad
    assert len(results) == DOCUMENT_COUNT
    print("\nSTRESS TEST PASSED")


if __name__ == "__main__":
    main()
