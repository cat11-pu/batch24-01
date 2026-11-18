"""Concurrent fuzz check for xmlsig_guard.validate.

Generates 1000 random XML documents (valid-shaped plus attack mutations
covering duplicate IDs, wrapper layers, empty references, detached
signatures and entity injection) and validates them from 32 threads.
Any attack mutation that validates, or any unexpected exception type,
fails the run.
"""

import random
import string
from concurrent.futures import ThreadPoolExecutor

from xmlsig_guard import validate

SAMPLES = 1000
THREADS = 32


def rand_id(rng):
    return "".join(rng.choices(string.ascii_lowercase, k=rng.randint(1, 8)))


def valid_doc(rng):
    doc_id = rand_id(rng)
    body = "".join(f"<x{i}/>" for i in range(rng.randint(0, 3)))
    return f"<root ID='{doc_id}'><Signature Reference='#{doc_id}'/>{body}</root>", True


def attack_doc(rng):
    doc_id = rand_id(rng)
    other = rand_id(rng)
    while other == doc_id:
        other = rand_id(rng)
    attacks = [
        # duplicate ID on sibling elements
        f"<root><Signature Reference='#{doc_id}'/><a ID='{doc_id}'/><b ID='{doc_id}'/></root>",
        # duplicate ID via Object inside Signature
        f"<root ID='{doc_id}'><Signature Reference='#{doc_id}'><Object ID='{doc_id}'/></Signature></root>",
        # duplicate ID attribute on one element
        f"<root ID='{doc_id}' ID='{other}'><Signature Reference='#{doc_id}'/></root>",
        # wrapper layer around the signed root
        f"<wrapper><root ID='{doc_id}'><Signature Reference='#{doc_id}'/></root></wrapper>",
        # reference points at a wrapped child instead of the root
        f"<root><Signature Reference='#{doc_id}'/><a ID='{doc_id}'><x/></a></root>",
        # empty / missing / dangling references
        f"<root ID='{doc_id}'><Signature Reference=''/></root>",
        f"<root ID='{doc_id}'><Signature/></root>",
        f"<root ID='{doc_id}'><Signature Reference='#{other}'/></root>",
        f"<root ID='{doc_id}'><Signature Reference='#'/></root>",
        # detached / extra signatures
        f"<root ID='{doc_id}'><Signature Reference='#{doc_id}'/><Signature/></root>",
        f"<root><Signature Reference='#{doc_id}'/><a ID='{doc_id}'><Signature/></a></root>",
        f"<root ID='{doc_id}'><a><Signature Reference='#{doc_id}'/></a></root>",
        # entity / DTD injection
        "<!DOCTYPE root [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><root>&x;</root>",
        f"<!DOCTYPE root [<!ENTITY x 'boom'>]><root ID='{doc_id}'><Signature Reference='#{doc_id}'/>&x;</root>",
        # garbage
        "",
        "not xml",
        f"<root ID='{doc_id}'><Signature Reference='#{doc_id}'/>",
    ]
    return rng.choice(attacks), False


def check(sample):
    doc, should_pass = sample
    try:
        result = validate(doc)
    except (ValueError, TypeError):
        return not should_pass
    except Exception:
        return False
    return should_pass and result is True


def main():
    rng = random.Random(20261119)
    samples = []
    for _ in range(SAMPLES):
        samples.append(valid_doc(rng) if rng.random() < 0.5 else attack_doc(rng))
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        results = list(pool.map(check, samples))
    failed = results.count(False)
    print(f"{len(results)} samples, {THREADS} threads, {failed} failures")
    if failed:
        for doc, should_pass in [s for s, ok in zip(samples, results) if not ok][:10]:
            print(f"FAIL expect_pass={should_pass}: {doc!r}")
        raise SystemExit(1)
    print("OK: no signature bypass, no unexpected exceptions")


if __name__ == "__main__":
    main()
