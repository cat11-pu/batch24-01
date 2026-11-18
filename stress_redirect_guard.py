import random
import string
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from oauth_redirect_guard import validate

REGISTERED = "https://app.example.com/cb"
THREADS = 32
SAMPLES = 1000


def random_uri(rng):
    host = "app.example.com"
    mutations = [
        lambda: "https://" + host + ".evil.com/cb",
        lambda: "https://evil" + host + "/cb",
        lambda: "https://" + host.upper() + "/cb",
        lambda: "https://" + host + "./cb",
        lambda: "https://user:pw@" + host + "/cb",
        lambda: "https://user@" + host + "/cb",
        lambda: "https://" + host + ":8443/cb",
        lambda: "https://" + host + ":443/cb",
        lambda: "http://" + host + "/cb",
        lambda: "https://" + host + "/cb/extra",
        lambda: "https://" + host + "/cb#frag",
        lambda: "https://" + host + "/cb?x=1",
        lambda: "https://" + host + "/%2e%2e/cb",
        lambda: "https://" + host + "/cb%00",
        lambda: "https://" + host + "/%63b",
        lambda: "https://" + host + "/cb\n",
        lambda: "https://" + host + "/cb\\evil",
        lambda: "https://" + host + "/cb/..;/evil",
        lambda: "",
        lambda: "https://" + host,
        lambda: "https://" + host + "/",
        lambda: "https://" + host + "/cb/",
        lambda: "https://" + host + "//cb",
        lambda: "https://" + host + "/cb..",
        lambda: "javascript:alert(1)",
        lambda: "https://" + host + ".cb",
        lambda: "".join(rng.choice(string.printable) for _ in range(rng.randint(0, 40))),
        lambda: "https://" + host + "/" + "".join(rng.choice(string.ascii_letters) for _ in range(rng.randint(0, 12))),
        lambda: REGISTERED,
    ]
    return rng.choice(mutations)()


def check(uri):
    try:
        validate(uri)
    except (ValueError, TypeError):
        return uri, False
    return uri, True


def main():
    rng = random.Random(20261119)
    uris = [random_uri(rng) for _ in range(SAMPLES)]
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        results = list(pool.map(check, uris))
    accepted = [uri for uri, ok in results if ok]
    unexpected = []
    for uri in accepted:
        parts = urlsplit(uri)
        normalized = "https://" + (parts.hostname or "").lower() + parts.path
        if parts.query:
            normalized += "?" + parts.query
        if normalized != REGISTERED:
            unexpected.append(uri)
    assert not unexpected, "diverted URIs accepted: %r" % unexpected
    assert accepted, "registered URI must be accepted"
    rejected = SAMPLES - len(accepted)
    print("OK: %d/%d rejected, %d accepted (all == registered URI), %d threads"
          % (rejected, SAMPLES, len(accepted), THREADS))


if __name__ == "__main__":
    main()
