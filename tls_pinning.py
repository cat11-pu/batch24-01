import re

_SHA256_HEX_RE = re.compile(r"[0-9a-fA-F]{64}")
_ALLOWED_SIG_ALGS = frozenset({"sha256", "sha384"})


def _is_sha256_hex(value):
    return isinstance(value, str) and _SHA256_HEX_RE.fullmatch(value) is not None


def _hostname_matches(hostname, san_name):
    if not isinstance(san_name, str) or not san_name:
        return False
    host = hostname.lower().rstrip(".")
    name = san_name.lower().rstrip(".")
    if not host or not name:
        return False
    if name.startswith("*."):
        suffix = name[2:]
        if "." not in suffix:
            return False
        if not host.endswith("." + suffix):
            return False
        leftmost = host[: len(host) - len(suffix) - 1]
        return bool(leftmost) and "." not in leftmost
    return host == name


def verify_peer(cert, pins, hostname, now):
    if not isinstance(cert, dict):
        return False
    if not isinstance(pins, (set, frozenset)) or not pins:
        return False
    if not isinstance(hostname, str) or not hostname:
        return False
    if not isinstance(now, int) or isinstance(now, bool):
        return False

    not_before = cert.get("not_before")
    not_after = cert.get("not_after")
    if not isinstance(not_before, int) or isinstance(not_before, bool):
        return False
    if not isinstance(not_after, int) or isinstance(not_after, bool):
        return False
    if now < not_before or now > not_after:
        return False

    sig_alg = cert.get("sig_alg")
    if not isinstance(sig_alg, str) or sig_alg.lower() not in _ALLOWED_SIG_ALGS:
        return False

    san = cert.get("san")
    if not isinstance(san, list) or not san:
        return False
    if not any(_hostname_matches(hostname, name) for name in san):
        return False

    spki = cert.get("spki_sha256")
    if not _is_sha256_hex(spki):
        return False

    normalized_pins = set()
    for pin in pins:
        if not _is_sha256_hex(pin):
            return False
        normalized_pins.add(pin.lower())
    if spki.lower() not in normalized_pins:
        return False

    return True
