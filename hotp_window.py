import hashlib
import hmac
import threading

_lock = threading.Lock()


def _hotp(secret, counter, digits):
    digest = hmac.new(secret.encode(), counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def verify(code, secret, counter, used, window=3, digits=6):
    if not isinstance(digits, int) or isinstance(digits, bool) or digits < 1:
        raise ValueError("digits must be a positive integer")
    if not isinstance(code, str) or len(code) != digits or not code.isdigit():
        raise ValueError("code must be a digit string matching digits length")
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must be a non-empty string")
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
        raise ValueError("counter must be a non-negative integer")
    if not isinstance(used, set):
        raise ValueError("used must be a set")
    if not isinstance(window, int) or isinstance(window, bool) or window < 1:
        raise ValueError("window must be a positive integer")

    match = None
    for candidate in range(counter, counter + window):
        if hmac.compare_digest(_hotp(secret, candidate, digits), code):
            match = candidate
            break
    if match is None:
        raise ValueError("code does not match any counter in window")

    with _lock:
        if match in used:
            raise ValueError("counter already used")
        used.add(match)
    return match + 1
