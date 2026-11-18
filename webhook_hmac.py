import hashlib
import hmac
import re
import threading


_HEX64_RE = re.compile(r"[0-9a-fA-F]{64}")
_SIGNATURE_PREFIX = "sha256="

_cache_lock = threading.Lock()


def verify(headers, body, secret, now, cache, window=300):
    if not isinstance(headers, dict):
        raise ValueError("headers must be a dict")
    if not isinstance(body, bytes):
        raise ValueError("body must be raw bytes")
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must be a non-empty string")
    if not isinstance(cache, dict):
        raise ValueError("cache must be a dict")

    signature = headers.get("x-signature")
    timestamp = headers.get("x-timestamp")
    if not isinstance(signature, str) or not isinstance(timestamp, str):
        return False

    if not signature.startswith(_SIGNATURE_PREFIX):
        return False
    provided_digest = signature[len(_SIGNATURE_PREFIX):]
    if _HEX64_RE.fullmatch(provided_digest) is None:
        return False

    try:
        timestamp_value = int(timestamp)
    except ValueError:
        return False

    if abs(now - timestamp_value) > window:
        return False

    expected_digest = hmac.new(
        secret.encode(),
        timestamp.encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_digest, provided_digest):
        return False

    with _cache_lock:
        if signature in cache:
            return False
        cache[signature] = True

    return True
