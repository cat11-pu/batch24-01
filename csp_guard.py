import base64
import math
import re
import secrets
import threading


_NONCE_BYTES = 32
_MIN_LENGTH = 16
_MAX_LENGTH = 128
_MIN_DISTINCT_CHARACTERS = 8
_MIN_ENTROPY_PER_CHARACTER = 3.0
_BASE64_NONCE = re.compile(r"[A-Za-z0-9+/]+={0,2}")

_STATIC_VALUES = frozenset(
    {
        "changeme",
        "csp",
        "default",
        "dummy",
        "example",
        "false",
        "fixme",
        "nonce",
        "none",
        "null",
        "password",
        "placeholder",
        "script",
        "secret",
        "static",
        "test",
        "todo",
        "true",
        "undefined",
    }
)

_lock = threading.Lock()
_issued_nonces = set()
_used_nonces = set()


def _entropy_per_character(value):
    length = len(value)
    return -sum(
        (value.count(character) / length) * math.log2(value.count(character) / length)
        for character in set(value)
    )


def _is_periodic(value):
    length = len(value)
    for period in range(1, length // 2 + 1):
        if length % period == 0 and value == value[:period] * (length // period):
            return True
    return False


def _validate_format(value):
    if not isinstance(value, str):
        raise TypeError("nonce must be a string")
    if not value:
        raise ValueError("nonce must not be empty")
    if not _MIN_LENGTH <= len(value) <= _MAX_LENGTH:
        raise ValueError("nonce length is outside the allowed range")
    if not _BASE64_NONCE.fullmatch(value):
        raise ValueError("nonce must contain only base64 characters")

    body = value.rstrip("=")
    if body.casefold() in _STATIC_VALUES:
        raise ValueError("nonce must not be a static value")
    if body.isdigit():
        raise ValueError("nonce must not consist only of digits")
    if len(set(body)) < _MIN_DISTINCT_CHARACTERS:
        raise ValueError("nonce does not contain enough distinct characters")
    if _is_periodic(body):
        raise ValueError("nonce must not repeat a fixed pattern")
    if _entropy_per_character(body) < _MIN_ENTROPY_PER_CHARACTER:
        raise ValueError("nonce does not contain enough entropy")


def generate_nonce():
    while True:
        value = base64.b64encode(secrets.token_bytes(_NONCE_BYTES)).decode("ascii")
        with _lock:
            if value not in _issued_nonces and value not in _used_nonces:
                _issued_nonces.add(value)
                return value


def generate():
    return generate_nonce()


def validate(value):
    _validate_format(value)
    with _lock:
        if value in _used_nonces:
            raise ValueError("nonce has already been used")
        _used_nonces.add(value)
    return True
