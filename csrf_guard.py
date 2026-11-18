import hmac
import math
import secrets
import threading
import time
from typing import NamedTuple


DEFAULT_TTL = 3600
ALLOWED_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class _TokenRecord(NamedTuple):
    session_id: str
    expires_at: float
    ttl: float


TOKENS = {}
_TOKENS_LOCK = threading.RLock()


def _validate_session_id(session_id):
    if not isinstance(session_id, str):
        raise TypeError("session_id must be a string")
    if not session_id:
        raise ValueError("session_id must not be empty")


def _validate_ttl(ttl):
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
        raise TypeError("ttl must be a number")
    if not math.isfinite(ttl) or ttl <= 0:
        raise ValueError("ttl must be a positive finite number")
    return float(ttl)


def _validate_method(method):
    if not isinstance(method, str):
        raise ValueError("request method is not allowed")
    normalized = method.upper()
    if normalized not in ALLOWED_METHODS:
        raise ValueError("request method is not allowed")
    return normalized


def _new_token_locked(excluded_token=None):
    token = secrets.token_urlsafe(32)
    while token == excluded_token or token in TOKENS:
        token = secrets.token_urlsafe(32)
    return token


def issue_csrf_token(session_id, ttl=DEFAULT_TTL):
    _validate_session_id(session_id)
    ttl = _validate_ttl(ttl)
    expires_at = time.time() + ttl
    with _TOKENS_LOCK:
        token = _new_token_locked()
        TOKENS[token] = _TokenRecord(session_id, expires_at, ttl)
    return token


def validate_csrf_token(session_id, token, method="POST"):
    _validate_method(method)
    _validate_session_id(session_id)
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    if not token:
        raise ValueError("token must not be empty")

    with _TOKENS_LOCK:
        record = TOKENS.get(token)
        if record is None:
            raise ValueError("invalid or already used CSRF token")
        if not hmac.compare_digest(
            record.session_id.encode("utf-8"), session_id.encode("utf-8")
        ):
            raise ValueError("CSRF token is not bound to this session")
        if time.time() >= record.expires_at:
            del TOKENS[token]
            raise ValueError("expired CSRF token")
        del TOKENS[token]

    return True


def rotate_csrf_token(session_id, old_token):
    _validate_session_id(session_id)
    if not isinstance(old_token, str):
        raise TypeError("token must be a string")
    if not old_token:
        raise ValueError("token must not be empty")

    with _TOKENS_LOCK:
        record = TOKENS.get(old_token)
        if record is None:
            raise ValueError("invalid or already used CSRF token")
        if not hmac.compare_digest(
            record.session_id.encode("utf-8"), session_id.encode("utf-8")
        ):
            raise ValueError("CSRF token is not bound to this session")
        now = time.time()
        if now >= record.expires_at:
            del TOKENS[old_token]
            raise ValueError("expired CSRF token")

        del TOKENS[old_token]
        new_token = _new_token_locked(excluded_token=old_token)
        TOKENS[new_token] = _TokenRecord(session_id, now + record.ttl, record.ttl)

    return new_token
