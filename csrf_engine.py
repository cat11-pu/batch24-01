import base64
import hashlib
import hmac
import json
import threading

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_STANDARD_METHODS = _SAFE_METHODS | {"POST", "PUT", "DELETE", "PATCH"}

_lock = threading.Lock()
_issued = {}


def _validate_common(session, secret, ttl):
    if not isinstance(session, str) or not session:
        raise ValueError("session must be a non-empty string")
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must be a non-empty string")
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl <= 0:
        raise ValueError("ttl must be a positive number")


def _sign(secret, payload):
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def issue(session, secret, now, ttl=300):
    _validate_common(session, secret, ttl)
    payload = base64.urlsafe_b64encode(
        json.dumps({"s": session, "t": now}, separators=(",", ":")).encode()
    ).decode()
    token = payload + "." + _sign(secret, payload)
    with _lock:
        _issued[session] = token
    return token


def check(token, session, secret, now, method, origin, allowed_origins, ttl=300):
    _validate_common(session, secret, ttl)
    if not isinstance(method, str):
        raise ValueError("method must be a string")
    method = method.upper()
    if method not in _STANDARD_METHODS:
        raise ValueError("unsupported method")
    if method in _SAFE_METHODS:
        return True
    if not isinstance(token, str) or not token:
        raise ValueError("token must be a non-empty string")
    if not isinstance(origin, str) or not origin:
        raise ValueError("origin is required")
    if not origin.startswith("https://"):
        raise ValueError("origin must use https")
    if allowed_origins is None or origin not in allowed_origins:
        raise ValueError("origin not allowed")
    try:
        payload, sig = token.split(".")
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
        token_session = data["s"]
        issued_at = data["t"]
    except Exception:
        raise ValueError("malformed token")
    if not isinstance(token_session, str) or not isinstance(issued_at, (int, float)):
        raise ValueError("malformed token")
    if token_session != session:
        raise ValueError("session mismatch")
    if not hmac.compare_digest(_sign(secret, payload), sig):
        raise ValueError("bad signature")
    if now < issued_at or now - issued_at > ttl:
        raise ValueError("token expired")
    with _lock:
        if _issued.get(session) != token:
            raise ValueError("token reused or rotated")
        del _issued[session]
    return True
