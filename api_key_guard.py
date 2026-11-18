import hashlib
import hmac
import secrets
import threading
import time

KEYS = {}
_LOCK = threading.RLock()


def _digest(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def issue_api_key(user, scopes=None, ttl=3600):
    if not isinstance(user, str):
        raise TypeError("user must be a string")
    if not user:
        raise ValueError("user must be a non-empty string")
    if not isinstance(ttl, (int, float)) or ttl <= 0:
        raise ValueError("ttl must be a positive number of seconds")
    key = "ak_" + secrets.token_urlsafe(32)
    record = {
        "user": user,
        "scopes": list(scopes or []),
        "expires_at": time.time() + ttl,
        "revoked": False,
    }
    with _LOCK:
        KEYS[_digest(key)] = record
    return key


def validate_api_key(key, user=None, scope=None):
    if not isinstance(key, str) or not key:
        raise ValueError("invalid api key")
    with _LOCK:
        record = KEYS.get(_digest(key))
        if record is None or record["revoked"]:
            raise ValueError("api key is invalid or revoked")
        if record["expires_at"] <= time.time():
            raise ValueError("api key has expired")
        if user is not None:
            if not isinstance(user, str) or not hmac.compare_digest(record["user"], user):
                raise ValueError("api key is not bound to this user")
        if scope is not None and scope not in record["scopes"]:
            raise ValueError("api key lacks the required scope")
    return True


def revoke_api_key(key):
    if not isinstance(key, str) or not key:
        return False
    with _LOCK:
        record = KEYS.get(_digest(key))
        if record is None:
            return False
        record["revoked"] = True
    return True


def revoke_user_keys(user):
    if not isinstance(user, str) or not user:
        return 0
    count = 0
    with _LOCK:
        for record in KEYS.values():
            if record["user"] == user and not record["revoked"]:
                record["revoked"] = True
                count += 1
    return count


def rotate_api_key(key):
    if not isinstance(key, str) or not key:
        raise ValueError("invalid api key")
    with _LOCK:
        record = KEYS.get(_digest(key))
        if record is None or record["revoked"]:
            raise ValueError("api key is invalid or revoked")
        if record["expires_at"] <= time.time():
            raise ValueError("api key has expired")
        user = record["user"]
        scopes = list(record["scopes"])
        record["revoked"] = True
    return issue_api_key(user, scopes=scopes)
