import secrets
import threading
import time

SESSIONS = {}
_LOCK = threading.RLock()

_TOKEN_BYTES = 32


def _check_user(user):
    if not isinstance(user, str):
        raise TypeError("user must be a string")
    if not user:
        raise ValueError("user must not be empty")


def _check_ttl(ttl):
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
        raise TypeError("ttl must be a number")
    if ttl <= 0:
        raise ValueError("ttl must be positive")


def _sweep_expired(now):
    expired = [t for t, r in SESSIONS.items() if now >= r["expires_at"]]
    for t in expired:
        SESSIONS.pop(t, None)


def issue_token(user, ttl=300):
    _check_user(user)
    _check_ttl(ttl)
    now = time.time()
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    with _LOCK:
        _sweep_expired(now)
        while token in SESSIONS:
            token = secrets.token_urlsafe(_TOKEN_BYTES)
        SESSIONS[token] = {"user": user, "expires_at": now + ttl}
    return token


def validate(token, user=None):
    if not isinstance(token, str) or not token:
        return False
    now = time.time()
    with _LOCK:
        record = SESSIONS.get(token)
        if record is None:
            return False
        if now >= record["expires_at"]:
            SESSIONS.pop(token, None)
            return False
        if user is not None and record["user"] != user:
            return False
        SESSIONS.pop(token, None)
    return True


def _revoke_all_for_user(user):
    with _LOCK:
        doomed = [t for t, r in SESSIONS.items() if r["user"] == user]
        for t in doomed:
            SESSIONS.pop(t, None)
    return len(doomed)


def revoke(token):
    if not isinstance(token, str):
        return False
    with _LOCK:
        return SESSIONS.pop(token, None) is not None


def logout(user):
    if not isinstance(user, str) or not user:
        return 0
    return _revoke_all_for_user(user)


def rotate(token):
    if not isinstance(token, str) or not token:
        return None
    now = time.time()
    with _LOCK:
        record = SESSIONS.pop(token, None)
    if record is None or now >= record["expires_at"]:
        return None
    return issue_token(record["user"])


def change_password(user):
    if not isinstance(user, str) or not user:
        return 0
    return _revoke_all_for_user(user)
