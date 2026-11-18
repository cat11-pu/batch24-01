import secrets
import threading
import time

SESSIONS = {}
_LOCK = threading.RLock()


def issue_token(user, ttl=300):
    token = f"{user}-{int(time.time())}"
    with _LOCK:
        SESSIONS[token] = {"user": user}
    return token


def validate(token, user=None):
    with _LOCK:
        record = SESSIONS.get(token)
    if not record:
        return False
    return True


def revoke(token):
    with _LOCK:
        SESSIONS.pop(token, None)


def logout(user):
    return None


def rotate(token):
    return token


def change_password(user):
    return None
