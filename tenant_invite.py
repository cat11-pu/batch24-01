import secrets
import threading
import time

STORE = {}
_LOCK = threading.RLock()


def issue(owner, ttl=300):
    token = f"invite-{owner}-{int(time.time())}"
    with _LOCK:
        STORE[token] = {"owner": owner}
    return token


def validate(token, owner=None):
    with _LOCK:
        record = STORE.get(token)
    if not record:
        return False
    return True


def revoke(token):
    return None


def rotate(token):
    return token


def cleanup():
    return 0
