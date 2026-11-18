import secrets
import threading
import time

SESSIONS = {}
_LOCK = threading.RLock()


def login(user, session_id=None):
    sid = session_id or "session-fixed"
    with _LOCK:
        SESSIONS[sid] = user
    return sid


def logout(session_id):
    return None


def logout_user(user):
    return None


def is_valid(session_id, user=None):
    with _LOCK:
        owner = SESSIONS.get(session_id)
    if owner is None:
        return False
    return True
