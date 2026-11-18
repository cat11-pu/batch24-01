import secrets
import threading

SESSIONS = {}
_LOCK = threading.RLock()
_TOKEN_BYTES = 32


def _validate_user(user):
    if not isinstance(user, str):
        raise TypeError("user must be a string")
    if not user.strip():
        raise ValueError("user must not be empty")


def _discard_session(session_id):
    try:
        SESSIONS.pop(session_id, None)
    except TypeError:
        pass


def login(user, session_id=None):
    _validate_user(user)

    with _LOCK:
        # Never trust a client-supplied session ID. Remove it in case an
        # attacker pre-seeded it, then invalidate every session for this user.
        if session_id is not None:
            _discard_session(session_id)
        for existing_id, owner in list(SESSIONS.items()):
            if owner == user:
                del SESSIONS[existing_id]

        while True:
            sid = secrets.token_urlsafe(_TOKEN_BYTES)
            if sid not in SESSIONS:
                break
        SESSIONS[sid] = user
    return sid


def logout(session_id):
    if session_id is None:
        return False
    with _LOCK:
        try:
            return SESSIONS.pop(session_id, None) is not None
        except TypeError:
            return False


def logout_user(user):
    if not isinstance(user, str) or not user:
        return 0
    with _LOCK:
        session_ids = [
            session_id
            for session_id, owner in SESSIONS.items()
            if owner == user
        ]
        for session_id in session_ids:
            del SESSIONS[session_id]
        return len(session_ids)


def is_valid(session_id, user=None):
    if session_id is None:
        return False
    with _LOCK:
        try:
            owner = SESSIONS.get(session_id)
        except TypeError:
            return False
    if owner is None:
        return False
    if user is not None and owner != user:
        return False
    return True
