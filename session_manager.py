import secrets
import threading

_lock = threading.RLock()

_SESSIONS = "sessions"
_BY_USER = "by_user"


def _validate_user_device(user, device):
    if not isinstance(user, str) or not user:
        raise ValueError("user must be a non-empty string")
    if not isinstance(device, str) or not device:
        raise ValueError("device must be a non-empty string")


def _validate_now(now):
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise ValueError("now must be a number")


def _ensure(store):
    sessions = store.setdefault(_SESSIONS, {})
    by_user = store.setdefault(_BY_USER, {})
    return sessions, by_user


def _drop(store, sessions, by_user, sid):
    record = sessions.pop(sid, None)
    if record is None:
        return None
    user_sessions = by_user.get(record["user"])
    if user_sessions is not None and sid in user_sessions:
        user_sessions.remove(sid)
        if not user_sessions:
            by_user.pop(record["user"], None)
    return record


def login(store, user, device, now, max_sessions=3):
    _validate_user_device(user, device)
    _validate_now(now)
    if not isinstance(max_sessions, int) or max_sessions < 1:
        raise ValueError("max_sessions must be a positive integer")
    with _lock:
        sessions, by_user = _ensure(store)
        user_sessions = by_user.setdefault(user, [])
        for sid in list(user_sessions):
            record = sessions.get(sid)
            if record is None:
                user_sessions.remove(sid)
            elif record["device"] == device:
                _drop(store, sessions, by_user, sid)
        while len(user_sessions) >= max_sessions:
            _drop(store, sessions, by_user, user_sessions[0])
        sid = secrets.token_hex(16)
        sessions[sid] = {
            "user": user,
            "device": device,
            "created": now,
            "last_seen": now,
        }
        user_sessions.append(sid)
        return sid


def touch(store, sid, now, idle=900, absolute=28800):
    _validate_now(now)
    with _lock:
        sessions, by_user = _ensure(store)
        record = sessions.get(sid)
        if record is None:
            return False
        if now < record["last_seen"]:
            raise ValueError("time must not go backwards")
        if now - record["last_seen"] > idle or now - record["created"] > absolute:
            _drop(store, sessions, by_user, sid)
            return False
        record["last_seen"] = now
        return True


def revoke(store, sid):
    with _lock:
        sessions, by_user = _ensure(store)
        return _drop(store, sessions, by_user, sid) is not None


def revoke_user(store, user):
    with _lock:
        sessions, by_user = _ensure(store)
        count = 0
        for sid in list(by_user.get(user, [])):
            if _drop(store, sessions, by_user, sid) is not None:
                count += 1
        return count
