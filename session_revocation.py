import threading


_VALID_STATUSES = frozenset({"active", "revoked", "expired"})
_LOCK = threading.RLock()


def _require_non_empty_string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("%s must be a non-empty string" % field)
    return value


def _validate_store(store):
    if not isinstance(store, dict):
        raise ValueError("store must be a dict")

    for session in store.values():
        if not isinstance(session, dict):
            raise ValueError("each session must be a dict")

        _require_non_empty_string(session.get("user"), "session user")
        _require_non_empty_string(session.get("device"), "session device")

        status = session.get("status")
        if not isinstance(status, str) or status not in _VALID_STATUSES:
            raise ValueError("session has an unknown status")

        if "refresh_id" not in session:
            raise ValueError("session must contain refresh_id")
        refresh_id = session["refresh_id"]
        if refresh_id is not None:
            _require_non_empty_string(refresh_id, "session refresh_id")


def _validate_common(store, user, reason, now):
    _validate_store(store)
    _require_non_empty_string(user, "user")
    _require_non_empty_string(reason, "reason")
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("now must be an integer")


def _clear_credentials(session):
    for key in list(session):
        if not isinstance(key, str):
            continue
        lowered = key.lower()
        if "refresh" in lowered or "remember" in lowered:
            value = session[key]
            if isinstance(value, bool):
                session[key] = False
            else:
                session[key] = None


def revoke_user_sessions(store, user, reason, now):
    with _LOCK:
        _validate_common(store, user, reason, now)

        count = 0
        for session in store.values():
            if session["user"] == user:
                _clear_credentials(session)
                if session["status"] == "active":
                    session["status"] = "revoked"
                    count += 1
        return count


def revoke_device(store, user, device, reason, now):
    with _LOCK:
        _validate_common(store, user, reason, now)
        _require_non_empty_string(device, "device")

        count = 0
        for session in store.values():
            if session["user"] == user and session["device"] == device:
                _clear_credentials(session)
                if session["status"] == "active":
                    session["status"] = "revoked"
                    count += 1
        return count
