import threading


_DEFAULT_ALLOWED_SCOPES = {"read", "write"}
ALLOWED_SCOPES = _DEFAULT_ALLOWED_SCOPES
ALLOWED = ALLOWED_SCOPES
SCOPES = ALLOWED_SCOPES

_LOCK = threading.RLock()
_NEXT_GRANT_ID = 1


def _validate_store(store):
    if not isinstance(store, dict):
        raise ValueError("store must be a dict")


def _validate_identity(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _validate_int(value, name):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")


def _resolve_allowed_scopes(allowed_scopes):
    if allowed_scopes is None:
        for name in ("ALLOWED_SCOPES", "ALLOWED", "SCOPES"):
            configured = globals().get(name)
            if configured is not _DEFAULT_ALLOWED_SCOPES:
                allowed_scopes = configured
                break
        else:
            allowed_scopes = _DEFAULT_ALLOWED_SCOPES
    if not isinstance(allowed_scopes, (list, tuple, set, frozenset)):
        raise ValueError("allowed_scopes must be a collection")
    if not allowed_scopes:
        raise ValueError("allowed_scopes must not be empty")
    for scope in allowed_scopes:
        if not isinstance(scope, str) or not scope.strip():
            raise ValueError("allowed scopes must be non-empty strings")
    return set(allowed_scopes)


def _validate_grant_args(store, user, client, scopes, now, ttl, allowed_scopes):
    _validate_store(store)
    _validate_identity(user, "user")
    _validate_identity(client, "client")
    _validate_int(now, "now")
    _validate_int(ttl, "ttl")
    if ttl <= 0:
        raise ValueError("ttl must be positive")
    if not isinstance(scopes, list):
        raise ValueError("scopes must be a list")
    if not scopes:
        raise ValueError("scopes must not be empty")

    permitted = _resolve_allowed_scopes(allowed_scopes)
    seen = set()
    for scope in scopes:
        if not isinstance(scope, str) or not scope.strip():
            raise ValueError("each scope must be a non-empty string")
        if scope in seen:
            raise ValueError("duplicate scope")
        if scope not in permitted:
            raise ValueError("scope is not allowed")
        seen.add(scope)
    return frozenset(seen)


def _find_active_grant(store, user, client):
    for grant_id, record in store.items():
        if not isinstance(record, dict):
            continue
        if record.get("user") == user and record.get("client") == client:
            return grant_id, record
    return None, None


def grant(store, user, client, scopes, now, ttl=3600, allowed_scopes=None):
    scope_set = _validate_grant_args(
        store, user, client, scopes, now, ttl, allowed_scopes
    )

    global _NEXT_GRANT_ID
    with _LOCK:
        old_id, old_record = _find_active_grant(store, user, client)
        if old_record is not None and now == old_record["issued_at"]:
            raise ValueError("duplicate grant for this user, client, and timestamp")

        if old_id is not None:
            del store[old_id]

        grant_id = f"g{_NEXT_GRANT_ID}"
        _NEXT_GRANT_ID += 1
        store[grant_id] = {
            "user": user,
            "client": client,
            "scopes": scope_set,
            "issued_at": now,
            "expires_at": now + ttl,
        }
        return grant_id


def revoke(store, grant_id):
    _validate_store(store)
    if not isinstance(grant_id, str) or not grant_id:
        return False

    with _LOCK:
        record = store.get(grant_id)
        if not isinstance(record, dict):
            return False
        del store[grant_id]
        return True


def check(store, user, client, scope, now, allowed_scopes=None):
    _validate_store(store)
    _validate_identity(user, "user")
    _validate_identity(client, "client")
    _validate_identity(scope, "scope")
    _validate_int(now, "now")
    if allowed_scopes is not None:
        _resolve_allowed_scopes(allowed_scopes)

    with _LOCK:
        _, record = _find_active_grant(store, user, client)
        if record is None:
            return False
        if now < record["issued_at"] or now >= record["expires_at"]:
            return False
        if scope not in record["scopes"]:
            return False
        if allowed_scopes is not None and scope not in allowed_scopes:
            return False
        return True
