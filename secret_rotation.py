"""Thread-safe, rollback-friendly secret rotation.

The ``store`` is a plain dict supplied by the caller::

    {
        service: {
            "current": "<active secret>",
            "history": [("<retired secret>", expires_at), ...],
        }
    }

A retired secret remains usable until ``expires_at`` (the rotation
timestamp plus the overlap window), so every rotation is rollback-friendly:
:func:`active_secrets` keeps returning the previous secret while the
overlap is in effect and drops it once the window ends. Legacy history
entries stored as plain strings are accepted and treated as expired.
"""

import string
import threading

SECRET_MIN_LENGTH = 32
SECRET_CHARSET = string.ascii_letters + string.digits
HISTORY_LIMIT = 3
DEFAULT_OVERLAP = 300
MAX_OVERLAP = 24 * 60 * 60

_rotation_lock = threading.RLock()


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_store(store):
    if not isinstance(store, dict):
        raise ValueError("store must be a dict")


def _validate_service_name(service):
    if not isinstance(service, str) or not service:
        raise ValueError("service must be a non-empty string")


def _load_entry(store, service):
    _validate_store(store)
    _validate_service_name(service)
    if service not in store:
        raise ValueError("unknown service: %r" % service)
    entry = store[service]
    if not isinstance(entry, dict):
        raise ValueError("service entry must be a dict")
    current = entry.get("current")
    if not isinstance(current, str) or not current:
        raise ValueError("service entry requires a non-empty 'current' secret")
    history = entry.get("history")
    if not isinstance(history, list):
        raise ValueError("service entry requires a list 'history'")
    return entry


def _validate_new_secret(new_secret):
    if not isinstance(new_secret, str) or not new_secret:
        raise ValueError("secret must be a non-empty string")
    if len(new_secret) < SECRET_MIN_LENGTH:
        raise ValueError(
            "secret must be at least %d characters" % SECRET_MIN_LENGTH
        )
    allowed = set(SECRET_CHARSET)
    if any(character not in allowed for character in new_secret):
        raise ValueError("secret contains characters outside the allowed charset")


def _history_secret(item):
    if isinstance(item, (tuple, list)) and item:
        return item[0]
    if isinstance(item, str):
        return item
    return None


def _history_expiry(item):
    if isinstance(item, (tuple, list)) and len(item) >= 2 and _is_int(item[1]):
        return item[1]
    return None


def rotate(
    store, service, new_secret, now,
    overlap=DEFAULT_OVERLAP, max_overlap=MAX_OVERLAP,
):
    """Rotate ``service`` to ``new_secret`` and retire the old one.

    The previous secret stays active for ``overlap`` seconds so that
    deployments can roll back. ``max_overlap`` lets the caller cap the
    window. Raises :class:`ValueError` for any validation failure.
    """
    with _rotation_lock:
        entry = _load_entry(store, service)
        _validate_new_secret(new_secret)
        if not _is_int(now):
            raise ValueError("now must be an integer timestamp")
        if not _is_int(overlap):
            raise ValueError("overlap must be an integer")
        if overlap < 0:
            raise ValueError("overlap must not be negative")
        if not _is_int(max_overlap) or max_overlap < 0:
            raise ValueError("max_overlap must be a non-negative integer")
        if overlap > max_overlap:
            raise ValueError("overlap exceeds the limit of %d" % max_overlap)

        history = entry["history"]
        recent_secrets = [entry["current"]]
        recent_secrets.extend(
            secret
            for secret in (
                _history_secret(item)
                for item in history[-(HISTORY_LIMIT - 1):]
            )
            if secret is not None
        )
        if new_secret in recent_secrets:
            raise ValueError(
                "new secret must not reuse one of the last %d secrets"
                % HISTORY_LIMIT
            )

        previous = entry["current"]
        expires_at = now + overlap
        history.append((previous, expires_at))
        entry["current"] = new_secret
        return {
            "service": service,
            "current": new_secret,
            "previous": previous,
            "expires_at": expires_at,
        }


def active_secrets(store, service, now):
    """Return the current secret plus every secret still inside its
    overlap window, newest first."""
    with _rotation_lock:
        entry = _load_entry(store, service)
        if not _is_int(now):
            raise ValueError("now must be an integer timestamp")

        active = [entry["current"]]
        for item in entry["history"]:
            secret = _history_secret(item)
            expires_at = _history_expiry(item)
            if secret is None or expires_at is None:
                continue
            if now < expires_at and secret not in active:
                active.append(secret)
        return active
