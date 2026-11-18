"""Privilege-transition validation with mandatory session rotation."""

import threading


# Role policy is declarative. Transition logic below is generic and does not
# special-case any particular role pair.
_ROLE_LEVELS = {
    "user": 0,
    "admin": 1,
}
_VALID_ROLES = frozenset(_ROLE_LEVELS)

_MISSING = object()
_LOCK = threading.RLock()
_SESSION_ROLES = {}
_REVOKED_SESSIONS = set()


def _validate_role(value, field):
    if not isinstance(value, str):
        raise TypeError("%s must be a string" % field)
    if not value.strip():
        raise ValueError("%s must not be empty" % field)
    if value != value.strip():
        raise ValueError("%s must not contain surrounding whitespace" % field)
    if value not in _VALID_ROLES:
        raise ValueError("unknown %s: %r" % (field, value))
    return value


def _validate_session_id(value):
    if not isinstance(value, str):
        raise TypeError("session_id must be a string")
    if not value.strip():
        raise ValueError("session_id must not be empty")
    if value != value.strip():
        raise ValueError("session_id must not contain surrounding whitespace")
    return value


def _validate_rotated(value):
    if isinstance(value, bool):
        return value
    raise TypeError("rotated must be a bool")


def _unpack(value):
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(
        value, (list, tuple)
    ):
        raise TypeError(
            "validate expects a four-item sequence or four arguments"
        )
    if len(value) != 4:
        raise ValueError(
            "validate expects old_role, new_role, session_id, rotated"
        )
    return value


def _revoke_role_sessions(role):
    doomed = [
        session_id
        for session_id, bound_role in _SESSION_ROLES.items()
        if bound_role == role
    ]
    for session_id in doomed:
        _SESSION_ROLES.pop(session_id, None)
        _REVOKED_SESSIONS.add(session_id)


def validate(
    old_role, new_role=_MISSING, session_id=_MISSING, rotated=_MISSING
):
    """Validate a role transition.

    A role change is accepted only with a fresh session: an old session id
    that has already been bound (or revoked) is rejected, and all sessions
    bound to the old role are invalidated.
    """
    if new_role is _MISSING and session_id is _MISSING and rotated is _MISSING:
        old_role, new_role, session_id, rotated = _unpack(old_role)
    elif (
        new_role is _MISSING
        or session_id is _MISSING
        or rotated is _MISSING
    ):
        raise TypeError(
            "validate expects old_role, new_role, session_id, rotated"
        )

    old_role = _validate_role(old_role, "old_role")
    new_role = _validate_role(new_role, "new_role")
    session_id = _validate_session_id(session_id)
    rotation = _validate_rotated(rotated)
    role_changed = old_role != new_role

    with _LOCK:
        # The guard never accepts an unrotated transition. Remember the
        # presented session as belonging to the old role so a later attempt
        # to rotate that same id into a new role is treated as reuse.
        if rotation is False:
            if session_id not in _REVOKED_SESSIONS:
                _SESSION_ROLES.setdefault(session_id, old_role)
            raise ValueError("session rotation is required")

        # rotated is True: session_id is the freshly issued session.
        if session_id in _REVOKED_SESSIONS:
            raise ValueError("session has been revoked")

        previous_role = _SESSION_ROLES.get(session_id)
        if role_changed:
            if previous_role is not None:
                raise ValueError("role change must use a fresh session")
            _revoke_role_sessions(old_role)
        elif previous_role is not None and previous_role != new_role:
            raise ValueError("session is bound to a different role")

        _SESSION_ROLES[session_id] = new_role
        return True
