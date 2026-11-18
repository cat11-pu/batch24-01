import secrets

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "access_token"

MIN_TOKEN_LENGTH = 8
MAX_TOKEN_LENGTH = 4096


def _reject():
    raise ValueError("invalid token exchange request")


def _require_string(mapping, key):
    value = mapping.get(key)
    if not isinstance(value, str):
        _reject()
    return value


def _check_token(token, allowed_types, token_type, min_length=MIN_TOKEN_LENGTH,
                 max_length=MAX_TOKEN_LENGTH):
    if not isinstance(token, str) or not min_length <= len(token) <= max_length:
        _reject()
    if not isinstance(token_type, str) or token_type not in allowed_types:
        _reject()


def exchange(request, now, client_id, allowed_subject_types):
    if not isinstance(request, dict):
        _reject()
    if not isinstance(now, int) or isinstance(now, bool):
        _reject()
    if not isinstance(client_id, str) or not client_id:
        _reject()
    if not allowed_subject_types or not isinstance(allowed_subject_types, (list, tuple, set, frozenset)):
        _reject()

    allowed_types = frozenset(allowed_subject_types)

    if _require_string(request, "grant_type") != GRANT_TYPE:
        _reject()

    subject_token = _require_string(request, "subject_token")
    subject_token_type = _require_string(request, "subject_token_type")
    _check_token(subject_token, allowed_types, subject_token_type)

    if _require_string(request, "audience") != client_id:
        _reject()
    if _require_string(request, "client_id") != client_id:
        _reject()

    scope = _require_string(request, "scope")
    if not scope.strip():
        _reject()

    if _require_string(request, "requested_token_type") != ACCESS_TOKEN_TYPE:
        _reject()

    has_actor_token = "actor_token" in request
    has_actor_type = "actor_token_type" in request
    if has_actor_token != has_actor_type:
        _reject()
    if has_actor_token:
        _check_token(request["actor_token"], allowed_types, request["actor_token_type"])

    return {
        "access_token": secrets.token_urlsafe(32),
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "scope": scope,
        "expires_in": 3600,
    }
