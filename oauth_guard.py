import base64
import hashlib
import hmac
import secrets
import threading
import time
from urllib.parse import urlsplit

USED_CODES = set()
USED_STATES = set()
_REPLAY_LOCK = threading.Lock()


def _constant_time_equals(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _is_non_empty_string(value):
    return isinstance(value, str) and bool(value.strip())


def _validate_redirect_uri(redirect_uri, registered_redirect_uris):
    if not _is_non_empty_string(redirect_uri):
        raise ValueError("invalid redirect_uri")
    if "#" in redirect_uri:
        raise ValueError("redirect_uri must not contain a fragment")

    try:
        parsed = urlsplit(redirect_uri)
    except (TypeError, ValueError):
        raise ValueError("invalid redirect_uri") from None

    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise ValueError("redirect_uri must not contain userinfo")
    if parsed.fragment:
        raise ValueError("redirect_uri must not contain a fragment")

    if registered_redirect_uris is None or isinstance(registered_redirect_uris, (str, bytes)):
        raise ValueError("invalid registered redirect_uris")

    try:
        registered = list(registered_redirect_uris)
    except TypeError:
        raise ValueError("invalid registered redirect_uris") from None

    for candidate in registered:
        if _constant_time_equals(redirect_uri, candidate):
            return
    raise ValueError("redirect_uri is not registered")


def _validate_pkce(code_verifier, code_challenge, code_challenge_method):
    if code_challenge_method is not None and code_challenge_method != "S256":
        raise ValueError("unsupported PKCE method")

    if code_challenge is None:
        return
    if not _is_non_empty_string(code_challenge):
        raise ValueError("invalid PKCE code_challenge")
    if code_challenge_method != "S256":
        raise ValueError("PKCE method must be S256")
    if not _is_non_empty_string(code_verifier):
        raise ValueError("PKCE code_verifier is required")

    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    s256_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    expected_challenges = (s256_challenge, digest.hex())

    if not any(
        _constant_time_equals(code_challenge.rstrip("="), candidate)
        for candidate in expected_challenges
    ):
        raise ValueError("PKCE code_verifier does not match code_challenge")


def build_authorize_url(client_id, redirect_uri, state=None, code_challenge=None, code_challenge_method="S256"):
    parts = [f"client_id={client_id}", f"redirect_uri={redirect_uri}"]
    if state is not None:
        parts.append(f"state={state}")
    if code_challenge is not None:
        parts.append(f"code_challenge={code_challenge}")
        parts.append(f"code_challenge_method={code_challenge_method}")
    return "https://auth.example.com/authorize?" + "&".join(parts)


def validate_callback(state, expected_state, code, redirect_uri, registered_redirect_uris,
                      code_verifier=None, code_challenge=None, code_challenge_method="S256",
                      client_id=None, expected_client_id=None):
    if not _is_non_empty_string(state) or not _is_non_empty_string(expected_state):
        raise ValueError("state is required")
    if not _constant_time_equals(state, expected_state):
        raise ValueError("state does not match")

    if not _is_non_empty_string(code):
        raise ValueError("authorization code is required")

    if not _is_non_empty_string(client_id) or not _is_non_empty_string(expected_client_id):
        raise ValueError("client_id is required")
    if not _constant_time_equals(client_id, expected_client_id):
        raise ValueError("client_id does not match")

    _validate_redirect_uri(redirect_uri, registered_redirect_uris)
    _validate_pkce(code_verifier, code_challenge, code_challenge_method)

    with _REPLAY_LOCK:
        if state in USED_STATES:
            raise ValueError("state has already been used")
        if code in USED_CODES:
            raise ValueError("authorization code has already been used")
        USED_STATES.add(state)
        USED_CODES.add(code)

    return True


def _reset_replay_state():
    with _REPLAY_LOCK:
        USED_CODES.clear()
        USED_STATES.clear()
