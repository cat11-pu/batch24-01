"""WebAuthn registration challenge lifecycle management.

A challenge is a cryptographically random token bound to a user and an
RP ID, stored with an expiry so it can be consumed at most once during
registration. Verification enforces origin/RP ID matching, a strictly
increasing signature counter, and single-use semantics even under
concurrent consumers.
"""

import secrets
import threading
from urllib.parse import urlparse

# At least 32 bytes of randomness as required for WebAuthn challenges.
_CHALLENGE_BYTES = 32

# Serializes store mutations so concurrent verification can only
# consume a challenge once.
_lock = threading.Lock()


def _require_non_empty_str(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError("{} must be a non-empty string".format(name))


def _origin_matches_rp_id(origin, rp_id):
    """Origin must be an HTTPS URL whose host exactly equals the RP ID."""
    if not isinstance(origin, str) or not origin:
        return False
    parsed = urlparse(origin)
    if parsed.scheme != "https":
        return False
    return parsed.hostname == rp_id


def create_challenge(store, user, rp_id, now, ttl=300):
    if not isinstance(store, dict):
        raise ValueError("store must be a dict")
    _require_non_empty_str(user, "user")
    _require_non_empty_str(rp_id, "rp_id")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        raise ValueError("ttl must be a positive integer")

    with _lock:
        challenge = secrets.token_hex(_CHALLENGE_BYTES)
        store[challenge] = {
            "user": user,
            "expires_at": now + ttl,
            "rp_id": rp_id,
            "consumed": False,
        }
    return challenge


def verify(store, challenge, user, origin, rp_id, sign_count, now):
    if not isinstance(store, dict):
        raise ValueError("store must be a dict")
    _require_non_empty_str(challenge, "challenge")
    _require_non_empty_str(user, "user")
    _require_non_empty_str(origin, "origin")
    _require_non_empty_str(rp_id, "rp_id")
    if isinstance(sign_count, bool) or not isinstance(sign_count, int):
        raise ValueError("sign_count must be an integer")
    if sign_count <= 0:
        raise ValueError("sign_count must be strictly increasing")

    with _lock:
        record = store.get(challenge)
        if record is None:
            raise ValueError("unknown or already consumed challenge")
        if record["consumed"]:
            raise ValueError("challenge has already been consumed")
        if now >= record["expires_at"]:
            raise ValueError("challenge has expired")
        if record["user"] != user:
            raise ValueError("challenge is bound to a different user")
        if record["rp_id"] != rp_id:
            raise ValueError("rp_id does not match the challenge")
        if not _origin_matches_rp_id(origin, rp_id):
            raise ValueError("origin does not match the rp_id")

        record["consumed"] = True
    return True
