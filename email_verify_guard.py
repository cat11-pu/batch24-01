"""Email verification token guard.

Tokens are high-entropy random strings issued through :func:`issue_token`.
Each token is stored server side, bound to one email address, expires after a
time-to-live and can be consumed exactly once.  :func:`validate` rejects any
value that does not come from :func:`issue_token`, including empty values,
short tokens, purely numeric guesses and values containing control characters.
"""

import re
import secrets
import threading
import time

__all__ = [
    "issue_token",
    "validate",
    "revoke_token",
    "purge_expired",
    "EmailVerifyError",
    "DEFAULT_TTL_SECONDS",
    "MIN_TOKEN_LENGTH",
]

DEFAULT_TTL_SECONDS = 30 * 60
MIN_TOKEN_LENGTH = 32
_TOKEN_BYTES = 32
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class EmailVerifyError(ValueError):
    """Raised when an email verification token cannot be accepted."""


def _new_token():
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    while len(token) < MIN_TOKEN_LENGTH:
        token = secrets.token_urlsafe(_TOKEN_BYTES)
    return token


class _TokenStore:
    def __init__(self):
        self._records = {}
        self._lock = threading.RLock()

    def issue(self, email, ttl_seconds, now):
        if not isinstance(email, str) or not _EMAIL_RE.match(email):
            raise EmailVerifyError("invalid email address")
        if not isinstance(ttl_seconds, (int, float)) or ttl_seconds <= 0:
            raise EmailVerifyError("ttl_seconds must be a positive number")
        expires_at = now + ttl_seconds
        with self._lock:
            for _ in range(8):
                token = _new_token()
                if token not in self._records:
                    break
            else:
                raise EmailVerifyError("failed to allocate a unique token")
            self._records[token] = {
                "email": email,
                "expires_at": expires_at,
                "used": False,
            }
        return token

    def consume(self, token, email, now):
        with self._lock:
            record = self._records.get(token)
            if record is None:
                raise EmailVerifyError("unknown verification token")
            if record["used"]:
                raise EmailVerifyError("verification token has already been used")
            if now >= record["expires_at"]:
                del self._records[token]
                raise EmailVerifyError("verification token has expired")
            if email is not None and record["email"] != email:
                raise EmailVerifyError("verification token is bound to another email")
            record["used"] = True
            del self._records[token]
            return record["email"]

    def revoke(self, token):
        with self._lock:
            return self._records.pop(token, None) is not None

    def purge(self, now):
        with self._lock:
            expired = [
                token
                for token, record in self._records.items()
                if now >= record["expires_at"]
            ]
            for token in expired:
                del self._records[token]
        return len(expired)

    def __len__(self):
        with self._lock:
            return len(self._records)


_store = _TokenStore()


def _reject_bad_shape(value):
    if not isinstance(value, str):
        raise TypeError("verification token must be a string")
    if not value:
        raise EmailVerifyError("empty verification token")
    if len(value) < MIN_TOKEN_LENGTH:
        raise EmailVerifyError("verification token is too short")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise EmailVerifyError("verification token contains control characters")
    if any(char.isspace() for char in value):
        raise EmailVerifyError("verification token contains whitespace")
    if value.isdigit():
        raise EmailVerifyError("verification token must not be purely numeric")


def issue_token(email, ttl_seconds=DEFAULT_TTL_SECONDS):
    """Issue a random, email-bound, single-use verification token."""
    return _store.issue(email, ttl_seconds, time.time())


def validate(value, email=None):
    """Validate and consume an email verification token.

    Raises ``ValueError``/``TypeError`` for malformed input and
    :class:`EmailVerifyError` for unknown, expired, replayed or cross-email
    tokens.  A successful validation consumes the token, so any later attempt
    with the same value fails.
    """
    _reject_bad_shape(value)
    if email is not None and (
        not isinstance(email, str) or not _EMAIL_RE.match(email)
    ):
        raise EmailVerifyError("invalid email address")
    return _store.consume(value, email, time.time())


def revoke_token(token):
    """Invalidate a token before it is used.  Return whether it existed."""
    if not isinstance(token, str):
        return False
    return _store.revoke(token)


def purge_expired():
    """Drop expired records and return how many were removed."""
    return _store.purge(time.time())
