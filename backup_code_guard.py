"""MFA backup-code guard.

Two layers are provided:

* :func:`validate` -- a stateless validator for a single ``(attempts, code)``
  sample. It rejects malformed input and attempts that already reached the
  lockout threshold.
* :class:`BackupCodeGuard` -- a stateful, thread-safe per-user rate limiter.
  Failed attempts are counted separately for every user inside a fixed time
  window; once the threshold is reached the user is locked until the window
  expires. All check-and-update operations are atomic.

Thresholds and window length are named, configurable parameters -- no magic
numbers are baked into the control flow.
"""

import threading
import time

MAX_FAILED_ATTEMPTS = 5
WINDOW_SECONDS = 300
CODE_LENGTH = 6
ZERO_CODE = "000000"
_DIGITS = frozenset("0123456789")


class BackupCodeError(ValueError):
    """Base class for backup-code validation failures."""


class InvalidBackupCodeError(BackupCodeError):
    """Raised when a backup code is missing or malformed."""


class BackupCodeLockedError(BackupCodeError):
    """Raised when a user has exhausted the attempt budget for the window."""


def _validate_threshold(max_failed_attempts):
    if isinstance(max_failed_attempts, bool) or not isinstance(
        max_failed_attempts, int
    ):
        raise TypeError("max_failed_attempts must be an int")
    if max_failed_attempts <= 0:
        raise ValueError("max_failed_attempts must be positive")
    return max_failed_attempts


def _validate_attempts(attempts, max_failed_attempts):
    if isinstance(attempts, bool) or not isinstance(attempts, int):
        raise TypeError("attempts must be an int")
    if attempts <= 0:
        raise ValueError("attempts must be greater than zero")
    if attempts >= max_failed_attempts:
        raise BackupCodeLockedError(
            "backup-code attempts exhausted; user is locked"
        )


def _validate_code(code):
    if not isinstance(code, str):
        raise TypeError("backup code must be a string")
    if len(code) != CODE_LENGTH or any(ch not in _DIGITS for ch in code):
        raise InvalidBackupCodeError(
            "backup code must be exactly %d ASCII digits" % CODE_LENGTH
        )
    if code == ZERO_CODE:
        raise InvalidBackupCodeError("all-zero backup code is not allowed")


def validate(value, max_failed_attempts=MAX_FAILED_ATTEMPTS):
    """Validate one ``(attempts, backup_code)`` sample.

    ``value`` must be a two-element list/tuple where ``attempts`` is the
    number of failed attempts already recorded for the user and ``code`` is
    the supplied backup code. Returns ``True`` when the sample is acceptable,
    otherwise raises :class:`TypeError` or :class:`ValueError`.
    """
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise TypeError("value must be a [attempts, backup_code] sequence")
    attempts, code = value
    threshold = _validate_threshold(max_failed_attempts)
    _validate_attempts(attempts, threshold)
    _validate_code(code)
    return True


class _UserState:
    __slots__ = ("failures", "window_started_at", "locked_until")

    def __init__(self):
        self.failures = 0
        self.window_started_at = None
        self.locked_until = 0.0


class BackupCodeGuard:
    """Per-user backup-code attempt limiter with fixed-window lockout.

    Failed attempts are counted in fixed windows of ``window_seconds``.
    Reaching the threshold locks the user until ``now + lock_seconds`` and
    anchors the window so it expires at the same instant as the lock.
    Expiry always performs a full reset, giving every user a fresh budget
    after lockout. A backwards-moving clock can never shorten a lock
    because elapsed time is clamped at zero.
    """

    def __init__(
        self,
        max_failed_attempts=MAX_FAILED_ATTEMPTS,
        window_seconds=WINDOW_SECONDS,
        lock_seconds=None,
        verifier=None,
        clock=time.monotonic,
    ):
        self.max_failed_attempts = _validate_threshold(max_failed_attempts)
        if isinstance(window_seconds, bool) or not isinstance(
            window_seconds, (int, float)
        ):
            raise TypeError("window_seconds must be a number")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if lock_seconds is None:
            lock_seconds = window_seconds
        if isinstance(lock_seconds, bool) or not isinstance(
            lock_seconds, (int, float)
        ):
            raise TypeError("lock_seconds must be a number")
        if lock_seconds <= 0:
            raise ValueError("lock_seconds must be positive")
        if verifier is not None and not callable(verifier):
            raise TypeError("verifier must be callable")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self.window_seconds = float(window_seconds)
        self.lock_seconds = float(lock_seconds)
        self._verifier = verifier
        self._clock = clock
        self._users = {}
        self._lock = threading.Lock()

    def _expired(self, state, now):
        if state.window_started_at is None:
            return False
        # Clamp negative elapsed time: a backwards clock must never unlock.
        elapsed = max(0.0, now - state.window_started_at)
        return elapsed >= self.window_seconds

    def _get_state(self, user_id, now):
        state = self._users.get(user_id)
        if state is None:
            state = _UserState()
            self._users[user_id] = state
            return state
        if self._expired(state, now):
            state.failures = 0
            state.window_started_at = None
            state.locked_until = 0.0
        return state

    def validate(self, user_id, code, verifier=None):
        """Check ``code`` for ``user_id`` atomically.

        The lock is evaluated first: while a user is locked every call --
        even with a correct or malformed code -- raises
        :class:`BackupCodeLockedError`, so the lock cannot be probed or
        bypassed. When unlocked, malformed input raises
        :class:`TypeError`/:class:`ValueError` without consuming an attempt,
        a wrong code returns ``False`` and consumes one attempt, and the
        attempt that reaches the threshold locks the user. A correct code
        before lockout returns ``True`` and clears the window.
        """
        verifier = verifier or self._verifier
        if verifier is None:
            raise TypeError("a verifier callable is required")

        with self._lock:
            now = self._clock()
            state = self._get_state(user_id, now)
            if now < state.locked_until:
                raise BackupCodeLockedError(
                    "user is locked until the window expires"
                )
            _validate_code(code)

            if verifier(code):
                state.failures = 0
                state.window_started_at = None
                state.locked_until = 0.0
                return True

            state.failures += 1
            if state.window_started_at is None:
                state.window_started_at = now
            if state.failures >= self.max_failed_attempts:
                state.locked_until = now + self.lock_seconds
                # Anchor the window to expire together with the lock so
                # the counter can never reset while the lock is in force.
                state.window_started_at = (
                    state.locked_until - self.window_seconds
                )
                raise BackupCodeLockedError(
                    "backup-code attempt threshold reached"
                )
            return False

    def is_locked(self, user_id):
        """Return whether ``user_id`` is currently locked."""
        with self._lock:
            now = self._clock()
            state = self._users.get(user_id)
            if state is None:
                return False
            self._get_state(user_id, now)
            return now < state.locked_until

    def remaining_attempts(self, user_id):
        """Return the wrong-code attempts still available in this window."""
        with self._lock:
            now = self._clock()
            state = self._users.get(user_id)
            if state is None:
                return self.max_failed_attempts
            self._get_state(user_id, now)
            if now < state.locked_until:
                return 0
            return max(0, self.max_failed_attempts - state.failures)

    def reset(self, user_id=None):
        """Clear the state of one user, or all users when ``user_id`` is None."""
        with self._lock:
            if user_id is None:
                self._users.clear()
            else:
                self._users.pop(user_id, None)
