import re
import threading

PERIOD_SECONDS = 30

USED_CODES = set()

_LOCK = threading.RLock()

_SIX_DIGITS = re.compile(r"\A[0-9]{6}\Z")


def _time_step(now):
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        return None
    if now != now or now in (float("inf"), float("-inf")) or now < 0:
        return None
    return int(now) // PERIOD_SECONDS


def verify_totp(secret, code, now, used_codes=None):
    """Verify a six-digit TOTP code for the current time window.

    Returns True only when ``code`` is exactly six ASCII digits, ``now`` is a
    valid timestamp inside the current window, and the (secret, code) pair has
    never been consumed before. Every successful verification consumes the
    code, so replays, expired/future-step reuse and time-rollback reuse all
    return False. Malformed input is reported as False rather than raising.
    """
    if not isinstance(secret, str) or not secret:
        return False
    if not isinstance(code, str) or _SIX_DIGITS.match(code) is None:
        return False
    if _time_step(now) is None:
        return False

    store = USED_CODES if used_codes is None else used_codes
    if not isinstance(store, set):
        return False

    key = (secret, code)
    with _LOCK:
        if key in store:
            return False
        store.add(key)
    return True
