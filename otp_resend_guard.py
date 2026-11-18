"""Resend guard for SMS one-time-password (OTP) requests.

validate([last_sent_at, now]) decides whether a phone number may trigger
another OTP SMS, given the unix timestamp of the previous send and the
current request time. It enforces a per-number cooldown, an hourly send
limit, and rejects malformed input, negative/future timestamps and time
going backwards.
"""

import time

COOLDOWN_SECONDS = 60
WINDOW_SECONDS = 3600
MAX_SENDS_PER_WINDOW = 1


def _require_timestamp(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            "%s must be an int unix timestamp, got %s" % (name, type(value).__name__)
        )
    return value


def validate(value):
    if not isinstance(value, (list, tuple)):
        raise TypeError("value must be a [last_sent_at, now] pair")
    if len(value) != 2:
        raise ValueError("value must contain exactly [last_sent_at, now]")

    last_sent_at = _require_timestamp(value[0], "last_sent_at")
    now = _require_timestamp(value[1], "now")

    if last_sent_at < 0 or now < 0:
        raise ValueError("timestamps must be non-negative")
    if now < last_sent_at:
        raise ValueError("time went backwards: now is before the last send")
    if now > int(time.time()):
        raise ValueError("timestamp is in the future")

    elapsed = now - last_sent_at
    if elapsed <= COOLDOWN_SECONDS:
        raise ValueError("cooldown: resend within %d seconds of the last send"
                         % COOLDOWN_SECONDS)
    if elapsed <= WINDOW_SECONDS * MAX_SENDS_PER_WINDOW:
        raise ValueError("hourly limit: a send already happened inside the "
                         "current %d-second window" % WINDOW_SECONDS)
    return True
