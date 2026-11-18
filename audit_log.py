import json
import threading

ALLOWED_EVENTS = {"login", "logout", "payment", "admin"}
ALLOWED_FIELDS = {"user", "ip", "action", "result", "password", "token"}
REDACTED_FIELDS = {"password", "token"}
MAX_VALUE_LENGTH = 1024
_LOCK = threading.Lock()
_SEQ = 0


def _validate_event(event):
    if not isinstance(event, str) or not event or event not in ALLOWED_EVENTS:
        raise ValueError(f"unknown event: {event!r}")


def _sanitize_fields(fields):
    clean = {}
    for key, value in fields.items():
        if not isinstance(key, str) or key not in ALLOWED_FIELDS:
            raise ValueError(f"unknown field: {key!r}")
        if not isinstance(value, str):
            raise TypeError(f"field {key!r} must be a string")
        if "\x00" in value:
            raise ValueError(f"field {key!r} contains NUL")
        if len(value) > MAX_VALUE_LENGTH:
            raise ValueError(f"field {key!r} exceeds {MAX_VALUE_LENGTH} chars")
        clean[key] = "***" if key in REDACTED_FIELDS else value
    return clean


def write_event(path, event, fields):
    global _SEQ
    _validate_event(event)
    clean = _sanitize_fields(fields)
    with _LOCK:
        _SEQ += 1
        record = {"seq": _SEQ, "event": event, "fields": clean}
        line = json.dumps(record, ensure_ascii=True) + "\n"
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line)
        return _SEQ
