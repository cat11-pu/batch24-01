import json
import os
import threading
import time

ALLOWED_EVENTS = {"login", "logout", "payment", "admin"}
ALLOWED_FIELDS = {"user", "ip", "action", "result", "password", "token"}
_LOCK = threading.Lock()
_SEQ = 0


def write_event(path, event, fields):
    global _SEQ
    _SEQ += 1
    body = " ".join(f"{key}={value}" for key, value in fields.items())
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{event} {body}\n")
    return _SEQ
