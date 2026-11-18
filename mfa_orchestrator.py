"""Multi-factor authentication flow orchestrator."""

import threading

MAX_FAILED = 3

_EVENTS = {"verify_password", "verify_totp", "verify_backup", "reset"}
_VERIFY_EVENTS = {"verify_password", "verify_totp", "verify_backup"}
_REQUIRED_KEYS = ("status", "user", "factors", "failed", "locked", "expires")
_LOCK = threading.RLock()


def _is_int(value):
    return type(value) is int


def _validate_state(state):
    if not isinstance(state, dict):
        raise ValueError("state must be a dict")
    for key in _REQUIRED_KEYS:
        if key not in state:
            raise ValueError("state missing key: %s" % key)
    if not isinstance(state["status"], str):
        raise ValueError("status must be a string")
    if not isinstance(state["user"], str) or not state["user"]:
        raise ValueError("user must be a non-empty string")
    if not isinstance(state["factors"], list) or not all(
        isinstance(f, str) for f in state["factors"]
    ):
        raise ValueError("factors must be a list of strings")
    if not _is_int(state["failed"]) or state["failed"] < 0:
        raise ValueError("failed must be a non-negative integer")
    if not isinstance(state["locked"], bool):
        raise ValueError("locked must be a bool")
    if not _is_int(state["expires"]):
        raise ValueError("expires must be an integer")


def _validate_code(event, code):
    if not isinstance(code, str) or not code:
        raise ValueError("code must be a non-empty string")
    if event == "verify_totp" and (len(code) != 6 or not code.isdigit()):
        raise ValueError("totp code must be exactly 6 digits")
    if event == "verify_backup" and len(code) < 8:
        raise ValueError("backup code must be at least 8 characters")


def step(state, event, factor="", now=0, code=""):
    with _LOCK:
        _validate_state(state)
        if not isinstance(event, str) or event not in _EVENTS:
            raise ValueError("unknown event")
        if not isinstance(factor, str):
            raise ValueError("factor must be a string")
        if not _is_int(now):
            raise ValueError("now must be an integer")
        if state["locked"]:
            raise ValueError("flow is locked")
        if now > state["expires"]:
            raise ValueError("flow has expired")

        if event in _VERIFY_EVENTS:
            if state["status"] == "pending" and state["failed"] >= MAX_FAILED:
                state["status"] = "locked"
                state["locked"] = True
                return state
            if state["status"] != "pending":
                raise ValueError("flow is not pending")
            expected = event[len("verify_"):]
            if factor != expected or expected not in state["factors"]:
                raise ValueError("factor not enrolled for this flow")
            _validate_code(event, code)
            state["status"] = "active"
            return state

        if state["status"] != "active":
            raise ValueError("reset requires an active flow")
        state["status"] = "pending"
        state["failed"] = 0
        state["locked"] = False
        return state
