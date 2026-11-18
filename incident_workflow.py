import threading
import weakref


VALID_STATUSES = (
    "detected",
    "triaged",
    "contained",
    "recovered",
    "closed",
    "escalated",
)

VALID_EVENTS = ("triage", "contain", "recover", "close")

VALID_SEVERITIES = ("P1", "P2", "P3", "P4")

REQUIRED_FIELDS = ("status", "severity", "assignee", "sla_due", "lead")

FORWARD_TRANSITIONS = {
    "detected": ("triaged",),
    "triaged": ("contained",),
    "contained": ("recovered",),
    "recovered": ("closed",),
}

TERMINAL_STATUSES = ("closed", "escalated")

_registry_guard = threading.RLock()
_state_locks = weakref.WeakValueDictionary()


def _lock_for(state):
    with _registry_guard:
        lock = _state_locks.get(id(state))
        if lock is None:
            lock = threading.RLock()
            _state_locks[id(state)] = lock
        return lock


def _validate(state, event, actor, now):
    if not isinstance(state, dict):
        raise ValueError("state must be a dict")

    missing = [field for field in REQUIRED_FIELDS if field not in state]
    if missing:
        raise ValueError("state is missing required fields: %s" % ", ".join(missing))

    if state["status"] not in VALID_STATUSES:
        raise ValueError("unknown status: %r" % (state["status"],))

    if state["severity"] not in VALID_SEVERITIES:
        raise ValueError("unknown severity: %r" % (state["severity"],))

    if not isinstance(state["assignee"], str):
        raise ValueError("assignee must be a string")

    if not isinstance(state["lead"], str) or not state["lead"]:
        raise ValueError("lead must be a non-empty string")

    if isinstance(state["sla_due"], bool) or not isinstance(state["sla_due"], int):
        raise ValueError("sla_due must be an integer timestamp")

    if event not in VALID_EVENTS:
        raise ValueError("unknown event: %r" % (event,))

    if not isinstance(actor, str) or not actor:
        raise ValueError("actor must be a non-empty string")

    if isinstance(now, bool) or not isinstance(now, int):
        raise ValueError("now must be an integer timestamp")


def transition(state, event, actor="", now=0):
    _validate(state, event, actor, now)

    lock = _lock_for(state)
    with lock:
        current_status = state["status"]

        if current_status in TERMINAL_STATUSES:
            raise ValueError(
                "incident already %s, no further transitions allowed" % current_status
            )

        if (
            current_status == "detected"
            and event == "triage"
            and state["severity"] == "P1"
            and now > state["sla_due"]
        ):
            state["status"] = "escalated"
            return state

        if event == "triage" and not state["assignee"]:
            raise ValueError("triage requires a concrete assignee")

        if event == "close" and actor != state["lead"]:
            raise ValueError("only the response lead can close the incident")

        allowed_targets = FORWARD_TRANSITIONS.get(current_status, ())
        target_status = {
            "triage": "triaged",
            "contain": "contained",
            "recover": "recovered",
            "close": "closed",
        }[event]

        if target_status not in allowed_targets:
            raise ValueError(
                "illegal transition: %s --%s--> %s"
                % (current_status, event, target_status)
            )

        state["status"] = target_status
        return state
