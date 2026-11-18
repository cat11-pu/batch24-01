"""Account-recovery submission and review logic.

The caller owns the clock and passes integer timestamps to both public
functions.  A submission is accepted at most once per user in any rolling
24-hour window, and a review is applied atomically so a case can be decided
only once.
"""

import threading
import uuid


_COOLDOWN_SECONDS = 24 * 60 * 60
_DECISIONS = frozenset(("approve", "reject"))
_PENDING = "pending"
_DECIDED_STATUSES = frozenset(("approved", "rejected"))

# Store dictionaries are plain caller-owned objects, so guard every read and
# mutation that participates in the cooldown or case-decision invariants.
_LOCK = threading.Lock()


def _require_timestamp(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("%s must be an integer timestamp" % name)
    return value


def _require_store(store):
    if not isinstance(store, dict):
        raise ValueError("store must be a dict")


def _require_non_empty_string(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("%s must be a non-empty string" % name)
    return value


def _validate_answers(answers):
    if not isinstance(answers, dict):
        raise ValueError("answers must be a dict")
    if len(answers) < 3:
        raise ValueError("at least three answers are required")

    for question, answer in answers.items():
        _require_non_empty_string(question, "answer question")
        _require_non_empty_string(answer, "answer")

    return dict(answers)


def _record_user(record):
    return record.get("user")


def _record_created(record):
    created = record.get("created")
    if created is None:
        created = record.get("submitted_at")
    return created


def _record_expires(record):
    return record.get("expires")


def _is_decided(record):
    if record.get("status") in _DECIDED_STATUSES:
        return True
    if record.get("reviewed") is True:
        return True
    return record.get("decision") is not None


def _new_case_id(store):
    while True:
        case_id = "case_" + uuid.uuid4().hex
        if case_id not in store:
            return case_id


def submit(store, user, answers, now):
    """Create a recovery case and return its case id.

    Raises ``ValueError`` for malformed inputs, for a user that already has a
    submission inside the 24-hour cooldown window, or for a store containing
    malformed case records.
    """

    _require_store(store)
    user = _require_non_empty_string(user, "user")
    answers = _validate_answers(answers)
    now = _require_timestamp(now, "now")

    with _LOCK:
        for record in store.values():
            if not isinstance(record, dict):
                raise ValueError("store contains a malformed case")

            if _record_user(record) != user:
                continue

            created = _record_created(record)
            if created is None:
                raise ValueError("store contains a case without a timestamp")
            created = _require_timestamp(created, "case creation timestamp")

            if now - created < _COOLDOWN_SECONDS:
                raise ValueError("user already submitted within 24 hours")

        case_id = _new_case_id(store)
        store[case_id] = {
            "case_id": case_id,
            "user": user,
            "answers": answers,
            "created": now,
            "expires": now + _COOLDOWN_SECONDS,
            "status": _PENDING,
            "decision": None,
            "reviewer": None,
            "reviewed_at": None,
        }

    return case_id


def review(store, case_id, reviewer, decision, now):
    """Review a pending recovery case.

    Returns ``"expired"`` when the case is past its expiry, ``"approved"`` or
    ``"rejected"`` when the decision is committed.  Malformed input, unknown
    cases, self-review, and attempts to review an already-decided case raise
    ``ValueError``.
    """

    _require_store(store)
    case_id = _require_non_empty_string(case_id, "case id")
    reviewer = _require_non_empty_string(reviewer, "reviewer")
    if not isinstance(decision, str) or decision not in _DECISIONS:
        raise ValueError("decision must be 'approve' or 'reject'")
    now = _require_timestamp(now, "now")

    with _LOCK:
        if case_id not in store:
            raise ValueError("unknown case")

        record = store[case_id]
        if not isinstance(record, dict):
            raise ValueError("case record must be a dict")

        requester = _record_user(record)
        if requester is None:
            raise ValueError("case record has no user")
        _require_non_empty_string(requester, "case user")
        if requester == reviewer:
            raise ValueError("requesters cannot review their own case")

        if _is_decided(record):
            raise ValueError("case has already been decided")

        expires = _record_expires(record)
        if expires is None:
            raise ValueError("case record has no expiry")
        expires = _require_timestamp(expires, "case expiry timestamp")

        if now >= expires:
            return "expired"

        record["status"] = "approved" if decision == "approve" else "rejected"
        record["decision"] = decision
        record["reviewer"] = reviewer
        record["reviewed_at"] = now

        return record["status"]
