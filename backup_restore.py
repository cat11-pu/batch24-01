import threading

DEFAULT_MAX_SIZE = 1024 * 1024
DEFAULT_ALLOWED_TARGETS = frozenset({"db-1"})

_lock = threading.Lock()
_in_flight = set()


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def plan(backup, request, now, max_size=DEFAULT_MAX_SIZE,
         allowed_targets=DEFAULT_ALLOWED_TARGETS):
    if not isinstance(backup, dict):
        raise ValueError("backup must be a dict")
    if not isinstance(request, dict):
        raise ValueError("request must be a dict")
    if not _is_int(now):
        raise ValueError("now must be an integer")
    if not _is_int(max_size) or max_size < 0:
        raise ValueError("max_size must be a non-negative integer")

    checksum = backup.get("checksum")
    if not checksum:
        raise ValueError("backup checksum is missing")
    if checksum != backup.get("expected_checksum"):
        raise ValueError("backup checksum mismatch")
    if backup.get("encrypted") is not True:
        raise ValueError("backup is not encrypted")
    created_at = backup.get("created_at")
    if not _is_int(created_at):
        raise ValueError("backup created_at must be an integer")
    if created_at > now:
        raise ValueError("backup created_at is in the future")
    expires = backup.get("expires")
    if not _is_int(expires):
        raise ValueError("backup expires must be an integer")
    if expires <= now:
        raise ValueError("backup is expired")
    size = backup.get("size")
    if not _is_int(size):
        raise ValueError("backup size must be an integer")
    if size < 0:
        raise ValueError("backup size is negative")
    if size > max_size:
        raise ValueError("backup exceeds size limit")

    requester = request.get("requester")
    approver = request.get("approver")
    if not requester or not approver:
        raise ValueError("requester and approver are required")
    if requester == approver:
        raise ValueError("requester cannot approve own restore")
    reason = request.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("restore reason is required")
    target = request.get("target")
    if target not in allowed_targets:
        raise ValueError("target instance is not allowed")

    key = (backup.get("id"), target)
    with _lock:
        if key in _in_flight:
            raise ValueError("conflicting restore already in progress")
        _in_flight.add(key)

    return {"status": "approved", "target": target, "backup_id": backup.get("id")}
