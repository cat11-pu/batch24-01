"""Outbound error message guard.

Interfaces must never echo raw exception details back to callers. This
module inspects a candidate outbound message and rejects anything that
carries exploitable internals: stack frames, SQL, file paths, private
network addresses, credential material or oversized payloads.

Rejections always surface the same generic wording and error code so the
outside response never leaks the offending fragment or the reason.
"""

import ipaddress
import re

GENERIC_ERROR_CODE = "INTERNAL_ERROR"
GENERIC_ERROR_MESSAGE = "Request failed. Please contact support."

MAX_MESSAGE_LENGTH = 256

_STACK_PATTERNS = (
    re.compile(r"traceback\s*\(most recent call last\)", re.IGNORECASE),
    re.compile(r"\btraceback\b", re.IGNORECASE),
    re.compile(r"\bfile\s+[\"'][^\"']+[\"']\s*,\s*line\s+\d+", re.IGNORECASE),
    re.compile(r"\bat\s+[\w.$]+\([^)]*\.java:\d+\)", re.IGNORECASE),
    re.compile(
        r"\b\w+(?:error|exception|fault|throwable)\b",
        re.IGNORECASE,
    ),
)

_SQL_PATTERNS = (
    re.compile(
        r"\b(?:select\s+.+\s+from|insert\s+into|update\s+\w+\s+set|"
        r"delete\s+from|drop\s+(?:table|database)|alter\s+table|"
        r"create\s+(?:table|index|database)|truncate\s+table|"
        r"grant\s+[\w*]+\s+on|revoke\s+[\w*]+\s+on|union\s+(?:all\s+)?select)\b",
        re.IGNORECASE,
    ),
    re.compile(r"(?m)^\s*select\s+[\w*][\w\s.,()='\"\-]*$", re.IGNORECASE),
    re.compile(
        r"\b(?:sqlite|mysql|psycopg2|postgres(?:ql)?|oracle|mssql|sqlserver|"
        r"pymssql|asyncpg|aiomysql|aiosqlite|odbc|jdbc)\d*"
        r"(?:\.[a-zA-Z_]\w*)*\.[a-zA-Z_]\w*"
        r"(?:error|errors?|exception|warning|table)\b",
        re.IGNORECASE,
    ),
)

_PATH_PATTERNS = (
    re.compile(r"(?<![\w./])/[^\s/]+/[^\s\"']+"),
    re.compile(r"(?<![A-Za-z])[a-zA-Z]:[\\/][^\s\"']+"),
)

_IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?:\s*:\s*\d{1,5})?(?!\d)")
_IPV6_PATTERNS = (
    re.compile(r"(?<![\w:])[0-9a-fA-F:]*::[0-9a-fA-F:]*(?:%\w+)?(?!\w)"),
    re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?:%\w+)?(?!\w)"),
)

_SECRET_PATTERNS = (
    re.compile(
        r"(?:token|password|passwd|secret|api[_-]?key|access[_-]?key|"
        r"private[_-]?key|credential|auth)\s*[:=]",
        re.IGNORECASE,
    ),
    re.compile(r"\bAKIA[0-9A-Z]{8,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{8,}\b"),
    re.compile(r"\b(?:postgres(?:ql)?|mysql|redis|mongodb|amqp)://", re.IGNORECASE),
    re.compile(r"://[^\s/@:]+:[^\s/@]+@"),
)


def _reject():
    raise ValueError("{}: {}".format(GENERIC_ERROR_CODE, GENERIC_ERROR_MESSAGE))


def _contains_private_address(text):
    for match in _IPV4_RE.finditer(text):
        candidate = match.group(0).replace(" ", "")
        host = candidate.split(":", 1)[0]
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            continue
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
        ):
            return True
    for pattern in _IPV6_PATTERNS:
        for match in pattern.finditer(text):
            candidate = match.group(0).rstrip(":")
            host = candidate
            if "::" not in candidate:
                parts = candidate.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    host = parts[0]
            try:
                address = ipaddress.ip_address(host.split("%", 1)[0])
            except ValueError:
                continue
            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_reserved
                or address.is_multicast
            ):
                return True
    return False


def validate(value):
    """Return True when ``value`` is safe to expose, otherwise reject it.

    Any failure raises :class:`ValueError` (or :class:`TypeError` when the
    value is not a string) containing only the generic public wording.
    """
    if not isinstance(value, str):
        raise TypeError("{}: {}".format(GENERIC_ERROR_CODE, GENERIC_ERROR_MESSAGE))

    if not value or not value.strip():
        _reject()

    if len(value) > MAX_MESSAGE_LENGTH:
        _reject()

    for pattern in _STACK_PATTERNS:
        if pattern.search(value):
            _reject()

    for pattern in _SQL_PATTERNS:
        if pattern.search(value):
            _reject()

    for pattern in _PATH_PATTERNS:
        if pattern.search(value):
            _reject()

    if _contains_private_address(value):
        _reject()

    for pattern in _SECRET_PATTERNS:
        if pattern.search(value):
            _reject()

    return True
