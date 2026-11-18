"""Gateway guard for debug and environment endpoints.

Operational endpoints such as ``/debug``, ``/actuator``, ``/.env`` and
``/metrics`` expose configuration and secrets, so they must never be
reachable from the public internet.  ``validate`` normalizes an incoming
request path before matching it against a configurable block list, which
closes case, percent-encoding, semicolon and double-slash bypasses.
Sensitive endpoints are only accepted for intranet clients or administrators.
"""

import os
import re
from ipaddress import ip_address
from urllib.parse import unquote


DEFAULT_BLOCKED_PREFIXES = (
    "/debug",
    "/actuator",
    "/.env",
    "/metrics",
    "/env",
    "/config",
)

_PREFIXES_ENV_VAR = "DEBUG_GUARD_BLOCKED_PREFIXES"
_MAX_DECODE_ROUNDS = 4
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


class PathValidationError(ValueError):
    """Malformed request path or access to a blocked endpoint."""


def _percent_decode(path):
    decoded = path
    for _ in range(_MAX_DECODE_ROUNDS):
        if _BAD_PERCENT_RE.search(decoded):
            raise PathValidationError("malformed percent-encoding in path")
        if "%" not in decoded:
            return decoded
        try:
            decoded = unquote(decoded, encoding="utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise PathValidationError("invalid percent-encoded path") from exc
    raise PathValidationError("excessive percent-encoding in path")


def normalize_path(value):
    """Return a canonical, case-folded path or raise on unsafe input."""
    if not isinstance(value, str):
        raise TypeError("request path must be a string")
    if not value:
        raise PathValidationError("request path must not be empty")

    path = value
    for separator in ("?", "#"):
        position = path.find(separator)
        if position != -1:
            path = path[:position]
    if not path.startswith("/"):
        raise PathValidationError("request path must be absolute")

    path = _percent_decode(path)

    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
        raise PathValidationError("control characters are not allowed")
    if ";" in path:
        raise PathValidationError("semicolon/matrix parameters are not allowed")
    if "\\" in path:
        raise PathValidationError("backslashes are not allowed in paths")

    segments = []
    for segment in path.casefold().split("/")[1:]:
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/" + "/".join(segments)


def _normalize_prefixes(blocked_prefixes):
    rules = []
    for prefix in blocked_prefixes:
        if not isinstance(prefix, str):
            raise TypeError("blocked prefixes must be strings")
        folded = prefix.casefold().strip()
        if not folded:
            continue
        if not folded.startswith("/"):
            folded = "/" + folded
        rule = tuple(segment for segment in folded.split("/") if segment)
        if rule:
            rules.append(rule)
    return rules


def _configured_prefixes():
    configured = os.environ.get(_PREFIXES_ENV_VAR)
    if configured is None:
        return DEFAULT_BLOCKED_PREFIXES
    return tuple(item for item in configured.split(",") if item.strip())


def is_sensitive_path(path, blocked_prefixes=None):
    """Return True when a normalized path matches a blocked prefix rule."""
    if blocked_prefixes is None:
        blocked_prefixes = _configured_prefixes()
    rules = _normalize_prefixes(blocked_prefixes)
    segments = tuple(segment for segment in path.split("/") if segment)
    return any(segments[: len(rule)] == rule for rule in rules)


def _is_intranet(client_ip):
    if client_ip is None:
        return False
    if not isinstance(client_ip, str):
        raise TypeError("client_ip must be a string")
    return ip_address(client_ip).is_private


def validate(value, client_ip=None, is_admin=False, blocked_prefixes=None):
    """Validate a request path and enforce endpoint exposure policy.

    Raises :class:`TypeError` for non-string input, :class:`ValueError`
    (via :class:`PathValidationError`) for malformed paths or blocked
    endpoints reached from a public network.  Returns the normalized path
    when the request is allowed.
    """
    normalized = normalize_path(value)
    if is_sensitive_path(normalized, blocked_prefixes):
        if is_admin or _is_intranet(client_ip):
            return normalized
        raise PathValidationError(
            "debug/environment endpoint is not allowed from public networks"
        )
    return normalized
