"""Reverse-proxy Host header validation and cache-key normalization."""

import ipaddress
import os
import re

DEFAULT_ALLOWED_HOSTS = ("api.example.com",)

_ALLOWED_HOSTS_ENV = "ALLOWED_HOSTS"
_STANDARD_PORTS = frozenset({80, 443})
_MAX_HOST_LENGTH = 253
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _default_allowed_hosts():
    raw = os.environ.get(_ALLOWED_HOSTS_ENV, "")
    hosts = tuple(h.strip().lower() for h in raw.split(",") if h.strip())
    return hosts or DEFAULT_ALLOWED_HOSTS


def _is_ip_literal(name):
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        pass
    if name and all(c.isdigit() or c == "." for c in name):
        return True
    return False


def normalize_host(host):
    """Return the canonical form of *host*, rejecting anything malformed."""
    if not isinstance(host, str):
        raise TypeError("host must be a str, not %s" % type(host).__name__)
    if not host:
        raise ValueError("host must not be empty")
    if len(host) > _MAX_HOST_LENGTH:
        raise ValueError("host exceeds %d characters" % _MAX_HOST_LENGTH)
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in host):
        raise ValueError("host contains whitespace or control characters")

    candidate = host.lower()

    if ":" in candidate:
        name, _, port = candidate.partition(":")
        if (
            not port
            or not port.isdigit()
            or ":" in port
            or int(port) not in _STANDARD_PORTS
        ):
            raise ValueError("only standard ports 80/443 are allowed")
        candidate = name

    if (
        not candidate
        or candidate.startswith(".")
        or candidate.endswith(".")
        or ".." in candidate
    ):
        raise ValueError("host has empty labels")

    labels = candidate.split(".")
    for label in labels:
        if not _LABEL_RE.fullmatch(label):
            raise ValueError("invalid label %r in host" % label)
    if labels[-1].isdigit():
        raise ValueError("numeric TLD is not allowed")
    if _is_ip_literal(candidate):
        raise ValueError("IP literals are not allowed")

    return candidate


def validate_host(host, allowed_hosts=None):
    """Validate *host* against the whitelist; return True when allowed."""
    normalized = normalize_host(host)
    if allowed_hosts is None:
        allowed = _default_allowed_hosts()
    else:
        allowed = tuple(
            entry.strip().lower()
            for entry in allowed_hosts
            if isinstance(entry, str)
        )
    if normalized not in allowed:
        raise ValueError("host %r is not in the allowed hosts" % normalized)
    return True


def build_cache_key(host, path):
    normalized = normalize_host(host)
    validate_host(normalized)
    return normalized + path
