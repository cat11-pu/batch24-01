import ipaddress
import os
import re
import unicodedata

# Canonical dotted-quad only: exactly four ASCII octets, no leading zeros,
# no abbreviations, no alternate radixes, no ports, no CIDR suffix.
_DOTTED_QUAD = re.compile(r"\A(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\Z")

_ALLOWLIST_ENV_VARS = ("IP_ALLOW_LIST", "IP_ALLOWLIST", "IP_WHITELIST")


def _has_whitespace_or_control(value):
    for char in value:
        if char.isspace() or unicodedata.category(char).startswith("C"):
            return True
    return False


def _parse_canonical_ipv4(value):
    if not isinstance(value, str):
        raise TypeError("IP address must be a string")
    if not value or _has_whitespace_or_control(value):
        raise ValueError("IP address contains whitespace or control characters")

    parts = value.split(".")
    if len(parts) != 4 or not all(_DOTTED_QUAD.fullmatch(part) for part in parts):
        raise ValueError("IP address is not a canonical dotted-quad IPv4: %r" % value)

    address = ipaddress.IPv4Address(value)
    if str(address) != value:
        raise ValueError("IP address is not in canonical form: %r" % value)
    return address


def _allowed_networks():
    raw = None
    for env_name in _ALLOWLIST_ENV_VARS:
        raw = os.environ.get(env_name)
        if raw:
            break
    if not raw:
        raise ValueError("IP allowlist is not configured")

    networks = []
    for entry in raw.split(","):
        entry = entry.strip()
        if entry:
            networks.append(ipaddress.IPv4Network(entry, strict=False))
    if not networks:
        raise ValueError("IP allowlist is empty")
    return networks


def validate(value):
    address = _parse_canonical_ipv4(value)
    if not any(address in network for network in _allowed_networks()):
        raise ValueError("IP address is not in the allowlist: %s" % value)
    return True
