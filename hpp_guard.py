from urllib.parse import unquote_to_bytes

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_FORBIDDEN_CHARS = frozenset(";\x00\r\n\ufeff?#")
_FORBIDDEN_DECODED = (b"\x00", b"\r", b"\n", b"\xef\xbb\xbf")


def _validate(qs):
    if not isinstance(qs, str):
        raise ValueError("query string must be a str")
    for ch in qs:
        if ch in _FORBIDDEN_CHARS:
            raise ValueError("forbidden character %r in query string" % ch)
    i = 0
    n = len(qs)
    while i < n:
        if qs[i] == "%":
            if i + 2 >= n or qs[i + 1] not in _HEX_DIGITS or qs[i + 2] not in _HEX_DIGITS:
                raise ValueError("invalid percent-encoding in query string")
            i += 3
        else:
            i += 1


def _normalize_key(raw_key):
    decoded = unquote_to_bytes(raw_key.replace("+", " "))
    _check_decoded(decoded)
    base = decoded.split(b"[", 1)[0]
    if not base:
        raise ValueError("empty key in query string")
    return base


def _check_decoded(decoded):
    for token in _FORBIDDEN_DECODED:
        if token in decoded:
            raise ValueError("forbidden encoded character in query string")


def parse_query(qs):
    _validate(qs)
    out = {}
    if not qs:
        return out
    seen = set()
    for part in qs.split("&"):
        if "=" in part:
            key, value = part.split("=", 1)
        else:
            key, value = part, None
        norm = _normalize_key(key)
        if norm in seen:
            raise ValueError("duplicate key in query string")
        seen.add(norm)
        if value is not None:
            _check_decoded(unquote_to_bytes(value.replace("+", " ")))
            out[key] = value
    return out
