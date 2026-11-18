"""Strict validation for JSON documents accepted by the guard entry point."""

import json
import math


MAX_INPUT_BYTES = 1_000_000
MAX_DEPTH = 64


def _reject_constant(token):
    raise ValueError(f"non-standard JSON constant: {token}")


def _parse_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("JSON number is outside the finite range")
    return value


def _object_from_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        if "\x00" in key:
            raise ValueError("NUL character is not allowed in JSON keys")
        result[key] = value
    return result


def _check_depth(text):
    depth = 0
    in_string = False
    escaped = False

    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("JSON nesting is too deep")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced JSON structure")


def _check_no_nul(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if "\x00" in item:
                raise ValueError("NUL character is not allowed in JSON values")
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def validate(value):
    """Return ``True`` for one valid, bounded JSON document.

    Invalid or unsafe input raises :class:`ValueError`.
    """

    if not isinstance(value, str):
        raise ValueError("JSON input must be a string")

    if len(value) > MAX_INPUT_BYTES:
        raise ValueError("JSON input is too large")

    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("JSON input contains invalid Unicode") from exc
    if len(encoded) > MAX_INPUT_BYTES:
        raise ValueError("JSON input is too large")

    if value.lstrip(" \t\r\n").startswith("\ufeff"):
        raise ValueError("UTF-8 BOM is not allowed")
    if "\x00" in value:
        raise ValueError("NUL character is not allowed")

    _check_depth(value)

    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise ValueError("JSON nesting is too deep") from exc

    _check_no_nul(parsed)
    return True
