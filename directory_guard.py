import re
import unicodedata
from urllib.parse import unquote_to_bytes


MAX_PATH_LENGTH = 255
_MAX_DECODE_PASSES = 8
_ENCODED_SEPARATOR = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


def _has_only_valid_escapes(value):
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if index + 2 >= len(value):
            return False
        if not all(char in "0123456789abcdefABCDEF" for char in value[index + 1:index + 3]):
            return False
        index += 3
    return True


def _decode_path(value):
    current = value
    for _ in range(_MAX_DECODE_PASSES):
        if _ENCODED_SEPARATOR.search(current):
            raise ValueError("encoded path separator is not allowed")
        if not _has_only_valid_escapes(current):
            raise ValueError("malformed percent escape")
        try:
            decoded = unquote_to_bytes(current).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("path is not valid UTF-8") from exc
        if decoded == current:
            return current
        current = decoded
    raise ValueError("path uses too many encoding layers")


def _reject_unsafe_characters(value):
    for char in value:
        if unicodedata.category(char) == "Cc":
            raise ValueError("control characters are not allowed")


def _reject_unsafe_segment(segment):
    if not segment:
        raise ValueError("empty path segment is not allowed")
    if "\\" in segment:
        raise ValueError("backslashes are not allowed")

    normalized = segment.split(";", 1)[0].strip()
    if normalized in (".", ".."):
        raise ValueError("relative path segments are not allowed")
    if normalized.rstrip(" .") == "":
        raise ValueError("directory-only path segment is not allowed")
    if _DRIVE_PREFIX.match(normalized):
        raise ValueError("drive-qualified paths are not allowed")


def validate(value):
    if not isinstance(value, str):
        raise TypeError("path must be a string")
    if not value or not value.strip():
        raise ValueError("path must not be empty")
    if value != value.strip():
        raise ValueError("path must not have surrounding whitespace")
    if len(value) > MAX_PATH_LENGTH:
        raise ValueError("path is too long")

    _reject_unsafe_characters(value)

    path = value.split("#", 1)[0].split("?", 1)[0]
    if not path or not path.strip() or path != path.strip():
        raise ValueError("path must not be empty")

    decoded = _decode_path(path)
    if len(decoded) > MAX_PATH_LENGTH:
        raise ValueError("path is too long")
    _reject_unsafe_characters(decoded)

    if "\\" in decoded:
        raise ValueError("backslashes are not allowed")
    if "//" in decoded:
        raise ValueError("duplicate slashes are not allowed")
    if decoded.endswith("/"):
        raise ValueError("directory requests are not allowed")

    segments = decoded.split("/")
    if decoded.startswith("/"):
        segments = segments[1:]
    for segment in segments:
        _reject_unsafe_segment(segment)

    return True
