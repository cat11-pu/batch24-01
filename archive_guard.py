import os
import re
import urllib.parse

_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _check_components(candidate):
    if candidate.startswith(("/", "\\")):
        raise ValueError("absolute path entry is not allowed")
    if _DRIVE_RE.match(candidate) or ":" in candidate:
        raise ValueError("drive/UNC style entry is not allowed")
    if "\x00" in candidate:
        raise ValueError("null byte in entry name")
    normalized = candidate.replace("\\", "/")
    for part in normalized.split("/"):
        if part in ("", "."):
            continue
        if set(part) == {"."}:
            raise ValueError("parent traversal in entry name")


def validate_entry(name, dest, is_symlink=False):
    if not isinstance(name, str):
        raise TypeError("entry name must be a string")
    if not isinstance(dest, str):
        raise TypeError("destination must be a string")
    if is_symlink:
        raise ValueError("symbolic link entries are not allowed")
    if not name:
        raise ValueError("empty entry name")

    decoded = name
    for _ in range(8):
        unquoted = urllib.parse.unquote(decoded)
        if unquoted == decoded:
            break
        decoded = unquoted

    _check_components(name)
    _check_components(decoded)

    parts = [
        part
        for part in decoded.replace("\\", "/").split("/")
        if part not in ("", ".")
    ]
    if not parts:
        raise ValueError("entry name has no usable path components")

    dest_real = os.path.realpath(dest)
    target = os.path.realpath(os.path.join(dest_real, *parts))
    if target != dest_real and os.path.commonpath((dest_real, target)) != dest_real:
        raise ValueError("entry escapes the destination directory")
    return target
