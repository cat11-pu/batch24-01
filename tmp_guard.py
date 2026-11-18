"""TOCTOU-safe temporary-file guard.

The guard never performs a separate "check then open" step.  Inputs are
validated purely in memory and the only filesystem operation is a single
atomic ``open(2)`` call carrying ``O_CREAT | O_EXCL`` (plus ``O_NOFOLLOW``
where the platform supports it), so the existence check and the creation
happen inside the kernel with no window in which an attacker can swap the
path.
"""

import os

# Only exclusive-creation modes are accepted.  Every mode here maps to an
# open(2) flag set that always contains O_CREAT | O_EXCL and never O_APPEND
# or O_TRUNC, so an existing path can never be modified.
_VALID_EXCLUSIVE_MODES = frozenset(
    ("x", "xb", "bx", "xt", "tx", "x+", "+x", "xb+", "x+b", "bx+", "b+x",
     "+xb", "+bx", "xt+", "x+t", "tx+", "t+x", "+xt", "+tx")
)

# Characters that are legal inside an exclusive-create mode string.
_ALLOWED_MODE_CHARS = frozenset("xwbat+")


def _split_args(path, mode):
    """Support both validate(path, mode) and validate((path, mode))."""
    if mode is None:
        try:
            path, mode = path
        except (TypeError, ValueError) as exc:
            raise TypeError(
                "validate expects (path, mode), either as two arguments or "
                "as a single (path, mode) sequence"
            ) from exc
    return path, mode


def _validate_mode(mode):
    if not isinstance(mode, str):
        raise TypeError("mode must be a string")
    if not mode:
        raise ValueError("mode must not be empty")
    if "\x00" in mode:
        raise ValueError("mode must not contain NUL bytes")
    if mode != mode.strip() or any(ch in mode for ch in ("\n", "\r", "\t")):
        raise ValueError("mode must not contain whitespace or control bytes")
    if any(ch not in _ALLOWED_MODE_CHARS for ch in mode):
        raise ValueError("unsupported mode %r" % mode)
    if "a" in mode or "r" in mode or "w" in mode:
        raise ValueError(
            "only exclusive creation (mode containing 'x') is allowed; "
            "read, write-truncate and append modes are rejected"
        )
    if mode.count("x") != 1:
        raise ValueError("mode must contain exactly one exclusive 'x' flag")
    if mode not in _VALID_EXCLUSIVE_MODES:
        raise ValueError("unsupported mode %r" % mode)
    return mode


def _build_open_flags(mode):
    if "+" in mode:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if "b" not in mode:
        text_flag = getattr(os, "O_TEXT", 0)
        if text_flag:
            flags |= text_flag
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is not None:
        flags |= nofollow
    return flags


def _validate_path(path):
    if not isinstance(path, str):
        raise TypeError("path must be a string")
    if not path:
        raise ValueError("path must not be empty")
    if "\x00" in path:
        raise ValueError("path must not contain NUL bytes")
    if os.path.isabs(path):
        raise ValueError("absolute paths are not allowed")
    if any(part == ".." for part in path.split(os.sep)):
        raise ValueError("path traversal segments are not allowed")
    normalized = os.path.normpath(path)
    if normalized == ".." or normalized.startswith(".." + os.sep) or (
        os.sep + ".." + os.sep in normalized
    ) or normalized.endswith(os.sep + ".."):
        raise ValueError("path traversal segments are not allowed")
    if any(part == ".." for part in normalized.split(os.sep)):
        raise ValueError("path traversal segments are not allowed")
    return normalized


def validate(path, mode=None):
    """Atomically create a temporary file or raise.

    Accepted modes are the exclusive-creation family (``x``, ``xb``, ``xt``,
    ``x+`` and their letter permutations).  Append, plain write/truncate,
    read, empty/illegal modes, empty or NUL-bearing paths, absolute paths and
    ``..`` traversal are rejected before any syscall.  The file is then
    created with ``O_CREAT | O_EXCL`` (and ``O_NOFOLLOW`` when available), so
    an existing file or a swapped-in symlink makes the single atomic open
    fail with :class:`FileExistsError`.

    Returns the open file descriptor; the caller owns it and must call
    :func:`os.close` when done.
    """
    path, mode = _split_args(path, mode)
    mode = _validate_mode(mode)
    safe_path = _validate_path(path)
    return os.open(safe_path, _build_open_flags(mode), 0o600)
