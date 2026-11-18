import os
import re
import stat

MAX_PATH_LENGTH = 255
MAX_NAME_LENGTH = 255
WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _fail(message):
    raise ValueError(message)


def validate(value, base_dir=None):
    """Validate a user-supplied relative path before touching the filesystem.

    The path must:
      * be a non-empty, non-whitespace ``str`` without NUL bytes or control
        characters;
      * be relative (no POSIX absolute paths, Windows drives or UNC paths);
      * contain no ``..`` traversal components and stay within the length
        limits;
      * resolve, when it exists, to a regular file located strictly inside
        ``base_dir``, with no symbolic link anywhere in the path.

    On success the validated absolute path is returned.
    """
    if value is None:
        raise TypeError("path value must not be None")
    if not isinstance(value, str):
        raise TypeError("path value must be a string, got %s" % type(value).__name__)
    if value == "":
        _fail("path value must not be empty")
    if "\x00" in value:
        _fail("path value must not contain NUL bytes")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        _fail("path value must not contain control characters")
    if value != value.strip():
        _fail("path value must not have leading or trailing whitespace")
    if len(value) > MAX_PATH_LENGTH:
        _fail("path value exceeds maximum length of %d" % MAX_PATH_LENGTH)
    if value.startswith(("/", "\\")):
        _fail("absolute paths are not allowed")
    if os.path.isabs(value):
        _fail("absolute paths are not allowed")
    if WINDOWS_DRIVE_RE.match(value):
        _fail("drive-qualified paths are not allowed")

    drive, tail = os.path.splitdrive(value)
    if drive or tail.startswith(("/", "\\")):
        _fail("absolute or drive-qualified paths are not allowed")

    normalized = value.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts:
        _fail("path value must name a file inside the target directory")
    if any(part == ".." for part in parts):
        _fail("path traversal ('..') is not allowed")
    if any(len(part) > MAX_NAME_LENGTH for part in parts):
        _fail("path component exceeds maximum length of %d" % MAX_NAME_LENGTH)

    if base_dir is None:
        base_dir = os.getcwd()
    base_dir = os.path.realpath(base_dir)
    if not os.path.isdir(base_dir):
        _fail("base directory does not exist: %s" % base_dir)

    candidate = os.path.abspath(os.path.join(base_dir, *parts))
    try:
        walked = base_dir
        last_stat = None
        for part in parts:
            walked = os.path.join(walked, part)
            last_stat = os.lstat(walked)
            if stat.S_ISLNK(last_stat.st_mode):
                _fail("symbolic links are not allowed: %s" % walked)
    except FileNotFoundError:
        last_stat = None
    except OSError as exc:
        _fail("cannot inspect path %s: %s" % (walked, exc))

    try:
        if os.path.commonpath([base_dir, walked]) != base_dir:
            _fail("path escapes the target directory")
    except ValueError:
        _fail("path is not contained in the target directory")

    if last_stat is not None:
        if not stat.S_ISREG(last_stat.st_mode):
            _fail("only regular files inside the target directory are allowed")

    return candidate


def safe_open(value, base_dir=None, mode="wb"):
    """Open a validated path while refusing symbolic links atomically.

    ``validate`` alone cannot close the time-of-check/time-of-use window in
    which an attacker swaps a regular file for a symlink.  ``O_NOFOLLOW``
    makes the kernel reject the open if the final component is a link, so the
    returned file object can never write through a symlink.
    """
    path = validate(value, base_dir=base_dir)
    flag_map = {
        "rb": os.O_RDONLY,
        "r+b": os.O_RDWR,
        "wb": os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        "ab": os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        "xb": os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    }
    if mode not in flag_map:
        _fail("unsupported mode %r; use one of %s" % (mode, sorted(flag_map)))
    flags = os.O_NOFOLLOW | os.O_CLOEXEC | flag_map[mode]
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        _fail("refusing to open unsafe path %s: %s" % (path, exc))
    return os.fdopen(descriptor, mode)
