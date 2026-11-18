"""Safety checks for tar entries before extraction.

A tar entry is described by ``(name, type, linkname)``:

* ``name``     -- path stored in the archive header;
* ``type``     -- entry kind, e.g. ``file``/``dir``/``symlink``/``hardlink``
                  or the device kinds ``char``/``block``;
* ``linkname`` -- target of a link entry (empty for other kinds).

Only plain files and directories with safe, in-tree paths are accepted.
Absolute links, links containing ``..``, device nodes and any entry whose
resolved location would escape the extraction directory are rejected with
``ValueError`` (or ``TypeError`` for non-string fields).
"""

import re

# Maximum component/path length we are willing to trust. 255 matches the
# common file-system name limit; tar's own name/linkname fields are 100 bytes
# without the GNU/PAX extensions, so 255 keeps both comfortably bounded.
MAX_NAME_LENGTH = 255

# Windows drive prefix such as "C:\\..." or "C:/...".
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")

_REGULAR_TYPES = frozenset(("file", "dir", "directory"))
_DEVICE_TYPES = frozenset(("char", "block", "fifo", "device"))
_LINK_TYPES = frozenset(("symlink", "hardlink", "link"))


def _is_absolute(path):
    """True for POSIX absolute paths and Windows-style absolute paths."""
    if path.startswith(("/", "\\")):
        return True
    if _WINDOWS_DRIVE.match(path):
        return True
    # UNC path such as "\\\\server\\share".
    if path.startswith(("\\\\", "//")):
        return True
    return False


def _escapes_directory(path):
    """Check whether a *relative* path leaves its base directory.

The check is purely lexical and works on both POSIX and Windows style
separators, so it cannot be fooled by mixing ``/`` and ``\\``. It also
detects the classic prefix tricks (``a/../../etc``).
"""
    normalized = path.replace("\\", "/")
    depth = 0
    for component in normalized.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


def _check_path(value, field, allow_empty=False):
    """Validate an entry name or link target string."""
    if not isinstance(value, str):
        raise TypeError("tar entry %s must be a string, got %r" % (field, value))
    if value == "":
        if allow_empty:
            return
        raise ValueError("tar entry %s must not be empty" % field)
    if "\x00" in value:
        raise ValueError("tar entry %s contains a NUL byte: %r" % (field, value))
    if len(value) > MAX_NAME_LENGTH:
        raise ValueError(
            "tar entry %s is too long (%d > %d bytes)"
            % (field, len(value), MAX_NAME_LENGTH)
        )
    if _is_absolute(value):
        raise ValueError("tar entry %s is an absolute path: %r" % (field, value))
    if _escapes_directory(value):
        raise ValueError(
            "tar entry %s escapes the target directory via '..': %r"
            % (field, value)
        )


def validate(value, type_=None, linkname=None):
    """Validate one tar entry.

Supports both ``validate((name, type, linkname))`` (a single 3-tuple/list)
and ``validate(name, type, linkname)``. Raises ``ValueError``/``TypeError``
    for anything unsafe and returns ``True`` for entries that may be
extracted.
"""
    if type_ is None and linkname is None:
        try:
            name, entry_type, entry_link = value
        except (TypeError, ValueError) as exc:
            raise TypeError(
                "validate expects a (name, type, linkname) triple"
            ) from exc
    else:
        name, entry_type, entry_link = value, type_, "" if linkname is None else linkname

    if not isinstance(entry_type, str):
        raise TypeError("tar entry type must be a string, got %r" % (entry_type,))

    # Link targets are validated for every entry type, not only links, so a
    # corrupt linkname field can never slip through on a regular file.
    _check_path(entry_link, "linkname", allow_empty=True)

    # Reject device/fifo nodes first: creating them must never happen during
    # an untrusted extraction, regardless of the name.
    if entry_type in _DEVICE_TYPES:
        raise ValueError("device entries are not permitted: %r" % (entry_type,))

    # Symlinks and hardlinks can be used to redirect later writes outside the
    # extraction root. Validate the target first (empty/absolute/.. targets
    # get a precise error), then reject the link type outright: only regular
    # files and directories are allowed to be extracted.
    if entry_type in _LINK_TYPES:
        _check_path(entry_link, "linkname")
        raise ValueError("link entries are not permitted: %r" % (entry_type,))

    # Only plain files and directories past this point.
    if entry_type not in _REGULAR_TYPES:
        raise ValueError("unsupported tar entry type: %r" % (entry_type,))

    _check_path(name, "name")

    return True
