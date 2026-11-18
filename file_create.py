import os

# Owner-only permission values: read+write, read-only and write-only.
# Anything granting group/other access is refused.
ALLOWED_MODES = frozenset({0o600, 0o400, 0o200})

# Single file-name component limit on typical POSIX file systems (NAME_MAX).
MAX_NAME_BYTES = 255


def create_file(base, name, data, mode=0o600):
    """Atomically create a new file under *base* without following links.

    The file name must be a single safe path component: it is reduced to its
    ``basename`` and anything containing parent references, absolute paths,
    directory separators, NUL bytes or an over-long component is refused.
    Creation uses ``O_CREAT | O_EXCL | O_NOFOLLOW`` so an existing target
    (including a symlink) is never overwritten or followed, and *mode* must be
    an owner-only permission from :data:`ALLOWED_MODES`.

    Choosing a trusted *base* directory and the permission policy is the
    caller's responsibility.

    Returns the on-disk path of the newly created file.
    Raises ``ValueError`` for invalid arguments or failed atomic creation.
    """
    if not isinstance(data, bytes):
        raise ValueError("data must be bytes")

    # bool is a subclass of int, but True/False are not permission values.
    if isinstance(mode, bool) or not isinstance(mode, int):
        raise ValueError("mode must be an integer permission value")
    if mode not in ALLOWED_MODES:
        raise ValueError("mode %o is not in the allowed permission whitelist" % mode)

    base_dir = os.fspath(base)
    if not os.path.isdir(base_dir):
        raise ValueError("base must be an existing directory")

    if not isinstance(name, str):
        raise ValueError("name must be a string file name")

    leaf = os.path.basename(name)
    if (
        not name
        or leaf != name
        or leaf in (".", "..")
        or os.sep in name
        or (os.altsep is not None and os.altsep in name)
        or "\x00" in name
    ):
        raise ValueError("name must be a single safe file-name component")

    if len(os.fsencode(leaf)) > MAX_NAME_BYTES:
        raise ValueError("file name exceeds %d bytes" % MAX_NAME_BYTES)

    if isinstance(base_dir, bytes):
        leaf = os.fsencode(leaf)
    target = os.path.join(base_dir, leaf)

    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(target, flags, mode)
    except OSError as exc:
        # Covers an existing regular file, an existing symlink and races.
        raise ValueError(
            "refusing to create %s: %s" % (target, exc.strerror or exc)
        ) from exc

    try:
        # Enforce the exact mode regardless of the process umask.
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(target)
        except OSError:
            pass
        raise
    else:
        os.close(fd)

    return target
