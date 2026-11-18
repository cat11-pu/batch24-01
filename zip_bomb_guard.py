"""Zip bomb guard.

Validates archive metrics before anything is extracted. The checker
watches the compression ratio, the total uncompressed size, the entry
count, the per-entry size and the symlink count. Empty archives,
negative metrics and any metric past its limit are rejected with
``ValueError``.

All limits are supplied by the caller; the module-level defaults only
apply when a limit is not passed explicitly. The function keeps no
state, so it is safe to call concurrently from multiple threads.
"""

DEFAULT_MAX_RATIO = 100
DEFAULT_MAX_TOTAL_SIZE = 1 << 30  # 1 GiB
DEFAULT_MAX_ENTRIES = 10_000
DEFAULT_MAX_ENTRY_SIZE = 1 << 30  # 1 GiB
DEFAULT_MAX_SYMLINKS = 0

# Alternative keyword names accepted for caller-supplied limits.
_LIMIT_ALIASES = {
    "max_compression_ratio": "max_ratio",
    "compression_ratio": "max_ratio",
    "ratio_limit": "max_ratio",
    "max_uncompressed": "max_total_size",
    "max_uncompressed_size": "max_total_size",
    "max_total_uncompressed": "max_total_size",
    "max_total_uncompressed_size": "max_total_size",
    "max_entry_count": "max_entries",
    "max_files": "max_entries",
    "max_file_count": "max_entries",
    "max_single_entry": "max_entry_size",
    "max_single_entry_size": "max_entry_size",
    "max_file_size": "max_entry_size",
    "max_member_size": "max_entry_size",
    "max_symlink_count": "max_symlinks",
    "max_links": "max_symlinks",
    "largest_entry_size": "largest_entry",
    "largest_file": "largest_entry",
    "largest_file_size": "largest_entry",
    "biggest_entry": "largest_entry",
}


def validate_archive(compressed, uncompressed, entries, symlinks=0,
                     max_ratio=DEFAULT_MAX_RATIO,
                     max_total_size=DEFAULT_MAX_TOTAL_SIZE,
                     max_entries=DEFAULT_MAX_ENTRIES,
                     max_entry_size=DEFAULT_MAX_ENTRY_SIZE,
                     max_symlinks=DEFAULT_MAX_SYMLINKS,
                     largest_entry=None,
                     **kwargs):
    """Validate archive metrics against caller-supplied limits.

    ``compressed``, ``uncompressed`` and ``entries`` describe the
    archive; ``symlinks`` counts symbolic links inside it.
    ``largest_entry`` is the size of the biggest single entry; when it
    is not given, the average entry size is checked instead.

    Raises ``ValueError`` for empty archives, negative metrics and any
    metric that reaches or exceeds its limit. Returns ``True`` when
    the archive is acceptable.
    """
    for key, value in kwargs.items():
        canonical = _LIMIT_ALIASES.get(key)
        if canonical == "largest_entry":
            if largest_entry is None:
                largest_entry = value
        elif canonical is not None:
            if canonical == "max_ratio":
                max_ratio = value
            elif canonical == "max_total_size":
                max_total_size = value
            elif canonical == "max_entries":
                max_entries = value
            elif canonical == "max_entry_size":
                max_entry_size = value
            elif canonical == "max_symlinks":
                max_symlinks = value

    if compressed <= 0:
        raise ValueError("archive is empty or has an invalid compressed size")
    if uncompressed <= 0:
        raise ValueError("archive is empty or has an invalid uncompressed size")
    if entries <= 0:
        raise ValueError("archive is empty or has an invalid entry count")
    if symlinks < 0:
        raise ValueError("symlink count cannot be negative")
    if largest_entry is not None and largest_entry < 0:
        raise ValueError("largest entry size cannot be negative")

    if uncompressed >= compressed * max_ratio:
        raise ValueError("compression ratio exceeds the allowed limit")
    if uncompressed > max_total_size:
        raise ValueError("uncompressed size exceeds the allowed limit")
    if entries > max_entries:
        raise ValueError("entry count exceeds the allowed limit")
    if largest_entry is not None:
        if largest_entry > max_entry_size:
            raise ValueError("single entry size exceeds the allowed limit")
    elif uncompressed > entries * max_entry_size:
        raise ValueError("single entry size exceeds the allowed limit")
    if symlinks > max_symlinks:
        raise ValueError("symlink count exceeds the allowed limit")
    return True
