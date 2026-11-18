"""Validation for URLs that may be used as cache keys.

Static files are served from the same origin as private pages.  A path with an
asset suffix is therefore cached by the static-asset rule, even if the
application router would serve a private page for that path.  Only
canonical, non-asset paths are considered safe.
"""

_STATIC_SUFFIXES = frozenset(
    {
        ".avif",
        ".bmp",
        ".cjs",
        ".css",
        ".eot",
        ".gif",
        ".gz",
        ".htm",
        ".html",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".json",
        ".map",
        ".mjs",
        ".mp3",
        ".mp4",
        ".ogg",
        ".otf",
        ".pdf",
        ".png",
        ".svg",
        ".tar",
        ".ttf",
        ".txt",
        ".wasm",
        ".wav",
        ".webm",
        ".webp",
        ".woff",
        ".woff2",
        ".xhtml",
        ".xml",
        ".zip",
    }
)


def _normalize(value):
    if not isinstance(value, str):
        raise TypeError("cache key must be a string")
    if not value:
        raise ValueError("cache key must not be empty")

    # Reject all percent escapes.  Decoding only some of them leaves the cache
    # key and the router with different interpretations of the same URL.
    if "%" in value:
        raise ValueError("percent-encoded characters are not allowed")

    if not value.isascii():
        raise ValueError("cache keys must use canonical ASCII characters")

    if not value.startswith("/") or value.startswith("//"):
        raise ValueError("cache key must be a single-rooted absolute path")
    if "//" in value:
        raise ValueError("duplicate path separators are not allowed")
    if "\\" in value:
        raise ValueError("backslashes are not allowed in a URL path")
    if ";" in value:
        raise ValueError("path parameters are not allowed")
    if "?" in value or "#" in value:
        raise ValueError("query strings and fragments are not allowed")

    for char in value:
        if char.isspace() or not char.isprintable():
            raise ValueError("control, whitespace, or format characters are not allowed")

    return value


def _has_static_suffix(path):
    for segment in path.split("/"):
        if not segment:
            continue
        segment = segment.lower()
        dot = segment.rfind(".")
        if dot >= 0 and segment[dot:] in _STATIC_SUFFIXES:
            return True
    return False


def validate(value):
    """Return ``True`` for a safe cache key; raise for an unsafe one."""

    path = _normalize(value)

    # Removing the leading slash leaves exactly the real path segments.  A
    # dot segment can make the cache and the application router resolve
    # different resources, so every such segment is rejected.
    remainder = path[1:]
    if path != "/":
        remainder = remainder.rstrip("/")
        for segment in remainder.split("/"):
            if not segment or segment in {".", ".."} or segment.endswith("."):
                raise ValueError("dot segments are not allowed")

    if _has_static_suffix(path):
        raise ValueError("static asset suffixes are not cacheable as private pages")

    return True
