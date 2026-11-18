from urllib.parse import unquote, urlsplit

_FORBIDDEN_CHARS = frozenset(chr(code) for code in range(0x20)) | {"\x7f", "\\"}


def safe_redirect(target, allowed_hosts):
    if not isinstance(target, str) or not target:
        raise ValueError("redirect target must be a non-empty string")
    if any(char in _FORBIDDEN_CHARS for char in target):
        raise ValueError("redirect target contains forbidden characters")
    if target != target.strip():
        raise ValueError("redirect target has surrounding whitespace")

    lowered = target.lower()
    if "%0d" in lowered or "%0a" in lowered or "%00" in lowered:
        raise ValueError("redirect target contains encoded control characters")

    parts = urlsplit(target)

    if parts.scheme:
        if parts.scheme.lower() != "https":
            raise ValueError("only https URLs are allowed")
        if not parts.netloc:
            raise ValueError("absolute URL must include a host")
    elif parts.netloc:
        raise ValueError("protocol-relative URLs are not allowed")

    if parts.netloc:
        if parts.username is not None or parts.password is not None:
            raise ValueError("userinfo is not allowed")
        try:
            port = parts.port
        except ValueError:
            raise ValueError("invalid port") from None
        if port is not None and port != 443:
            raise ValueError("non-standard port is not allowed")
        if port is not None:
            host = parts.netloc[: parts.netloc.rfind(":")]
        else:
            host = parts.netloc
        if host.endswith("."):
            raise ValueError("trailing dot in host is not allowed")
        if host not in allowed_hosts:
            raise ValueError("host is not in the allowlist")

    decoded_path = unquote(parts.path)
    if any(char in _FORBIDDEN_CHARS for char in decoded_path):
        raise ValueError("redirect path contains forbidden characters")
    if ".." in decoded_path.split("/"):
        raise ValueError("parent directory references are not allowed")

    return target
