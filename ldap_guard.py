_ESCAPED_CHARS = {
    "\x00": r"\00",
    "(": r"\28",
    ")": r"\29",
    "*": r"\2a",
    "\\": r"\5c",
}


def escape_filter(value):
    """Escape a value for safe use inside an RFC 4515 LDAP filter."""
    if not isinstance(value, str):
        raise TypeError("LDAP filter value must be a string")
    if not value:
        raise ValueError("LDAP filter value must not be empty")

    value.encode("utf-8")
    escaped = []
    for char in value:
        replacement = _ESCAPED_CHARS.get(char)
        if replacement is None:
            codepoint = ord(char)
            if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
                replacement = "".join(
                    f"\\{byte:02x}" for byte in char.encode("utf-8")
                )
            else:
                replacement = char
        escaped.append(replacement)

    return "".join(escaped)
