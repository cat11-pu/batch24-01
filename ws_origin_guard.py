from urllib.parse import urlsplit

SECURE_SCHEMES = ("https",)

_CONTROL_OR_WHITESPACE = frozenset(
    [chr(code) for code in range(0x21)] + [chr(0x7F)]
)


def _reject():
    raise ValueError("WebSocket handshake rejected: invalid Origin or Host header")


def _contains_forbidden_char(value):
    return any(char in _CONTROL_OR_WHITESPACE for char in value)


def _host_header_name(host):
    if host.startswith("["):
        closing = host.find("]")
        if closing <= 1:
            _reject()
        name = host[1:closing]
        tail = host[closing + 1:]
        if tail:
            if not tail.startswith(":") or not tail[1:].isdigit():
                _reject()
            _check_port(tail[1:])
        return name.lower()

    if ":" in host:
        name, port = host.rsplit(":", 1)
        if not port.isdigit():
            _reject()
        _check_port(port)
        return name.lower()

    return host.lower()


def _check_port(port_text):
    try:
        port = int(port_text)
    except ValueError:
        _reject()
    if not 1 <= port <= 65535:
        _reject()


def check_handshake(origin, host, allowed_origins):
    if not isinstance(origin, str) or not origin:
        _reject()
    if _contains_forbidden_char(origin):
        _reject()

    parsed = urlsplit(origin)

    if parsed.scheme not in SECURE_SCHEMES:
        _reject()
    if not parsed.hostname:
        _reject()
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        _reject()

    try:
        port = parsed.port
    except ValueError:
        _reject()
    if port is not None:
        _reject()

    if parsed.path or parsed.query or parsed.fragment:
        _reject()
    if parsed.netloc != parsed.netloc.lower():
        _reject()

    try:
        allowed = set(allowed_origins)
    except TypeError:
        _reject()
    if origin not in allowed:
        _reject()

    if not isinstance(host, str) or not host:
        _reject()
    if _contains_forbidden_char(host) or "@" in host:
        _reject()

    if _host_header_name(host) != parsed.hostname:
        _reject()

    return True
