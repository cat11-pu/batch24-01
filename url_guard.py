from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _parse_ip_literal(host):
    """Return an ipaddress object if host is an IP literal, else None.

    Handles dotted-quad, IPv6, and legacy forms such as decimal
    (2130706433), hex (0x7f000001), octal and short forms (127.1).
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        packed = socket.inet_aton(host)
    except (OSError, ValueError):
        return None
    return ipaddress.IPv4Address(packed)


def _is_forbidden_ip(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_host_ips(host):
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise ValueError(f"host does not resolve: {host!r}")
    ips = set()
    for info in infos:
        ips.add(ipaddress.ip_address(info[4][0]))
    if not ips:
        raise ValueError(f"host does not resolve: {host!r}")
    return ips


def validate_url(url, allowed_hosts=None):
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url must be a non-empty string")

    hosts = set(ALLOWED_HOSTS if allowed_hosts is None else allowed_hosts)
    hosts = {h.strip().lower().rstrip(".") for h in hosts}

    try:
        parsed = urlparse(url.strip())
    except ValueError as exc:
        raise ValueError(f"malformed url: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"scheme not allowed: {parsed.scheme!r}")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("userinfo is not allowed")

    host = parsed.hostname
    if not host:
        raise ValueError("missing host")
    host = host.lower().rstrip(".")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid port: {exc}") from exc
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        raise ValueError(f"non-standard port not allowed: {port}")

    literal_ip = _parse_ip_literal(host)
    if literal_ip is not None:
        if _is_forbidden_ip(literal_ip):
            raise ValueError(f"forbidden ip address: {host!r}")
        if host not in hosts:
            raise ValueError(f"host not in allowlist: {host!r}")
        return True

    if host not in hosts:
        raise ValueError(f"host not in allowlist: {host!r}")

    for ip in _resolve_host_ips(host):
        if _is_forbidden_ip(ip):
            raise ValueError(f"host resolves to forbidden ip: {ip}")

    return True
