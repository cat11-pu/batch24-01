import ipaddress
import re
from urllib.parse import quote


ALLOWED_HOSTS = {"app.example.com"}

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def _looks_like_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # Reject IPv4-like numeric forms that alternate resolvers may accept.
    if re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)", host):
        return True
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", host):
        return True
    if re.fullmatch(r"0[xX][0-9A-Fa-f]+(?:\.[0-9A-Fa-f]+){1,3}", host):
        return True
    return False


def validate_reset_host(host):
    if not isinstance(host, str) or not host:
        return False
    if len(host) > 253 or host.endswith("."):
        return False
    if any(not char.isprintable() or char.isspace() for char in host):
        return False
    if any(char in host for char in "@/\\[]:%?#"):
        return False
    if _looks_like_ip(host):
        return False
    if not _HOSTNAME_RE.fullmatch(host):
        return False

    # Compare the complete string with the allowlist; never normalize or
    # perform suffix/subdomain matching.
    return host in ALLOWED_HOSTS


def build_reset_link(host, token):
    if not validate_reset_host(host):
        raise ValueError("reset host is not allowed")
    if not isinstance(token, str):
        raise ValueError("reset token must be a string")
    return f"https://{host}/reset?token={quote(token, safe='')}"
