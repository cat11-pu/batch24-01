import ipaddress
import re
from email.utils import parsedate_to_datetime


_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
_MAX_AGE_RE = re.compile(r"^-?[0-9]{1,19}$")
_COOKIE_OCTETS = frozenset(
    chr(code)
    for code in range(0x21, 0x7F)
    if code not in (0x22, 0x2C, 0x3B, 0x5C)
)

_KNOWN_ATTRIBUTES = frozenset(
    {
        "expires",
        "max-age",
        "domain",
        "path",
        "secure",
        "httponly",
        "samesite",
        "priority",
        "partitioned",
    }
)
_FLAG_ATTRIBUTES = frozenset({"secure", "httponly", "partitioned"})
_VALUE_ATTRIBUTES = _KNOWN_ATTRIBUTES - _FLAG_ATTRIBUTES

_MAX_COOKIE_LENGTH = 4096
_MAX_DOMAIN_LENGTH = 253
_MAX_LABEL_LENGTH = 63


def _reject_controls(value):
    for char in value:
        code = ord(char)
        if code < 0x20 or code == 0x7F or code > 0x7E:
            raise ValueError("cookie contains a control or non-ASCII character")


def _validate_cookie_value(value):
    if not value:
        return
    if value.startswith('"') or value.endswith('"'):
        if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
            raise ValueError("malformed quoted cookie value")
        escaped = False
        for char in value[1:-1]:
            code = ord(char)
            if escaped:
                if code < 0x20 or code > 0x7E or code == 0x7F:
                    raise ValueError("invalid escape in cookie value")
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"' or code < 0x20 or code > 0x7E or code == 0x7F:
                raise ValueError("invalid character in quoted cookie value")
        if escaped:
            raise ValueError("invalid escape in cookie value")
        return
    if any(char not in _COOKIE_OCTETS for char in value):
        raise ValueError("invalid character in cookie value")


def _validate_name(name):
    if not name:
        raise ValueError("cookie name must not be empty")
    if not _TOKEN_RE.fullmatch(name):
        raise ValueError("invalid cookie name")


def _validate_domain_syntax(domain):
    if not domain:
        raise ValueError("Domain must not be empty")
    if domain != domain.strip():
        raise ValueError("Domain must not contain surrounding whitespace")
    if domain.startswith(".") or domain.endswith("."):
        raise ValueError("Domain must not start or end with a dot")
    if ".." in domain:
        raise ValueError("Domain must not contain empty labels")
    if len(domain) > _MAX_DOMAIN_LENGTH:
        raise ValueError("Domain is too long")

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("Domain must be a host name, not an IP address")

    labels = domain.split(".")
    if len(labels) < 2:
        raise ValueError("Domain must contain a parent label")
    for label in labels:
        if len(label) > _MAX_LABEL_LENGTH or not _LABEL_RE.fullmatch(label):
            raise ValueError("invalid Domain label")


def _validate_path(path):
    if not path.startswith("/"):
        raise ValueError("Path must start with '/'")
    if "," in path or " " in path:
        raise ValueError("invalid character in Path")


def _validate_expires(value):
    try:
        parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("invalid Expires value") from exc


def _validate_max_age(value):
    if not _MAX_AGE_RE.fullmatch(value):
        raise ValueError("invalid Max-Age value")


def _normalise_host(host):
    if not isinstance(host, str):
        raise TypeError("host must be a string")
    host = host.strip().lower()
    if not host:
        raise ValueError("host must not be empty")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        _validate_domain_syntax(host)
    return host


def _validate_domain_scope(domain, host):
    _validate_domain_syntax(domain)
    if host is None:
        raise ValueError("session cookies must be host-only; Domain is not allowed")

    host = _normalise_host(host)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if domain.lower() != host:
            raise ValueError("Domain is outside the request host scope")
    else:
        raise ValueError("IP address hosts cannot use a Domain attribute")


def _validate_prefixes(name, secure, httponly, path, domain):
    if name.startswith("__Host-"):
        if len(name) == len("__Host-"):
            raise ValueError("__Host- cookie name must include a suffix")
        if not secure:
            raise ValueError("__Host- cookies require Secure")
        if not httponly:
            raise ValueError("__Host- cookies require HttpOnly")
        if path != "/":
            raise ValueError("__Host- cookies require Path=/")
        if domain is not None:
            raise ValueError("__Host- cookies must not include Domain")
    elif name.startswith("__Secure-"):
        if len(name) == len("__Secure-"):
            raise ValueError("__Secure- cookie name must include a suffix")
        if not secure:
            raise ValueError("__Secure- cookies require Secure")


def _parse_attributes(rest):
    attributes = {}
    value_attributes = {}

    for raw_attribute in rest:
        attribute = raw_attribute.strip(" ")
        if not attribute:
            raise ValueError("empty cookie attribute")
        if "=" in attribute:
            attr_name, attr_value = attribute.split("=", 1)
            attr_name = attr_name.strip(" ")
            attr_value = attr_value.strip(" ")
            has_value = True
        else:
            attr_name = attribute
            attr_value = ""
            has_value = False

        if not _TOKEN_RE.fullmatch(attr_name):
            raise ValueError("invalid cookie attribute name")
        lowered = attr_name.lower()
        if lowered not in _KNOWN_ATTRIBUTES:
            raise ValueError("unknown cookie attribute")
        if lowered in attributes:
            raise ValueError("duplicate cookie attribute")
        attributes[lowered] = has_value
        value_attributes[lowered] = attr_value

    return attributes, value_attributes


def validate(value, host=None):
    if not isinstance(value, str):
        raise TypeError("cookie must be a string")
    if not value:
        raise ValueError("cookie must not be empty")
    if len(value) > _MAX_COOKIE_LENGTH:
        raise ValueError("cookie is too long")

    _reject_controls(value)
    value = value.strip(" ")
    if not value:
        raise ValueError("cookie must not be empty")

    parts = value.split(";")
    name_value = parts[0]
    if "=" not in name_value:
        raise ValueError("cookie must contain a name and value")
    name, cookie_value = name_value.split("=", 1)
    _validate_name(name)
    _validate_cookie_value(cookie_value)

    attributes, value_attributes = _parse_attributes(parts[1:])

    for attr_name, has_value in attributes.items():
        if attr_name in _FLAG_ATTRIBUTES and has_value:
            raise ValueError("cookie flag attributes must not have a value")
        if attr_name in _VALUE_ATTRIBUTES and not has_value:
            raise ValueError("cookie attributes require a value")

    secure = "secure" in attributes
    httponly = "httponly" in attributes

    if not secure:
        raise ValueError("session cookies require Secure")
    if not httponly:
        raise ValueError("session cookies require HttpOnly")
    if "samesite" not in attributes:
        raise ValueError("session cookies require SameSite")

    same_site = value_attributes["samesite"].lower()
    if same_site not in {"lax", "strict", "none"}:
        raise ValueError("invalid SameSite value")
    if same_site == "none" and not secure:
        raise ValueError("SameSite=None requires Secure")

    path = value_attributes.get("path")
    if "path" in attributes:
        _validate_path(path)

    domain = None
    if "domain" in attributes:
        domain = value_attributes["domain"]
        _validate_domain_scope(domain, host)

    if "expires" in attributes:
        _validate_expires(value_attributes["expires"])
    if "max-age" in attributes:
        _validate_max_age(value_attributes["max-age"])
    if "priority" in attributes:
        if value_attributes["priority"].lower() not in {"low", "medium", "high"}:
            raise ValueError("invalid Priority value")

    _validate_prefixes(name, secure, httponly, path, domain)
    return True
