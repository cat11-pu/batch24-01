import ipaddress
import json
import re
import string


_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")
_PUBLIC_CACHE_FORBIDDEN_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "cookie2"}
)
_STANDARD_PORTS = frozenset({80, 443})


def _fail(message):
    raise ValueError(message)


def _normalize_percent_encoding(value, component):
    normalized = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "%":
            normalized.append(char)
            index += 1
            continue

        if index + 2 >= len(value):
            _fail(f"{component} contains an incomplete escape")
        escape = value[index + 1 : index + 3]
        if any(digit not in string.hexdigits for digit in escape):
            _fail(f"{component} contains an invalid escape")

        decoded = chr(int(escape, 16))
        if decoded in _UNRESERVED:
            normalized.append(decoded)
        else:
            normalized.append("%" + escape.upper())
        index += 3

    return "".join(normalized)


def _normalize_host(value):
    if not isinstance(value, str) or not value:
        _fail("host must be a non-empty string")
    if value != value.strip():
        _fail("host must not contain surrounding whitespace")
    if any(ord(char) < 0x21 or ord(char) == 0x7F for char in value):
        _fail("host contains whitespace or control characters")
    if any(char in value for char in "/?#@,;"):
        _fail("host contains invalid characters")

    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            _fail("host contains an invalid IPv6 literal")
        address = value[1:closing]
        remainder = value[closing + 1 :]
        try:
            host = ipaddress.IPv6Address(address).compressed
        except ValueError:
            _fail("host contains an invalid IPv6 literal")
        if remainder:
            if not remainder.startswith(":"):
                _fail("host contains invalid characters after the IPv6 literal")
            port_text = remainder[1:]
        else:
            port_text = None
        host = f"[{host}]"
    else:
        if value.count(":") > 1:
            _fail("IPv6 hosts must be bracketed")
        if ":" in value:
            name, port_text = value.rsplit(":", 1)
        else:
            name, port_text = value, None

        host = name[:-1].lower() if name.endswith(".") else name.lower()
        if not host or len(host) > 253:
            _fail("host is invalid")
        for label in host.split("."):
            if (
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not _LABEL_RE.fullmatch(label)
            ):
                _fail("host is invalid")

    if port_text is not None:
        if not port_text or not port_text.isdigit():
            _fail("host contains an invalid port")
        if int(port_text) not in _STANDARD_PORTS:
            _fail("host contains a non-standard port")

    return host


def _canonical_path(value):
    if not isinstance(value, str) or not value.startswith("/"):
        _fail("path must be a string starting with '/'")
    if any(char in value for char in "?#\\"):
        _fail("path contains a fragment, query, or invalid separator")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        _fail("path contains control characters")
    if any(char.isspace() for char in value):
        _fail("path contains unescaped whitespace")

    path = _normalize_percent_encoding(value, "path")

    security_view = re.sub(r"(?i)%2e", ".", path)
    security_view = re.sub(r"(?i)%2f|%5c", "/", security_view)
    if any(segment == ".." for segment in security_view.split("/")):
        _fail("path contains a traversal segment")

    parts = path.split("/")
    folded = []
    for part in parts:
        if part == ".":
            continue
        if part == "..":
            _fail("path contains a traversal segment")
        folded.append(part)

    result = "/".join(folded)
    if (path.endswith("/") or path.endswith("/.")) and not result.endswith("/"):
        result += "/"
    return result or "/"


def _normalize_query_part(value, component):
    if not isinstance(value, str):
        _fail(f"{component} must be a string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        _fail(f"{component} contains control characters")
    return _normalize_percent_encoding(value, component)


def _canonical_query(value):
    if not isinstance(value, list):
        _fail("query must be a list")

    result = []
    seen_keys = set()
    for item in value:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            _fail("each query item must be a name/value pair")
        name = _normalize_query_part(item[0], "query name")
        item_value = _normalize_query_part(item[1], "query value")
        if name in seen_keys:
            _fail("query contains a duplicate key")
        seen_keys.add(name)
        result.append((name, item_value))

    result.sort(key=lambda pair: (pair[0], pair[1]))
    return [[name, item_value] for name, item_value in result]


def _canonical_headers(value):
    if not isinstance(value, dict):
        _fail("headers must be a dict")

    result = {}
    for name, header_value in value.items():
        if not isinstance(name, str) or not _TOKEN_RE.fullmatch(name):
            _fail("header names must be valid tokens")
        normalized_name = name.lower()
        if normalized_name in result:
            _fail("headers contain duplicate names")
        if not isinstance(header_value, str):
            _fail("header values must be strings")
        if any(
            (ord(char) < 0x20 and char != "\t") or ord(char) == 0x7F
            for char in header_value
        ):
            _fail("header values contain control characters")
        result[normalized_name] = " ".join(header_value.strip().split())

    return result


def _canonical_policy(value):
    if not isinstance(value, dict):
        _fail("policy must be a dict")

    allowed_hosts = value.get("allowed_hosts")
    if not isinstance(allowed_hosts, list) or not allowed_hosts:
        _fail("allowed_hosts must be a non-empty list")

    normalized_hosts = set()
    for host in allowed_hosts:
        normalized_hosts.add(_normalize_host(host))
    if not normalized_hosts:
        _fail("allowed_hosts must be a non-empty list")

    vary = value.get("vary", [])
    if not isinstance(vary, list):
        _fail("vary must be a list")

    vary_names = set()
    for name in vary:
        if not isinstance(name, str) or not _TOKEN_RE.fullmatch(name):
            _fail("vary entries must be valid header names")
        normalized_name = name.lower()
        if normalized_name == "*":
            _fail("vary must not contain '*'")
        if normalized_name in _PUBLIC_CACHE_FORBIDDEN_HEADERS:
            _fail("public cache keys must not vary on credentials or cookies")
        vary_names.add(normalized_name)

    return normalized_hosts, sorted(vary_names)


def cache_key(request, policy):
    """Return a deterministic cache key for a request in a public cache."""
    if not isinstance(request, dict):
        _fail("request must be a dict")

    required = ("method", "host", "path", "query", "headers")
    if any(field not in request for field in required):
        _fail("request is missing a required field")

    method = request["method"]
    if not isinstance(method, str) or method not in {"GET", "HEAD"}:
        _fail("method must be GET or HEAD")

    allowed_hosts, vary_names = _canonical_policy(policy)

    host = _normalize_host(request["host"])
    if host not in allowed_hosts:
        _fail("host is not allowed")

    path = _canonical_path(request["path"])
    query = _canonical_query(request["query"])
    headers = _canonical_headers(request["headers"])

    if any(name in headers for name in _PUBLIC_CACHE_FORBIDDEN_HEADERS):
        _fail("credentials and cookies must not enter a public cache")

    vary_values = []
    for name in vary_names:
        if name not in headers:
            _fail(f"missing vary header: {name}")
        vary_values.append([name, headers[name]])

    key_material = {
        "method": method,
        "host": host,
        "path": path,
        "query": query,
        "vary": vary_values,
    }
    return json.dumps(
        key_material,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
