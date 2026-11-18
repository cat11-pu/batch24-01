"""Cache-key guard for a shared (public) cache.

The original bug was that the cache key was derived from the URL only, so
request headers that change the response (Host, X-Forwarded-Host,
Authorization, Cookie, ...) were ignored and an attacker could poison an
entry later served to other users.

This module fixes that in two layers:

1. ``validate`` rejects any header list that is unsafe to use with the
   shared cache.  Every rule is driven by a :class:`CacheKeyPolicy`
   configuration object -- the guard logic itself contains no hard coded
   header names.
2. ``build_cache_key`` folds every accepted, response-affecting header into
   the cache key, so two requests that differ in those headers can never
   share a cache entry.

The default policy can be overridden through environment variables, which
keeps deployment specific allow lists out of the source code.
"""

import hashlib
import json
import os


def _split_csv(value):
    return [item.strip() for item in value.split(",") if item.strip()]


class CacheKeyPolicy:
    """Configuration describing which requests the shared cache may serve.

    All header names referenced by the guard live here so that the
    validation logic stays generic and no header name is hard coded.
    """

    def __init__(
        self,
        allowed_headers,
        sensitive_headers,
        host_headers,
        allowed_hosts,
        allowed_ports,
        forwarding_headers=None,
        allowed_forwarded_values=None,
    ):
        self.allowed_headers = frozenset(name.lower() for name in allowed_headers)
        self.sensitive_headers = frozenset(name.lower() for name in sensitive_headers)
        self.host_headers = frozenset(name.lower() for name in host_headers)
        self.allowed_hosts = frozenset(host.lower() for host in allowed_hosts)
        self.allowed_ports = frozenset(allowed_ports)
        self.forwarding_headers = {
            name.lower(): kind for name, kind in (forwarding_headers or {}).items()
        }
        self.allowed_forwarded_values = dict(allowed_forwarded_values or {})

    @classmethod
    def default(cls):
        """Build the production policy, optionally overridden via env vars."""
        host_header = "Host"
        forwarded_host_header = "X-Forwarded-Host"
        forwarded_proto_header = "X-Forwarded-Proto"
        forwarded_port_header = "X-Forwarded-Port"

        allowed_hosts = _split_csv(
            os.environ.get(
                "CACHE_GUARD_ALLOWED_HOSTS",
                "app.example.com,cdn.example.com",
            )
        )
        allowed_ports = frozenset(
            int(port)
            for port in _split_csv(
                os.environ.get("CACHE_GUARD_ALLOWED_PORTS", "443,80")
            )
        )

        policy = cls(
            allowed_headers=(
                host_header,
                forwarded_host_header,
                forwarded_proto_header,
                forwarded_port_header,
                "Accept",
                "Accept-Encoding",
            ),
            sensitive_headers=("Authorization", "Cookie", "Proxy-Authorization"),
            host_headers=(host_header, forwarded_host_header),
            allowed_hosts=allowed_hosts,
            allowed_ports=allowed_ports,
            forwarding_headers={
                forwarded_proto_header: "proto",
                forwarded_port_header: "port",
            },
            allowed_forwarded_values={
                "proto": frozenset(("https",)),
                "port": allowed_ports,
            },
        )
        return policy


DEFAULT_POLICY = CacheKeyPolicy.default()


def _reject(reason):
    raise ValueError("unsafe cache key input: " + reason)


def _normalise_header_name(name):
    if not isinstance(name, str) or not name:
        _reject("header name must be a non-empty string")
    normalised = name.strip().lower()
    if not normalised:
        _reject("header name must be a non-empty string")
    return normalised


def _check_header_value(value):
    if not isinstance(value, str):
        _reject("header value must be a string")
    if value == "":
        _reject("empty header value")
    if value.strip() != value:
        _reject("leading or trailing whitespace in header value")
    for char in value:
        code = ord(char)
        if code <= 0x1F or code == 0x7F:
            _reject("control character in header value")


def _check_host(value, policy):
    """Validate a Host / X-Forwarded-Host value against the allow list."""
    hostname = value
    if ":" in value:
        hostname, _, port_text = value.rpartition(":")
        if not port_text.isdigit():
            _reject("invalid port in host header")
        port = int(port_text)
        if port not in policy.allowed_ports:
            _reject("port not in allow list: %d" % port)
    if not hostname:
        _reject("empty host")
    if hostname != hostname.lower():
        _reject("host must be lower case: %s" % hostname)
    normalised_host = hostname.rstrip(".")
    if normalised_host not in policy.allowed_hosts:
        _reject("host not in allow list: %s" % hostname)
    return normalised_host


def validate(value, policy=None):
    """Validate a request header list for use with the shared cache.

    ``value`` is a list of ``[header-name, header-value]`` pairs.  On success
    a canonical dict of the accepted headers is returned; this dict is also
    the material folded into the cache key.  Any unsafe input raises
    :class:`ValueError` (or :class:`TypeError` for a malformed structure).
    """
    if policy is None:
        policy = DEFAULT_POLICY

    if not isinstance(value, list):
        raise TypeError("headers must be a list of [name, value] pairs")

    seen = set()
    canonical = {}

    for pair in value:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise TypeError("each header must be a [name, value] pair")

        raw_name, raw_header_value = pair
        name = _normalise_header_name(raw_name)

        if name in seen:
            _reject("duplicate header: %s" % raw_name)
        seen.add(name)

        # Sensitive, per-user material must never be stored in a public
        # cache entry -- refuse instead of silently keying on it.
        if name in policy.sensitive_headers:
            _reject("sensitive header is forbidden on shared cache: %s" % raw_name)

        # Every header reaching the cache has to be an explicitly trusted
        # one; unknown request headers are rejected rather than ignored.
        if name not in policy.allowed_headers:
            _reject("header not in allow list: %s" % raw_name)

        _check_header_value(raw_header_value)

        if name in policy.host_headers:
            canonical[name] = _check_host(raw_header_value, policy)
            continue

        forwarding_kind = policy.forwarding_headers.get(name)
        if forwarding_kind is not None:
            allowed = policy.allowed_forwarded_values.get(forwarding_kind, frozenset())
            if raw_header_value.lower() not in {
                str(item).lower() for item in allowed
            }:
                _reject(
                    "forwarding header value not allowed: %s=%s"
                    % (raw_name, raw_header_value)
                )
            canonical[name] = raw_header_value.lower()
            continue

        canonical[name] = raw_header_value

    if not canonical:
        _reject("request without headers cannot be cached")

    return canonical


def build_cache_key(url, headers, policy=None):
    """Return a cache key that includes every response-affecting header.

    The headers are validated first; any unsafe input raises and therefore
    can never produce a cache entry.  Accepted headers are serialised into
    the key so distinct Host / forwarding / content-negotiation values can
    never collide on the same URL.
    """
    if not isinstance(url, str) or not url:
        raise ValueError("url must be a non-empty string")
    canonical = validate(headers, policy=policy)
    material = json.dumps(
        {"url": url, "headers": canonical},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return "cache:" + digest
