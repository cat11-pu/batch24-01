import base64
import binascii
import re
from urllib.parse import urlsplit


_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_FRAME_MODES = frozenset({"DENY", "SAMEORIGIN", "ALLOW-FROM"})
_SAMESITE_VALUES = frozenset({"Strict", "Lax", "None"})
_MAX_HSTS_AGE = 63072000
_MIN_NONCE_LENGTH = 16


def _require_dict(value, name):
    if not isinstance(value, dict):
        raise ValueError("%s must be a dict" % name)


def _require_bool(value, name):
    if not isinstance(value, bool):
        raise ValueError("%s must be a bool" % name)


def _require_origin(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError("%s must be a non-empty string" % name)
    if value != value.strip():
        raise ValueError("%s must not contain surrounding whitespace" % name)
    if any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError("%s must not contain control characters" % name)

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid %s" % name) from exc

    if parsed.scheme not in ("http", "https"):
        raise ValueError("%s must use http or https" % name)
    if not parsed.netloc or parsed.hostname is None:
        raise ValueError("%s must include a host" % name)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("%s must not include user information" % name)
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("%s must be an origin without a path or query" % name)
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("%s has an invalid port" % name)


def _hsts_header(config, secure):
    _require_dict(config, "hsts")

    if "max_age" not in config:
        raise ValueError("hsts max_age is required")
    max_age = config["max_age"]
    if isinstance(max_age, bool) or not isinstance(max_age, int):
        raise ValueError("hsts max_age must be an integer")
    if max_age <= 0 or max_age > _MAX_HSTS_AGE:
        raise ValueError("hsts max_age is out of range")

    include_subdomains = config.get("include_subdomains", False)
    _require_bool(include_subdomains, "hsts include_subdomains")

    if secure is not True:
        raise ValueError("transport security headers require a secure request")

    value = "max-age=%d" % max_age
    if include_subdomains:
        value += "; includeSubDomains"
    return value


def _frame_header(policy):
    frame = policy.get("frame")
    if not isinstance(frame, str) or frame not in _FRAME_MODES:
        raise ValueError("invalid frame mode")

    allow_from = policy.get("allow_from", "")
    if not isinstance(allow_from, str):
        raise ValueError("allow_from must be a string")

    if frame == "ALLOW-FROM":
        if not allow_from:
            raise ValueError("ALLOW-FROM requires a non-empty allow_from")
        _require_origin(allow_from, "allow_from")
        return "ALLOW-FROM %s" % allow_from

    if allow_from:
        raise ValueError("allow_from conflicts with frame mode %s" % frame)
    return frame


def _csp_header(nonce):
    if not isinstance(nonce, str):
        raise ValueError("csp_nonce must be a string")
    if len(nonce) < _MIN_NONCE_LENGTH:
        raise ValueError("csp_nonce is too short")
    if len(nonce) % 4 or _BASE64_RE.fullmatch(nonce) is None:
        raise ValueError("csp_nonce must be base64")

    try:
        base64.b64decode(nonce, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("csp_nonce must be base64") from exc

    return "script-src 'nonce-%s'" % nonce


def _cookie_header(config):
    _require_dict(config, "cookie")

    if "samesite" not in config:
        raise ValueError("cookie samesite is required")
    samesite = config["samesite"]
    if not isinstance(samesite, str) or samesite not in _SAMESITE_VALUES:
        raise ValueError("invalid cookie samesite")

    secure = config.get("secure", False)
    _require_bool(secure, "cookie secure")
    if samesite == "None" and not secure:
        raise ValueError("SameSite=None requires Secure")

    attributes = ["SameSite=%s" % samesite]
    if secure:
        attributes.append("Secure")
    return "; ".join(attributes)


def _cors_header(config, origin):
    _require_dict(config, "cors")

    allowed_origins = config.get("allowed_origins")
    if isinstance(allowed_origins, (str, bytes)) or not isinstance(
        allowed_origins, (list, tuple, set, frozenset)
    ):
        raise ValueError("cors allowed_origins must be a collection")
    if not allowed_origins:
        raise ValueError("cors allowed_origins must not be empty")

    for allowed in allowed_origins:
        _require_origin(allowed, "allowed origin")

    if origin is None:
        raise ValueError("request origin is required")
    _require_origin(origin, "request origin")
    if origin not in allowed_origins:
        raise ValueError("request origin is not allowed")
    return origin


def build_headers(policy, request):
    _require_dict(policy, "policy")
    _require_dict(request, "request")

    secure = request.get("secure", False)
    _require_bool(secure, "request secure")

    if "origin" in request:
        origin = request["origin"]
        _require_origin(origin, "request origin")
    else:
        origin = None

    headers = {}

    if "hsts" in policy:
        headers["Strict-Transport-Security"] = _hsts_header(policy["hsts"], secure)

    if "frame" in policy or policy.get("allow_from"):
        headers["X-Frame-Options"] = _frame_header(policy)

    if "csp_nonce" in policy:
        headers["Content-Security-Policy"] = _csp_header(policy["csp_nonce"])

    if "cookie" in policy:
        headers["Set-Cookie"] = _cookie_header(policy["cookie"])

    if "cors" in policy:
        headers["Access-Control-Allow-Origin"] = _cors_header(
            policy["cors"], origin
        )

    return headers
