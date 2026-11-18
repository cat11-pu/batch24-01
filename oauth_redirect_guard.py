import os
from urllib.parse import urlsplit

_DEFAULT_REDIRECT_URI = "https://app.example.com/cb"


def _registered_uri():
    return os.environ.get("OAUTH_REDIRECT_URI", _DEFAULT_REDIRECT_URI)


def _reject(reason):
    raise ValueError("redirect_uri rejected: %s" % reason)


def validate(value, registered=None):
    if not isinstance(value, str):
        raise TypeError("redirect_uri must be a str")
    if not value:
        _reject("empty value")
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in value):
        _reject("control or whitespace characters")
    if "\\" in value:
        _reject("backslash is not allowed")
    if "%" in value:
        _reject("percent-encoded variants are not allowed")

    try:
        candidate = urlsplit(value)
        expected = urlsplit(registered if registered is not None else _registered_uri())
    except ValueError as exc:
        _reject("unparseable URI (%s)" % exc)

    if candidate.scheme.lower() != "https":
        _reject("scheme must be https")
    if candidate.username is not None or candidate.password is not None:
        _reject("userinfo is not allowed")
    try:
        if candidate.port is not None:
            _reject("explicit port is not allowed")
    except ValueError:
        _reject("invalid port")
    if candidate.hostname is None or candidate.hostname.lower() != (expected.hostname or "").lower():
        _reject("host does not match registered value")
    if candidate.path != expected.path:
        _reject("path does not match registered value")
    if candidate.query != expected.query:
        _reject("query does not match registered value")
    if candidate.fragment:
        _reject("fragment is not allowed")
    return True
