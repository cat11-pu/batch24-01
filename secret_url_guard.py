import re
import unicodedata
from urllib.parse import unquote, urlsplit


_MAX_DECODE_ROUNDS = 8

_CREDENTIAL_PARTS = frozenset(
    {
        "token",
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "passcode",
        "pass",
        "secret",
        "key",
        "auth",
        "authorization",
        "authentication",
        "authorisation",
        "session",
        "credential",
        "credentials",
        "signature",
        "sig",
        "jwt",
        "bearer",
        "nonce",
    }
)

_KEY_PREFIXES = frozenset(
    {
        "api",
        "access",
        "secret",
        "private",
        "public",
        "signing",
        "encryption",
        "encrypt",
        "decryption",
        "decrypt",
        "client",
        "master",
        "app",
        "application",
        "web",
        "mobile",
        "device",
        "host",
        "server",
        "service",
        "shared",
        "session",
        "auth",
        "user",
        "account",
        "subscription",
        "storage",
        "database",
        "db",
        "bucket",
        "resource",
        "tenant",
        "org",
        "organization",
        "project",
        "workspace",
        "team",
        "group",
        "environment",
        "env",
        "deployment",
        "instance",
        "consumer",
        "developer",
        "primary",
        "secondary",
        "fallback",
        "backup",
        "old",
        "new",
        "prod",
        "production",
        "dev",
        "development",
        "test",
        "staging",
        "global",
        "default",
        "my",
        "our",
        "the",
        "hmac",
        "aes",
        "rsa",
        "ssh",
        "gpg",
        "pgp",
        "jwt",
        "oauth",
        "publish",
        "publishable",
        "restricted",
        "write",
        "read",
        "admin",
        "management",
        "recovery",
        "pass",
    }
)

_TOKEN_PREFIXES = frozenset(
    {
        "access",
        "refresh",
        "id",
        "auth",
        "api",
        "csrf",
        "xsrf",
        "bearer",
        "session",
        "oauth",
        "verification",
        "verify",
        "reset",
        "email",
        "phone",
        "invite",
        "invitation",
        "activation",
        "recovery",
        "magic",
        "personal",
        "client",
        "app",
        "application",
        "user",
        "account",
    }
)

_TOKEN_SUFFIXES = frozenset(
    {
        "s",
        "key",
        "value",
        "id",
        "hash",
        "secret",
        "code",
        "data",
        "string",
        "bytes",
        "file",
    }
)

_SECRET_SUFFIXES = frozenset(
    {
        "s",
        "key",
        "value",
        "id",
        "hash",
        "token",
        "code",
        "data",
        "string",
        "bytes",
        "file",
        "path",
    }
)

_SESSION_SUFFIXES = frozenset(
    {
        "s",
        "id",
        "key",
        "token",
        "secret",
        "value",
        "hash",
        "code",
        "data",
        "string",
        "cookie",
    }
)

_KEY_SUFFIXES = frozenset(
    {
        "s",
        "id",
        "name",
        "value",
        "token",
        "secret",
        "hash",
        "file",
        "path",
        "data",
        "bytes",
        "store",
        "ring",
        "vault",
        "pair",
        "material",
    }
)

_SIMPLE_NAME = re.compile(r"[A-Za-z0-9_.\-\[\]]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ACRONYM_BOUNDARY = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_URL_WITH_USERINFO = re.compile(
    r"(?i)(?:[a-z][a-z0-9+.\-]*:)?//[^/?#\s]*@"
)


def _decode_repeatedly(value):
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def _identifier_parts(value):
    value = unicodedata.normalize("NFKC", value)
    value = _CAMEL_BOUNDARY.sub(" ", value)
    value = _ACRONYM_BOUNDARY.sub(" ", value)
    parts = tuple(
        part for part in re.split(r"[^A-Za-z0-9]+", value.casefold()) if part
    )
    return parts, "".join(parts)


def _is_simple_name(name):
    normalized = unicodedata.normalize("NFKC", name.strip())
    return bool(_SIMPLE_NAME.fullmatch(normalized))


def _compound_with_suffixes(prefix, suffix, prefixes, suffixes):
    if not prefix and not suffix:
        return True
    if suffix in suffixes or suffix.isdigit():
        return True
    if prefix in prefixes:
        return True
    return False


def _has_password(parts, compact):
    if any(
        part in {"password", "passwd", "pwd", "passphrase", "passcode", "pass"}
        for part in parts
    ):
        return True
    if any(word in compact for word in ("password", "passwd", "passphrase", "passcode")):
        return True
    if compact.startswith("pwd") or compact.endswith("pwd"):
        return True
    return False


def _has_token(compact):
    start = compact.find("token")
    if start < 0:
        return False
    prefix = compact[:start]
    suffix = compact[start + len("token") :]
    return _compound_with_suffixes(
        prefix, suffix, _TOKEN_PREFIXES | _KEY_PREFIXES, _TOKEN_SUFFIXES
    )


def _has_secret(parts, compact):
    if "secret" in parts:
        return True
    start = compact.find("secret")
    if start < 0:
        return False
    prefix = compact[:start]
    suffix = compact[start + len("secret") :]
    if not suffix:
        return True
    if suffix in _SECRET_SUFFIXES or suffix.isdigit():
        return True
    if prefix in _KEY_PREFIXES:
        return True
    return False


def _has_key(parts, compact):
    if "key" in parts:
        return True
    if compact.endswith("key"):
        prefix = compact[: -len("key")]
        if prefix in _KEY_PREFIXES:
            return True
    if compact.endswith("keys"):
        prefix = compact[: -len("keys")]
        if not prefix or prefix in _KEY_PREFIXES:
            return True
    if compact.startswith("key"):
        suffix = compact[len("key") :]
        if suffix in _KEY_SUFFIXES or suffix.isdigit():
            return True
    return False


def _has_session(parts, compact):
    if "session" in parts:
        return True
    for part in parts:
        if part.startswith("session"):
            suffix = part[len("session") :]
            if suffix in _SESSION_SUFFIXES or suffix.isdigit():
                return True
    if compact.endswith("session"):
        prefix = compact[: -len("session")]
        if prefix in _KEY_PREFIXES:
            return True
    return False


def _has_auth(parts):
    return any(
        part
        in {"auth", "authorization", "authentication", "authorisation"}
        or (
            part.endswith("s")
            and part[:-1]
            in {"auth", "authorization", "authentication", "authorisation"}
        )
        for part in parts
    )


def _is_sensitive_name(name):
    decoded = _decode_repeatedly(name)
    parts, compact = _identifier_parts(decoded)
    if not compact:
        return False
    if compact in _CREDENTIAL_PARTS:
        return True
    if any(part in _CREDENTIAL_PARTS for part in parts):
        return True
    if _has_password(parts, compact):
        return True
    if _has_token(compact):
        return True
    if _has_secret(parts, compact):
        return True
    if "apikey" in compact:
        return True
    if _has_key(parts, compact):
        return True
    if _has_session(parts, compact):
        return True
    if _has_auth(parts):
        return True
    if any(part.startswith("credential") for part in parts):
        return True
    if "credential" in compact:
        return True
    if any(part in {"sig", "signature"} for part in parts):
        return True
    if compact.startswith("signature") or compact.endswith("signature"):
        return True
    if "jwt" in compact or "bearer" in compact:
        return True
    return False


def _scan_value(value):
    decoded = _decode_repeatedly(value)
    if _URL_WITH_USERINFO.search(decoded):
        raise ValueError("URL userinfo is not allowed")
    for chunk in re.split(r"[&;?#\s]+", decoded):
        if "=" not in chunk:
            continue
        for name in chunk.split("=")[:-1]:
            if _is_simple_name(name) and _is_sensitive_name(name):
                raise ValueError("URL contains a sensitive query parameter")


def _scan_query(query):
    text = query
    seen = set()
    for _ in range(_MAX_DECODE_ROUNDS):
        if text in seen:
            break
        seen.add(text)
        for segment in re.split(r"[&;]", text):
            if not segment:
                continue
            name, separator, value = segment.partition("=")
            if _is_sensitive_name(name):
                raise ValueError("URL contains a sensitive query parameter")
            if separator:
                _scan_value(value)
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded


def validate(value):
    if not isinstance(value, str):
        raise TypeError("URL must be a string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("URL contains control characters")

    parsed = urlsplit(value)

    if "#" in value or parsed.fragment:
        raise ValueError("URL fragments are not allowed")

    decoded_netloc = _decode_repeatedly(parsed.netloc)
    if (
        "@" in parsed.netloc
        or "@" in decoded_netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("URL userinfo is not allowed")

    _scan_query(parsed.query)
    return True
