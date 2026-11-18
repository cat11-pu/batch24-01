import base64
import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping


_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _b64url_decode(value):
    if not isinstance(value, str) or not value:
        raise ValueError("empty base64url value")

    if "=" in value:
        core = value.rstrip("=")
        padding = len(value) - len(core)
        if padding > 2 or "=" in core:
            raise ValueError("invalid base64url padding")
        if (len(core) + padding) % 4:
            raise ValueError("invalid base64url padding")
        encoded = core + "=" * padding
    else:
        core = value
        if len(core) % 4 == 1:
            raise ValueError("invalid base64url length")
        encoded = core + "=" * (-len(core) % 4)

    if not _B64URL_RE.fullmatch(core):
        raise ValueError("invalid base64url alphabet")

    return base64.urlsafe_b64decode(encoded.encode("ascii"))


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def _decode_json(value):
    raw = _b64url_decode(value)
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )


def _is_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return not isinstance(value, float) or math.isfinite(value)


def _is_safe_kid(kid):
    if not isinstance(kid, str) or not kid:
        return False
    if "\x00" in kid or "/" in kid or "\\" in kid:
        return False
    lowered = kid.lower()
    if "%2f" in lowered or "%5c" in lowered or "%2e" in lowered:
        return False
    return kid != "." and ".." not in kid


def _key_bytes(key):
    if isinstance(key, str):
        return key.encode("utf-8")
    if isinstance(key, (bytes, bytearray, memoryview)):
        return bytes(key)
    raise ValueError("invalid key type")


def _audience_set(value):
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, tuple, set, frozenset)):
        if not value or not all(isinstance(item, str) for item in value):
            raise ValueError("invalid audience")
        return set(value)
    raise ValueError("invalid audience")


def _audience_matches(claim, expected):
    token_audiences = _audience_set(claim)
    expected_audiences = _audience_set(expected)
    return not token_audiences.isdisjoint(expected_audiences)


def verify(token, keys, now, issuer, audience, revoked=None, skew=60):
    try:
        if not isinstance(token, str) or not token:
            return False
        if not isinstance(keys, Mapping):
            return False
        if not _is_number(now) or not _is_number(skew) or skew < 0:
            return False

        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            return False

        header_part, payload_part, signature_part = parts
        header = _decode_json(header_part)
        payload = _decode_json(payload_part)
        signature = _b64url_decode(signature_part)

        if not isinstance(header, dict) or not isinstance(payload, dict):
            return False
        if header.get("alg") != "HS256":
            return False

        kid = header.get("kid")
        if not _is_safe_kid(kid) or kid not in keys:
            return False

        signing_input = f"{header_part}.{payload_part}".encode("ascii")
        expected_signature = hmac.new(
            _key_bytes(keys[kid]), signing_input, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected_signature, signature):
            return False

        if (
            "iss" not in payload
            or not isinstance(payload["iss"], str)
            or not isinstance(issuer, str)
            or payload["iss"] != issuer
        ):
            return False
        if "aud" not in payload or not _audience_matches(payload["aud"], audience):
            return False

        for claim in ("exp", "nbf", "iat"):
            if claim not in payload or not _is_number(payload[claim]):
                return False

        exp = payload["exp"]
        nbf = payload["nbf"]
        iat = payload["iat"]
        if exp <= now - skew:
            return False
        if nbf > now + skew:
            return False
        if iat > now + skew:
            return False

        if revoked is not None and payload.get("jti") in revoked:
            return False

        return True
    except Exception:
        return False
