import base64
import binascii
import hmac


_DIGEST_LENGTHS = {
    "sha256": 32,
    "sha384": 48,
    "sha512": 64,
}
_BASE64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
)
_URLSAFE_TO_STANDARD = str.maketrans("-_", "+/")


def _decode_digest(text, expected_length):
    if not text or any(char not in _BASE64_CHARS for char in text):
        raise ValueError("invalid base64 digest")

    core = text.rstrip("=")
    padding = text[len(core):]
    if "=" in core or len(padding) > 2 or len(core) % 4 == 1:
        raise ValueError("invalid base64 digest")

    normalized = core.translate(_URLSAFE_TO_STANDARD)
    required_padding = (-len(normalized)) % 4
    if padding and len(padding) != required_padding:
        raise ValueError("invalid base64 padding")

    try:
        digest = base64.b64decode(
            normalized + "=" * required_padding, validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64 digest") from exc

    if len(digest) != expected_length:
        raise ValueError("incorrect digest length")

    canonical = base64.b64encode(digest).decode("ascii").rstrip("=")
    if not hmac.compare_digest(canonical, normalized):
        raise ValueError("non-canonical base64 digest")

    return digest


def validate(value):
    if not isinstance(value, str):
        raise TypeError("integrity value must be a string")
    if not value:
        raise ValueError("integrity value must not be empty")

    tokens = value.split(" ")
    if not tokens or any(not token for token in tokens):
        raise ValueError("invalid integrity metadata")

    seen = {}
    for token in tokens:
        algorithm, separator, encoded = token.partition("-")
        if not separator or algorithm not in _DIGEST_LENGTHS:
            raise ValueError("unsupported hash algorithm")

        digest = _decode_digest(encoded, _DIGEST_LENGTHS[algorithm])
        if algorithm in seen:
            if not hmac.compare_digest(seen[algorithm], digest):
                raise ValueError("conflicting digests for the same algorithm")
        else:
            seen[algorithm] = digest

    return True
