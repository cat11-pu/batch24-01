import base64
import binascii
import hashlib
import hmac
import os

ALGORITHM = "pbkdf2_sha256"
DIGEST = "sha256"
DEFAULT_ITERATIONS = 120000
SALT_BYTES = 16
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def _encode_salt(salt):
    if salt is None:
        return os.urandom(SALT_BYTES)
    if isinstance(salt, str):
        return salt.encode("ascii")
    if isinstance(salt, (bytes, bytearray)):
        return bytes(salt)
    raise ValueError("salt must be bytes, a string, or None")


def _validate_password(password):
    if not isinstance(password, str):
        raise ValueError("password must be a string")
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise ValueError(
            "password length must be between %d and %d characters"
            % (MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)
        )


def hash_password(password, salt=None, iterations=DEFAULT_ITERATIONS):
    _validate_password(password)
    raw_salt = _encode_salt(salt)
    derived_key = hashlib.pbkdf2_hmac(
        DIGEST,
        password.encode("utf-8"),
        raw_salt,
        iterations,
    )
    return "%s$%d$%s$%s" % (
        ALGORITHM,
        iterations,
        base64.b64encode(raw_salt).decode("ascii"),
        base64.b64encode(derived_key).decode("ascii"),
    )


def _parse_stored(stored):
    if not isinstance(stored, str) or not stored:
        return None
    parts = stored.split("$")
    if len(parts) != 4 or any(not part for part in parts):
        return None
    algorithm, iteration_text, salt_text, hash_text = parts
    if algorithm != ALGORITHM:
        return None
    try:
        iterations = int(iteration_text)
        raw_salt = base64.b64decode(salt_text, validate=True)
        expected_hash = base64.b64decode(hash_text, validate=True)
    except (ValueError, binascii.Error):
        return None
    if iterations <= 0 or not raw_salt or not expected_hash:
        return None
    return iterations, raw_salt, expected_hash


def verify_password(password, stored):
    if not isinstance(password, str):
        return False
    parsed = _parse_stored(stored)
    if parsed is None:
        return False
    iterations, raw_salt, expected_hash = parsed
    try:
        derived_key = hashlib.pbkdf2_hmac(
            DIGEST,
            password.encode("utf-8"),
            raw_salt,
            iterations,
        )
    except (ValueError, OverflowError):
        return False
    return hmac.compare_digest(derived_key, expected_hash)


def needs_rehash(stored):
    parsed = _parse_stored(stored)
    if parsed is None:
        return True
    iterations = parsed[0]
    return iterations < DEFAULT_ITERATIONS
