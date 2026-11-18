import base64
import hashlib
import hmac
import json

import pytest

from jwt_rotation import verify

KEYS = {"k1": "secret-key-123456"}
ISS = "https://issuer.example"
AUD = "app"
NOW = 1000


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make(header, payload, secret):
    h = b64(json.dumps(header, separators=(",", ":")).encode())
    p = b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


GOOD_H = {"alg": "HS256", "kid": "k1"}
GOOD_P = {"iss": ISS, "aud": AUD, "exp": 1100, "nbf": 900, "iat": 950, "jti": "j1"}


def rejected(token, keys=KEYS, revoked=None):
    try:
        assert verify(token, keys, NOW, ISS, AUD, revoked, 60) is False
    except ValueError:
        return


def test_alg_none_is_rejected():
    rejected(make({**GOOD_H, "alg": "none"}, GOOD_P, KEYS["k1"]))


def test_alg_hs512_is_rejected():
    rejected(make({**GOOD_H, "alg": "HS512"}, GOOD_P, KEYS["k1"]))


def test_unknown_kid_is_rejected():
    rejected(make({**GOOD_H, "kid": "k2"}, GOOD_P, KEYS["k1"]))


def test_bad_signature_is_rejected():
    rejected(make(GOOD_H, GOOD_P, "wrong-secret-1234"))


def test_expired_token_is_rejected():
    rejected(make(GOOD_H, {**GOOD_P, "exp": 900}, KEYS["k1"]))


def test_not_before_in_future_is_rejected():
    rejected(make(GOOD_H, {**GOOD_P, "nbf": 1100}, KEYS["k1"]))


def test_wrong_issuer_is_rejected():
    rejected(make(GOOD_H, {**GOOD_P, "iss": "evil"}, KEYS["k1"]))


def test_wrong_audience_is_rejected():
    rejected(make(GOOD_H, {**GOOD_P, "aud": "other"}, KEYS["k1"]))


def test_missing_exp_is_rejected():
    payload = dict(GOOD_P)
    del payload["exp"]
    rejected(make(GOOD_H, payload, KEYS["k1"]))


def test_malformed_token_is_rejected():
    rejected("abc")


def test_empty_token_is_rejected():
    rejected("")


def test_non_string_token_is_rejected():
    rejected(None)


def test_kid_path_traversal_is_rejected():
    rejected(make({**GOOD_H, "kid": "../k1"}, GOOD_P, KEYS["k1"]))


def test_revoked_jti_is_rejected():
    rejected(make(GOOD_H, GOOD_P, KEYS["k1"]), KEYS, {"j1"})


def test_future_iat_is_rejected():
    rejected(make(GOOD_H, {**GOOD_P, "iat": 1200}, KEYS["k1"]))
