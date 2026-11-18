import hashlib

import pytest

from oauth_guard import validate_callback

REGISTERED = ["https://app.example.com/cb"]


def callback(**overrides):
    args = {
        "state": "state-1",
        "expected_state": "state-1",
        "code": "code-1",
        "redirect_uri": "https://app.example.com/cb",
        "registered_redirect_uris": REGISTERED,
        "code_verifier": None,
        "code_challenge": None,
        "code_challenge_method": "S256",
        "client_id": "client-1",
        "expected_client_id": "client-1",
    }
    args.update(overrides)
    return validate_callback(**args)


def test_1_state_mismatch_is_rejected():
    with pytest.raises(ValueError):
        callback(state="attacker-state")


def test_2_missing_state_is_rejected():
    with pytest.raises(ValueError):
        callback(state="")


def test_3_state_cannot_be_replayed():
    assert callback() is True
    with pytest.raises(ValueError):
        callback()


def test_4_redirect_prefix_bypass_is_rejected():
    with pytest.raises(ValueError):
        callback(redirect_uri="https://app.example.com/cb.evil.com")


def test_5_unregistered_redirect_is_rejected():
    with pytest.raises(ValueError):
        callback(redirect_uri="https://evil.example.com/cb")


def test_6_code_cannot_be_replayed():
    assert callback(code="code-replay") is True
    with pytest.raises(ValueError):
        callback(code="code-replay")


def test_7_missing_code_is_rejected():
    with pytest.raises(ValueError):
        callback(code="")


def test_8_empty_code_is_rejected():
    with pytest.raises(ValueError):
        callback(code="   ")


def test_9_pkce_requires_verifier():
    with pytest.raises(ValueError):
        callback(code_challenge="challenge-1")


def test_10_wrong_pkce_verifier_is_rejected():
    challenge = hashlib.sha256(b"correct-verifier").hexdigest()
    with pytest.raises(ValueError):
        callback(code_challenge=challenge, code_verifier="wrong-verifier")


def test_11_plain_pkce_method_is_rejected():
    challenge = hashlib.sha256(b"correct-verifier").hexdigest()
    with pytest.raises(ValueError):
        callback(code_challenge=challenge, code_verifier="correct-verifier", code_challenge_method="plain")


def test_12_client_mismatch_is_rejected():
    with pytest.raises(ValueError):
        callback(client_id="other-client")


def test_13_expected_client_is_required():
    with pytest.raises(ValueError):
        callback(expected_client_id="")


def test_14_redirect_with_userinfo_is_rejected():
    with pytest.raises(ValueError):
        callback(redirect_uri="https://user@app.example.com/cb")


def test_15_redirect_with_fragment_is_rejected():
    with pytest.raises(ValueError):
        callback(redirect_uri="https://app.example.com/cb#fragment")
