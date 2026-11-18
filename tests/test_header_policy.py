import pytest

from header_policy import build_headers

POLICY = {
    "hsts": {"max_age": 31536000, "include_subdomains": True},
    "frame": "DENY",
    "allow_from": "",
    "csp_nonce": "abcdefghijklmnop",
    "cookie": {"samesite": "Lax", "secure": True},
    "cors": {"allowed_origins": ["https://app.example"]},
}
REQ = {"origin": "https://app.example", "secure": True}


def test_policy_must_be_dict():
    with pytest.raises(ValueError):
        build_headers("policy", REQ)


def test_request_must_be_dict():
    with pytest.raises(ValueError):
        build_headers(POLICY, "request")


def test_hsts_on_insecure_request_is_rejected():
    with pytest.raises(ValueError):
        build_headers(POLICY, {**REQ, "secure": False})


def test_zero_max_age_is_rejected():
    with pytest.raises(ValueError):
        build_headers({**POLICY, "hsts": {"max_age": 0, "include_subdomains": True}}, REQ)


def test_max_age_over_two_years_is_rejected():
    with pytest.raises(ValueError):
        build_headers({**POLICY, "hsts": {"max_age": 63072001, "include_subdomains": True}}, REQ)


def test_invalid_frame_mode_is_rejected():
    with pytest.raises(ValueError):
        build_headers({**POLICY, "frame": "ALLOW"}, REQ)


def test_allow_from_without_origin_is_rejected():
    with pytest.raises(ValueError):
        build_headers({**POLICY, "frame": "ALLOW-FROM", "allow_from": ""}, REQ)


def test_short_nonce_is_rejected():
    with pytest.raises(ValueError):
        build_headers({**POLICY, "csp_nonce": "abc"}, REQ)


def test_invalid_nonce_characters_are_rejected():
    with pytest.raises(ValueError):
        build_headers({**POLICY, "csp_nonce": "!!!!!!!!!!!!!!!!"}, REQ)


def test_samesite_none_without_secure_is_rejected():
    with pytest.raises(ValueError):
        build_headers({**POLICY, "cookie": {"samesite": "None", "secure": False}}, REQ)


def test_invalid_samesite_value_is_rejected():
    with pytest.raises(ValueError):
        build_headers({**POLICY, "cookie": {"samesite": "Sometimes", "secure": True}}, REQ)


def test_untrusted_origin_is_rejected():
    with pytest.raises(ValueError):
        build_headers(POLICY, {**REQ, "origin": "https://evil.example"})


def test_missing_origin_is_rejected():
    with pytest.raises(ValueError):
        build_headers(POLICY, {**REQ, "origin": None})


def test_empty_allowed_origins_is_rejected():
    with pytest.raises(ValueError):
        build_headers({**POLICY, "cors": {"allowed_origins": []}}, REQ)


def test_non_integer_max_age_is_rejected():
    with pytest.raises(ValueError):
        build_headers({**POLICY, "hsts": {"max_age": "31536000", "include_subdomains": True}}, REQ)
