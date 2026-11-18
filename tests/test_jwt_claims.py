import pytest

from jwt_claims import validate_claims

NOW = 1000000
ISS = "https://issuer.example"
AUD = "app"

BAD_PAYLOADS = [
    {},
    {"exp": NOW + 60},
    {"iat": NOW},
    {"exp": NOW - 1, "iat": NOW - 10, "iss": ISS, "aud": AUD},
    {"exp": NOW + 60, "iat": NOW + 10, "iss": ISS, "aud": AUD},
    {"exp": NOW + 60, "iat": NOW - 10, "iss": "evil", "aud": AUD},
    {"exp": NOW + 60, "iat": NOW - 10, "iss": ISS, "aud": "other"},
    {"exp": str(NOW + 60), "iat": NOW - 10, "iss": ISS, "aud": AUD},
    {"exp": NOW + 60, "iat": str(NOW - 10), "iss": ISS, "aud": AUD},
    {"exp": NOW + 60, "iat": NOW - 10, "nbf": NOW + 30, "iss": ISS, "aud": AUD},
    {"exp": NOW + 100000, "iat": NOW - 10, "iss": ISS, "aud": AUD},
    {"exp": NOW + 60, "iat": NOW + 60, "iss": ISS, "aud": AUD},
    None,
    ["not", "dict"],
    {"exp": NOW + 60, "iat": NOW - 10, "aud": AUD},
]


@pytest.mark.parametrize("payload", BAD_PAYLOADS)
def test_bad_jwt_claims_are_rejected(payload):
    with pytest.raises(ValueError):
        validate_claims(payload, NOW, ISS, AUD, 300)
