import pytest

from tls_pinning import verify_peer

PIN = "ab" * 32
PINS = {PIN}
GOOD = {"subject": "CN=app.example", "san": ["app.example"], "not_before": 900, "not_after": 2000, "sig_alg": "sha256", "spki_sha256": PIN}


def rejected(cert, pins=PINS, host="app.example", now=1000):
    try:
        assert verify_peer(cert, pins, host, now) is False
    except ValueError:
        return


def test_expired_certificate_is_rejected():
    rejected({**GOOD, "not_after": 900})


def test_not_yet_valid_certificate_is_rejected():
    rejected({**GOOD, "not_before": 1100})


def test_hostname_mismatch_is_rejected():
    rejected(GOOD, PINS, "evil.example")


def test_wildcard_covers_only_one_label():
    rejected({**GOOD, "san": ["*.example.com"]}, PINS, "a.b.example.com")


def test_weak_algorithm_is_rejected():
    rejected({**GOOD, "sig_alg": "md5"})


def test_pin_mismatch_is_rejected():
    rejected(GOOD, {"cd" * 32})


def test_empty_pins_are_rejected():
    rejected(GOOD, set())


def test_empty_san_is_rejected():
    rejected({**GOOD, "san": []})


def test_non_dict_certificate_is_rejected():
    rejected("cert")


def test_non_integer_time_is_rejected():
    rejected(GOOD, PINS, "app.example", "now")


def test_missing_spki_is_rejected():
    bad = dict(GOOD)
    del bad["spki_sha256"]
    rejected(bad)


def test_non_hex_pin_is_rejected():
    rejected(GOOD, {"zz" * 32})


def test_empty_hostname_is_rejected():
    rejected(GOOD, PINS, "")


def test_san_must_be_list():
    rejected({**GOOD, "san": "app.example"})


def test_non_string_sig_alg_is_rejected():
    rejected({**GOOD, "sig_alg": 123})
