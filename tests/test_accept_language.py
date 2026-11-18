import pytest

from accept_language import negotiate

SUPPORTED = ["en", "fr"]


def test_empty_header_is_rejected():
    with pytest.raises(ValueError):
        negotiate("", SUPPORTED)


def test_none_header_is_rejected():
    with pytest.raises(ValueError):
        negotiate(None, SUPPORTED)


def test_non_string_header_is_rejected():
    with pytest.raises(ValueError):
        negotiate(123, SUPPORTED)


def test_non_numeric_q_is_rejected():
    with pytest.raises(ValueError):
        negotiate("en;q=abc", SUPPORTED)


def test_q_above_one_is_rejected():
    with pytest.raises(ValueError):
        negotiate("en;q=1.5", SUPPORTED)


def test_negative_q_is_rejected():
    with pytest.raises(ValueError):
        negotiate("en;q=-1", SUPPORTED)


def test_duplicate_q_is_rejected():
    with pytest.raises(ValueError):
        negotiate("en;q=0.5;q=0.6", SUPPORTED)


def test_trailing_comma_is_rejected():
    with pytest.raises(ValueError):
        negotiate("en,", SUPPORTED)


def test_leading_comma_is_rejected():
    with pytest.raises(ValueError):
        negotiate(",en", SUPPORTED)


def test_double_semicolon_is_rejected():
    with pytest.raises(ValueError):
        negotiate("en;;", SUPPORTED)


def test_empty_q_is_rejected():
    with pytest.raises(ValueError):
        negotiate("en;q=", SUPPORTED)


def test_all_zero_weights_are_rejected():
    with pytest.raises(ValueError):
        negotiate("en;q=0", SUPPORTED)


def test_highest_weight_wins():
    assert negotiate("fr;q=1,en;q=0.5", SUPPORTED) == "fr"


def test_second_language_can_win():
    assert negotiate("en;q=0.1,fr;q=0.9", SUPPORTED) == "fr"


def test_unsupported_language_falls_back_to_supported():
    assert negotiate("de;q=0.8,fr;q=0.9", SUPPORTED) == "fr"
