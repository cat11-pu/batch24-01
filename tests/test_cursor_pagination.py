import pytest

import cursor_pagination as cp

SECRET = "k" * 32
PAYLOAD = {"offset": 10, "limit": 20, "filter": "a"}
FILTERS = {"filter": "a"}


def test_empty_token_is_rejected():
    with pytest.raises(ValueError):
        cp.decode_cursor("", SECRET, FILTERS, 1000)


def test_none_token_is_rejected():
    with pytest.raises(ValueError):
        cp.decode_cursor(None, SECRET, FILTERS, 1000)


def test_non_string_token_is_rejected():
    with pytest.raises(ValueError):
        cp.decode_cursor(123, SECRET, FILTERS, 1000)


def test_malformed_token_is_rejected():
    with pytest.raises(ValueError):
        cp.decode_cursor("not-base64!!", SECRET, FILTERS, 1000)


def test_wrong_secret_is_rejected():
    token = cp.encode_cursor(PAYLOAD, SECRET)
    with pytest.raises(ValueError):
        cp.decode_cursor(token, "z" * 32, FILTERS, 1000)


def test_tampered_token_is_rejected():
    token = cp.encode_cursor(PAYLOAD, SECRET)
    with pytest.raises(ValueError):
        cp.decode_cursor(token + "x", SECRET, FILTERS, 1000)


def test_expired_token_is_rejected():
    token = cp.encode_cursor({**PAYLOAD, "issued_at": 100}, SECRET)
    with pytest.raises(ValueError):
        cp.decode_cursor(token, SECRET, FILTERS, 1000, 300)


def test_future_token_is_rejected():
    token = cp.encode_cursor({**PAYLOAD, "issued_at": 2000}, SECRET)
    with pytest.raises(ValueError):
        cp.decode_cursor(token, SECRET, FILTERS, 1000, 300)


def test_filter_mismatch_is_rejected():
    token = cp.encode_cursor({**PAYLOAD, "issued_at": 900}, SECRET)
    with pytest.raises(ValueError):
        cp.decode_cursor(token, SECRET, {"filter": "b"}, 1000)


def test_non_dict_payload_is_rejected():
    with pytest.raises(ValueError):
        cp.encode_cursor([1, 2], SECRET)


def test_missing_issued_at_is_rejected():
    token = cp.encode_cursor(PAYLOAD, SECRET)
    with pytest.raises(ValueError):
        cp.decode_cursor(token, SECRET, FILTERS, 1000)


def test_limit_above_max_is_rejected():
    token = cp.encode_cursor({**PAYLOAD, "limit": 1000, "issued_at": 900}, SECRET)
    with pytest.raises(ValueError):
        cp.decode_cursor(token, SECRET, FILTERS, 1000, 300, 100)


def test_negative_offset_is_rejected():
    token = cp.encode_cursor({**PAYLOAD, "offset": -1, "issued_at": 900}, SECRET)
    with pytest.raises(ValueError):
        cp.decode_cursor(token, SECRET, FILTERS, 1000)


def test_valid_cursor_round_trips():
    token = cp.encode_cursor({**PAYLOAD, "issued_at": 900}, SECRET)
    out = cp.decode_cursor(token, SECRET, FILTERS, 1000, 300, 100)
    assert out["offset"] == 10 and out["limit"] == 20


def test_non_dict_filters_is_rejected():
    token = cp.encode_cursor({**PAYLOAD, "issued_at": 900}, SECRET)
    with pytest.raises(ValueError):
        cp.decode_cursor(token, SECRET, "filter=a", 1000)
