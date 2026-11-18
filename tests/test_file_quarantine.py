import pytest

from file_quarantine import decide

POLICY = {"allowed_mimes": ["image/png", "application/pdf"], "max_size": 10000000, "blocked_extensions": ["exe", "js"]}
GOOD = {"size": 100, "sha256": "ab" * 32, "mime": "image/png", "extension": "png", "scan": "clean", "encrypted": False}


def test_infected_file_is_quarantined():
    assert decide({**GOOD, "scan": "infected"}, POLICY) == "quarantine"


def test_pending_scan_is_rejected():
    with pytest.raises(ValueError):
        decide({**GOOD, "scan": "pending"}, POLICY)


def test_oversized_file_is_rejected():
    with pytest.raises(ValueError):
        decide({**GOOD, "size": 10000001}, POLICY)


def test_bad_hash_is_rejected():
    with pytest.raises(ValueError):
        decide({**GOOD, "sha256": "zz"}, POLICY)


def test_disallowed_mime_is_rejected():
    with pytest.raises(ValueError):
        decide({**GOOD, "mime": "text/html"}, POLICY)


def test_blocked_extension_is_quarantined():
    assert decide({**GOOD, "extension": "exe"}, POLICY) == "quarantine"


def test_encrypted_file_is_quarantined():
    assert decide({**GOOD, "encrypted": True}, POLICY) == "quarantine"


def test_non_dict_meta_is_rejected():
    with pytest.raises(ValueError):
        decide("meta", POLICY)


def test_missing_scan_is_rejected():
    bad = dict(GOOD)
    del bad["scan"]
    with pytest.raises(ValueError):
        decide(bad, POLICY)


def test_non_string_hash_is_rejected():
    with pytest.raises(ValueError):
        decide({**GOOD, "sha256": 123}, POLICY)


def test_negative_size_is_rejected():
    with pytest.raises(ValueError):
        decide({**GOOD, "size": -1}, POLICY)


def test_non_dict_policy_is_rejected():
    with pytest.raises(ValueError):
        decide(GOOD, "policy")


def test_empty_allowed_mimes_is_rejected():
    with pytest.raises(ValueError):
        decide(GOOD, {**POLICY, "allowed_mimes": []})


def test_unknown_scan_state_is_rejected():
    with pytest.raises(ValueError):
        decide({**GOOD, "scan": "weird"}, POLICY)


def test_empty_extension_is_rejected():
    with pytest.raises(ValueError):
        decide({**GOOD, "extension": ""}, POLICY)
