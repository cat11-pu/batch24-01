import pytest

from fraud_rules import score

RULES = [
    {"type": "amount", "weight": 30, "threshold": 1000},
    {"type": "velocity", "weight": 25, "threshold": 5},
    {"type": "geo", "weight": 20},
    {"type": "new_device", "weight": 15},
    {"type": "chargebacks", "weight": 10, "threshold": 2},
]
EVENT = {"id": "e1", "amount": 100, "geo": "US", "device": "d1"}
PROFILE = {"velocity": 0, "home_geo": "US", "known_devices": ["d1"], "chargebacks": 0}


def test_event_must_be_dict():
    with pytest.raises(ValueError):
        score("event", PROFILE, RULES, 1000)


def test_profile_must_be_dict():
    with pytest.raises(ValueError):
        score(EVENT, "profile", RULES, 1000)


def test_rules_must_be_list():
    with pytest.raises(ValueError):
        score(EVENT, PROFILE, "rules", 1000)


def test_negative_amount_is_rejected():
    with pytest.raises(ValueError):
        score({**EVENT, "amount": -1}, PROFILE, RULES, 1000)


def test_high_velocity_blocks():
    out = score(EVENT, {**PROFILE, "velocity": 10}, RULES, 1000)
    assert out["decision"] in ("review", "block")


def test_geo_mismatch_adds_risk():
    out = score({**EVENT, "geo": "RU"}, PROFILE, RULES, 1000)
    assert out["score"] > 0


def test_new_device_adds_risk():
    out = score({**EVENT, "device": "new"}, PROFILE, RULES, 1000)
    assert out["score"] > 0


def test_chargebacks_add_risk():
    out = score(EVENT, {**PROFILE, "chargebacks": 5}, RULES, 1000)
    assert out["score"] > 0


def test_unknown_rule_type_is_rejected():
    with pytest.raises(ValueError):
        score(EVENT, PROFILE, [{"type": "ghost", "weight": 10}], 1000)


def test_missing_weight_is_rejected():
    with pytest.raises(ValueError):
        score(EVENT, PROFILE, [{"type": "amount", "threshold": 100}], 1000)


def test_score_is_capped_at_100():
    out = score({**EVENT, "amount": 100000}, {**PROFILE, "velocity": 100, "chargebacks": 100}, RULES, 1000)
    assert out["score"] == 100


def test_empty_rules_are_rejected():
    with pytest.raises(ValueError):
        score(EVENT, PROFILE, [], 1000)


def test_non_integer_time_is_rejected():
    with pytest.raises(ValueError):
        score(EVENT, PROFILE, RULES, "now")


def test_empty_event_id_is_rejected():
    with pytest.raises(ValueError):
        score({**EVENT, "id": ""}, PROFILE, RULES, 1000)


def test_high_amount_blocks():
    out = score({**EVENT, "amount": 100000}, PROFILE, RULES, 1000)
    assert out["decision"] == "block"
