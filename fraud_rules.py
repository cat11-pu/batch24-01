"""Deterministic rule-based fraud risk scoring."""

import math
import numbers


RULE_TYPES = frozenset({"amount", "velocity", "geo", "new_device", "chargebacks"})
THRESHOLD_RULE_TYPES = frozenset({"amount", "velocity", "chargebacks"})

REVIEW_THRESHOLD = 10
BLOCK_THRESHOLD = 30
MAX_SCORE = 100


def _is_int(value):
    return type(value) is int


def _is_number(value):
    return isinstance(value, numbers.Real) and not isinstance(value, bool)


def _number(value, name, minimum=0):
    if not _is_number(value) or not math.isfinite(value) or value < minimum:
        raise ValueError("%s must be a finite number >= %s" % (name, minimum))
    return value


def _validate_event(event):
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")

    event_id = event.get("id")
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("event id must be a non-empty string")

    if "amount" not in event:
        raise ValueError("event amount is required")
    amount = _number(event["amount"], "event amount")

    if not isinstance(event.get("geo"), str):
        raise ValueError("event geo must be a string")
    if not isinstance(event.get("device"), str):
        raise ValueError("event device must be a string")
    return amount


def _validate_profile(profile):
    if not isinstance(profile, dict):
        raise ValueError("profile must be a dict")

    if "velocity" not in profile:
        raise ValueError("profile velocity is required")
    velocity = _number(profile["velocity"], "profile velocity")

    if not isinstance(profile.get("home_geo"), str):
        raise ValueError("profile home_geo must be a string")

    known_devices = profile.get("known_devices")
    if not isinstance(known_devices, (list, tuple, set, frozenset)):
        raise ValueError("profile known_devices must be a collection of strings")
    if not all(isinstance(device, str) for device in known_devices):
        raise ValueError("profile known_devices must contain only strings")

    chargebacks = profile.get("chargebacks")
    if not _is_int(chargebacks) or chargebacks < 0:
        raise ValueError("profile chargebacks must be a non-negative integer")

    return velocity, known_devices, chargebacks


def _validate_rules(rules):
    if not isinstance(rules, list) or not rules:
        raise ValueError("rules must be a non-empty list")

    validated = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError("rule %d must be a dict" % index)

        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or rule_type not in RULE_TYPES:
            raise ValueError("rule %d has an unknown type" % index)

        if "weight" not in rule:
            raise ValueError("rule %d is missing weight" % index)
        weight = rule["weight"]
        if not _is_int(weight) or weight < 0:
            raise ValueError("rule %d weight must be a non-negative integer" % index)

        threshold = None
        if rule_type in THRESHOLD_RULE_TYPES:
            if "threshold" not in rule:
                raise ValueError("rule %d is missing threshold" % index)
            threshold = _number(rule["threshold"], "rule %d threshold" % index)
        elif "threshold" in rule:
            _number(rule["threshold"], "rule %d threshold" % index)

        validated.append((rule_type, weight, threshold))
    return validated


def _validate_threshold(value, name):
    if not _is_int(value) or value < 0:
        raise ValueError("%s must be a non-negative integer" % name)
    return value


def _threshold_units(value, threshold):
    if threshold == 0:
        return 1
    return max(1, int(value // threshold))


def score(
    event,
    profile,
    rules,
    now,
    review_threshold=None,
    block_threshold=None,
):
    """Score an event against the supplied rules and choose an action."""
    if not _is_int(now):
        raise ValueError("now must be an integer")

    amount = _validate_event(event)
    velocity, known_devices, chargebacks = _validate_profile(profile)
    validated_rules = _validate_rules(rules)

    review_threshold = _validate_threshold(
        REVIEW_THRESHOLD if review_threshold is None else review_threshold,
        "review threshold",
    )
    block_threshold = _validate_threshold(
        BLOCK_THRESHOLD if block_threshold is None else block_threshold,
        "block threshold",
    )
    if review_threshold > block_threshold:
        raise ValueError("review threshold cannot exceed block threshold")

    total = 0
    for rule_type, weight, threshold in validated_rules:
        if rule_type == "amount":
            contribution = (
                weight * _threshold_units(amount, threshold)
                if amount >= threshold
                else 0
            )
        elif rule_type == "velocity":
            contribution = (
                weight * _threshold_units(velocity, threshold)
                if velocity >= threshold
                else 0
            )
        elif rule_type == "geo":
            contribution = weight if event["geo"] != profile["home_geo"] else 0
        elif rule_type == "new_device":
            contribution = weight if event["device"] not in known_devices else 0
        else:
            contribution = (
                weight * _threshold_units(chargebacks, threshold)
                if chargebacks >= threshold
                else 0
            )

        if contribution:
            total += contribution
            if total >= MAX_SCORE:
                total = MAX_SCORE
                break

    if total < review_threshold:
        decision = "allow"
    elif total < block_threshold:
        decision = "review"
    else:
        decision = "block"

    return {"score": total, "decision": decision}
