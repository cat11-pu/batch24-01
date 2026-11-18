"""Request inspection against a table of WAF signatures."""

import math
from urllib.parse import unquote


DEFAULT_THRESHOLD = 10

_TARGETS = ("path", "query", "body")
_PATTERN_TYPES = frozenset({"contains", "literal", "substring"})


def _is_score(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return isinstance(value, int) or math.isfinite(value)


def _validate_request(request):
    if not isinstance(request, dict):
        raise ValueError("request must be a dict")

    for field in _TARGETS:
        if field not in request:
            raise ValueError("request is missing field: %s" % field)
        if not isinstance(request[field], str):
            raise ValueError("request field must be a string: %s" % field)


def _validate_threshold(threshold):
    if not _is_score(threshold) or threshold < 0:
        raise ValueError("threshold must be a non-negative number")


def _validate_rules(rules):
    if not isinstance(rules, list):
        raise ValueError("rules must be a list")

    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("each rule must be a dict")

        for field in ("id", "target", "pattern", "score"):
            if field not in rule:
                raise ValueError("rule is missing field: %s" % field)

        if not isinstance(rule["id"], str) or not rule["id"]:
            raise ValueError("rule id must be a non-empty string")

        if not isinstance(rule["target"], str) or rule["target"] not in _TARGETS:
            raise ValueError("unknown rule target: %r" % (rule["target"],))

        if not isinstance(rule["pattern"], str) or not rule["pattern"]:
            raise ValueError("rule pattern must be a non-empty string")

        if not _is_score(rule["score"]) or rule["score"] < 0:
            raise ValueError("rule score must be a non-negative number")

        pattern_type = rule.get("type", "contains")
        if (
            not isinstance(pattern_type, str)
            or pattern_type.casefold() not in _PATTERN_TYPES
        ):
            raise ValueError("unknown rule pattern type: %r" % (pattern_type,))


def inspect(request, rules, threshold=DEFAULT_THRESHOLD):
    """Inspect *request* using *rules* and return the blocking decision.

    ``threshold`` is the minimum accumulated score that blocks a request.  Each
    request field is percent-decoded exactly once and matching is
    case-insensitive.  Invalid requests, rules, or thresholds raise ValueError.
    """

    _validate_request(request)
    _validate_rules(rules)
    _validate_threshold(threshold)

    fields = {name: unquote(request[name]).casefold() for name in _TARGETS}
    score = 0
    matched = []

    for rule in rules:
        pattern = rule["pattern"].casefold()
        if pattern in fields[rule["target"]]:
            score += rule["score"]
            matched.append(rule["id"])

    return {
        "action": "block" if score >= threshold else "allow",
        "score": score,
        "matched": matched,
    }
