import threading

import pytest

import waf_rules as wr

RULES = [
    {"id": "sqli", "target": "query", "pattern": "union select", "score": 10},
    {"id": "xss", "target": "body", "pattern": "<script", "score": 10},
    {"id": "traversal", "target": "path", "pattern": "../", "score": 10},
]
REQ = {"path": "/a", "query": "x=1", "body": "hello"}


def test_request_must_be_dict():
    with pytest.raises(ValueError):
        wr.inspect("request", RULES)


def test_rules_must_be_list():
    with pytest.raises(ValueError):
        wr.inspect(REQ, "rules")


def test_unknown_target_is_rejected():
    with pytest.raises(ValueError):
        wr.inspect(REQ, [{"id": "x", "target": "cookie", "pattern": "a", "score": 1}])


def test_unknown_pattern_type_is_rejected():
    with pytest.raises(ValueError):
        wr.inspect(REQ, [{"id": "x", "target": "path", "type": "glob", "pattern": "a", "score": 1}])


def test_empty_pattern_is_rejected():
    with pytest.raises(ValueError):
        wr.inspect(REQ, [{"id": "x", "target": "path", "pattern": "", "score": 1}])


def test_negative_score_is_rejected():
    with pytest.raises(ValueError):
        wr.inspect(REQ, [{"id": "x", "target": "path", "pattern": "a", "score": -1}])


def test_missing_rule_id_is_rejected():
    with pytest.raises(ValueError):
        wr.inspect(REQ, [{"target": "path", "pattern": "a", "score": 1}])


def test_path_traversal_is_blocked():
    assert wr.inspect({"path": "/a/../etc/passwd", "query": "", "body": ""}, RULES)["action"] == "block"


def test_sql_injection_is_blocked():
    assert wr.inspect({"path": "/a", "query": "x=1 union select 1", "body": ""}, RULES)["action"] == "block"


def test_xss_is_blocked():
    assert wr.inspect({"path": "/a", "query": "", "body": "<script>alert(1)</script>"}, RULES)["action"] == "block"


def test_encoded_traversal_is_blocked():
    assert wr.inspect({"path": "/a/%2e%2e/etc/passwd", "query": "", "body": ""}, RULES)["action"] == "block"


def test_case_insensitive_match():
    assert wr.inspect({"path": "/a", "query": "X=1 UNION SELECT 1", "body": ""}, RULES)["action"] == "block"


def test_scores_accumulate_to_block():
    assert wr.inspect({"path": "/a/../x", "query": "q=union select", "body": "<script>"}, RULES)["score"] >= 20


def test_concurrent_inspection_is_consistent():
    results = []

    def worker():
        results.append(wr.inspect({"path": "/a/../x", "query": "", "body": ""}, RULES)["action"])

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == ["block", "block"]


def test_request_fields_must_be_strings():
    with pytest.raises(ValueError):
        wr.inspect({"path": 123, "query": "", "body": ""}, RULES)
