import threading

import pytest

import secret_exposure as se

RULES = [{"id": "token", "pattern": "token=", "severity": "high"}, {"id": "key", "pattern": "api_key=", "severity": "low"}]


def test_files_must_be_dict():
    with pytest.raises(ValueError):
        se.scan([], RULES, set())


def test_rules_must_be_list():
    with pytest.raises(ValueError):
        se.scan({"a.py": "x"}, "rules", set())


def test_rule_must_be_dict():
    with pytest.raises(ValueError):
        se.scan({"a.py": "x"}, ["rule"], set())


def test_missing_rule_id_is_rejected():
    with pytest.raises(ValueError):
        se.scan({"a.py": "x"}, [{"pattern": "x", "severity": "low"}], set())


def test_invalid_severity_is_rejected():
    with pytest.raises(ValueError):
        se.scan({"a.py": "x"}, [{"id": "x", "pattern": "x", "severity": "weird"}], set())


def test_empty_pattern_is_rejected():
    with pytest.raises(ValueError):
        se.scan({"a.py": "x"}, [{"id": "x", "pattern": "", "severity": "low"}], set())


def test_high_severity_secret_blocks():
    assert se.scan({"a.py": "token=abc"}, RULES, set())["blocked"] is True


def test_finding_contains_path():
    out = se.scan({"a.py": "token=abc"}, RULES, set())
    assert out["findings"][0]["path"] == "a.py"


def test_duplicate_rule_ids_are_rejected():
    with pytest.raises(ValueError):
        se.scan({"a.py": "token=abc"}, [RULES[0], RULES[0]], set())


def test_non_string_path_is_rejected():
    with pytest.raises(ValueError):
        se.scan({123: "token=abc"}, RULES, set())


def test_non_string_content_is_rejected():
    with pytest.raises(ValueError):
        se.scan({"a.py": 123}, RULES, set())


def test_non_string_pattern_is_rejected():
    with pytest.raises(ValueError):
        se.scan({"a.py": "x"}, [{"id": "x", "pattern": 123, "severity": "low"}], set())


def test_low_severity_finding_is_still_reported():
    out = se.scan({"a.py": "api_key=abc"}, RULES, set())
    assert len(out["findings"]) >= 1


def test_non_string_rule_id_is_rejected():
    with pytest.raises(ValueError):
        se.scan({"a.py": "x"}, [{"id": 123, "pattern": "x", "severity": "low"}], set())


def test_concurrent_scan_is_consistent():
    results = []

    def worker():
        results.append(se.scan({"a.py": "token=abc"}, RULES, set())["blocked"])

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [True, True]
