import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from audit_log import write_event


def test_1_newline_in_field_is_escaped(tmp_path):
    path = tmp_path / "audit.log"
    write_event(path, "login", {"user": "alice\nlevel=admin"})
    text = path.read_text(encoding="utf-8")
    assert len(text.splitlines()) == 1


def test_2_crlf_in_field_is_escaped(tmp_path):
    path = tmp_path / "audit.log"
    write_event(path, "login", {"user": "alice\r\nlevel=admin"})
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_3_ansi_escape_is_escaped(tmp_path):
    path = tmp_path / "audit.log"
    write_event(path, "login", {"user": "\x1b[31mred"})
    assert "\x1b" not in path.read_text(encoding="utf-8")


def test_4_nul_is_rejected(tmp_path):
    path = tmp_path / "audit.log"
    with pytest.raises(ValueError):
        write_event(path, "login", {"user": "alice\x00bob"})


def test_5_unicode_line_separator_is_escaped(tmp_path):
    path = tmp_path / "audit.log"
    write_event(path, "login", {"user": "alice\u2028bob"})
    assert "\u2028" not in path.read_text(encoding="utf-8")


def test_6_field_name_injection_is_rejected(tmp_path):
    path = tmp_path / "audit.log"
    with pytest.raises(ValueError):
        write_event(path, "login", {"user\nlevel": "admin"})


def test_7_password_is_redacted(tmp_path):
    path = tmp_path / "audit.log"
    write_event(path, "login", {"user": "alice", "password": "secret"})
    assert "secret" not in path.read_text(encoding="utf-8")


def test_8_token_is_redacted(tmp_path):
    path = tmp_path / "audit.log"
    write_event(path, "login", {"user": "alice", "token": "tok-123"})
    assert "tok-123" not in path.read_text(encoding="utf-8")


def test_9_non_string_value_is_rejected(tmp_path):
    path = tmp_path / "audit.log"
    with pytest.raises(TypeError):
        write_event(path, "login", {"user": 123})


def test_10_oversized_value_is_rejected(tmp_path):
    path = tmp_path / "audit.log"
    with pytest.raises(ValueError):
        write_event(path, "login", {"user": "x" * 2048})


def test_11_unknown_event_is_rejected(tmp_path):
    path = tmp_path / "audit.log"
    with pytest.raises(ValueError):
        write_event(path, "debug", {"user": "alice"})


def test_12_output_is_json_line(tmp_path):
    path = tmp_path / "audit.log"
    write_event(path, "login", {"user": "alice", "ip": "1.2.3.4"})
    payload = json.loads(path.read_text(encoding="utf-8").strip())
    assert payload["event"] == "login"


def test_13_concurrent_writes_have_unique_sequence(tmp_path):
    path = tmp_path / "audit.log"

    def worker(i):
        return write_event(path, "login", {"user": f"user{i}"})

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(worker, range(32)))
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len({line["seq"] for line in lines}) == 32


def test_14_unknown_field_is_rejected(tmp_path):
    path = tmp_path / "audit.log"
    with pytest.raises(ValueError):
        write_event(path, "login", {"role": "admin"})


def test_15_empty_event_is_rejected(tmp_path):
    path = tmp_path / "audit.log"
    with pytest.raises(ValueError):
        write_event(path, "", {"user": "alice"})
