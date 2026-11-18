import pytest

from json_pointer import resolve

DOC = {"a": [10, 20], "b": {"c": 1}}


def test_pointer_without_leading_slash_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, "a", 10)


def test_none_pointer_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, None, 10)


def test_non_string_pointer_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, 123, 10)


def test_proto_segment_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, "/__proto__", 10)


def test_constructor_segment_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, "/a/constructor", 10)


def test_prototype_segment_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, "/b/prototype", 10)


def test_invalid_escape_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, "/a/~2", 10)


def test_incomplete_escape_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, "/a/~", 10)


def test_leading_zero_index_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, "/a/01", 10)


def test_negative_index_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, "/a/-1", 10)


def test_out_of_range_index_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, "/a/99", 10)


def test_depth_limit_is_enforced():
    with pytest.raises(ValueError):
        resolve(DOC, "/b/c/d/e/f/g/h/i/j/k/l", 10)


def test_non_container_document_is_rejected():
    with pytest.raises(ValueError):
        resolve("doc", "", 10)


def test_percent_encoding_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, "/b%20c", 10)


def test_zero_depth_is_rejected():
    with pytest.raises(ValueError):
        resolve(DOC, "", 0)
