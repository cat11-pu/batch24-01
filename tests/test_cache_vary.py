import pytest

from cache_vary import cache_key

POLICY = {"allowed_hosts": ["app.example"], "vary": ["accept-encoding"]}


def req(**kw):
    base = {"method": "GET", "host": "app.example", "path": "/a", "query": [], "headers": {"accept-encoding": "gzip"}}
    base.update(kw)
    return base


def test_missing_host_is_rejected():
    with pytest.raises(ValueError):
        cache_key(req(host=""), POLICY)


def test_untrusted_host_is_rejected():
    with pytest.raises(ValueError):
        cache_key(req(host="evil.example"), POLICY)


def test_host_with_userinfo_is_rejected():
    with pytest.raises(ValueError):
        cache_key(req(host="u@app.example"), POLICY)


def test_path_traversal_is_rejected():
    with pytest.raises(ValueError):
        cache_key(req(path="/a/../admin"), POLICY)


def test_duplicate_query_keys_are_rejected():
    with pytest.raises(ValueError):
        cache_key(req(query=[("a", "1"), ("a", "2")]), POLICY)


def test_non_standard_port_is_rejected():
    with pytest.raises(ValueError):
        cache_key(req(host="app.example:8443"), POLICY)


def test_fragment_in_path_is_rejected():
    with pytest.raises(ValueError):
        cache_key(req(path="/a#frag"), POLICY)


def test_post_method_is_rejected():
    with pytest.raises(ValueError):
        cache_key(req(method="POST"), POLICY)


def test_missing_vary_header_is_rejected():
    with pytest.raises(ValueError):
        cache_key(req(headers={}), POLICY)


def test_request_must_be_dict():
    with pytest.raises(ValueError):
        cache_key("request", POLICY)


def test_policy_must_be_dict():
    with pytest.raises(ValueError):
        cache_key(req(), "policy")


def test_empty_allowed_hosts_is_rejected():
    with pytest.raises(ValueError):
        cache_key(req(), {"allowed_hosts": [], "vary": []})


def test_path_must_start_with_slash():
    with pytest.raises(ValueError):
        cache_key(req(path="a"), POLICY)


def test_headers_must_be_dict():
    with pytest.raises(ValueError):
        cache_key(req(headers=[]), POLICY)


def test_query_must_be_list():
    with pytest.raises(ValueError):
        cache_key(req(query={"a": 1}), POLICY)
