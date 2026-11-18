import pytest

from idempotency_guard import register

BAD_KEYS = [
    "",
    None,
    123,
    "a" * 300,
    "bad key",
    "key\n",
    "key\x00",
    "key/with/slash",
]

BAD_HASHES = [
    "",
    None,
    123,
    "nothex",
]


@pytest.mark.parametrize("key", BAD_KEYS)
def test_bad_key_is_rejected(key):
    with pytest.raises(ValueError):
        register({}, key, "ab" * 32, 128)


@pytest.mark.parametrize("value", BAD_HASHES)
def test_bad_hash_is_rejected(value):
    with pytest.raises(ValueError):
        register({}, "order-1", value, 128)


def test_same_hash_is_replay():
    store = {}
    assert register(store, "order-1", "ab" * 32, 128) is True
    assert register(store, "order-1", "ab" * 32, 128) is False


def test_different_hash_conflicts():
    store = {}
    register(store, "order-1", "ab" * 32, 128)
    with pytest.raises(ValueError):
        register(store, "order-1", "cd" * 32, 128)


def test_store_must_be_dict():
    with pytest.raises(ValueError):
        register([], "order-1", "ab" * 32, 128)
