import hmac
import json
import threading


_GENESIS_HASH = "0" * 64
_RECORD_FIELDS = frozenset(("seq", "event", "prev_hash", "hash"))
_CHAIN_LOCK = threading.Lock()


def _validate_chain(chain):
    if not isinstance(chain, list):
        raise ValueError("chain must be a list")


def _secret_bytes(secret):
    if isinstance(secret, str):
        if not secret:
            raise ValueError("secret must not be empty")
        return secret.encode("utf-8")
    if isinstance(secret, (bytes, bytearray)):
        if not secret:
            raise ValueError("secret must not be empty")
        return bytes(secret)
    raise ValueError("secret must be a non-empty string or bytes")


def _canonical_json(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("event must be JSON serializable") from exc


def _digest(secret, seq, prev_hash, event, algorithm):
    payload = _canonical_json(
        {"seq": seq, "prev_hash": prev_hash, "event": event}
    )
    return hmac.new(secret, payload, algorithm).hexdigest()


def append(chain, event, secret, algorithm="sha256"):
    _validate_chain(chain)
    if not isinstance(event, dict) or not event:
        raise ValueError("event must be a non-empty dict")
    secret = _secret_bytes(secret)

    with _CHAIN_LOCK:
        if chain:
            previous = chain[-1]
            if not isinstance(previous, dict):
                raise ValueError("chain entries must be dicts")
            try:
                prev_hash = previous["hash"]
                last_seq = previous["seq"]
            except KeyError as exc:
                raise ValueError("chain entries must contain hash and seq") from exc
            if type(last_seq) is not int or last_seq < 1:
                raise ValueError("chain sequence is invalid")
            if not isinstance(prev_hash, str):
                raise ValueError("chain hash is invalid")
            seq = last_seq + 1
        else:
            prev_hash = _GENESIS_HASH
            seq = 1

        entry = {
            "seq": seq,
            "event": event,
            "prev_hash": prev_hash,
            "hash": _digest(secret, seq, prev_hash, event, algorithm),
        }
        chain.append(entry)
        return entry


def verify(chain, secret, algorithm="sha256"):
    _validate_chain(chain)
    secret = _secret_bytes(secret)

    with _CHAIN_LOCK:
        if not chain:
            return False

        prev_hash = _GENESIS_HASH
        for expected_seq, entry in enumerate(chain, start=1):
            if not isinstance(entry, dict) or set(entry) != _RECORD_FIELDS:
                return False

            seq = entry["seq"]
            event = entry["event"]
            stored_prev_hash = entry["prev_hash"]
            stored_hash = entry["hash"]

            if type(seq) is not int or seq != expected_seq:
                return False
            if not isinstance(event, dict) or not event:
                return False
            if not isinstance(stored_prev_hash, str):
                return False
            if not isinstance(stored_hash, str):
                return False
            if not hmac.compare_digest(stored_prev_hash, prev_hash):
                return False

            try:
                expected_hash = _digest(
                    secret, seq, stored_prev_hash, event, algorithm
                )
            except (TypeError, ValueError):
                return False
            if not hmac.compare_digest(stored_hash, expected_hash):
                return False

            prev_hash = stored_hash

        return True
