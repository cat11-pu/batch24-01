import copy
import threading

STATE_ACTIVE = "active"

# Canonical seed state. Tests never mutate this directly; the live
# COUPONS table is rebuilt from it before every test via _reset_coupon_state.
_COUPON_SEED = {
    "C1": {
        "activity_id": "A1",
        "owner": "alice",
        "expires_at": 1000,
        "limit": 1,
        "state": STATE_ACTIVE,
        "redeemed_by": [],
    }
}

COUPONS = copy.deepcopy(_COUPON_SEED)
_LOCK = threading.RLock()


def _reset_coupon_state():
    with _LOCK:
        COUPONS.clear()
        COUPONS.update(copy.deepcopy(_COUPON_SEED))


def _require_text(value, error):
    if not isinstance(value, str):
        raise TypeError(error)
    if not value:
        raise ValueError(error)


def redeem(coupon, user, now):
    _require_text(coupon, "coupon id is required")
    _require_text(user, "user id is required")
    if not isinstance(now, int) or isinstance(now, bool) or now < 0:
        raise ValueError("redemption time is invalid")

    with _LOCK:
        record = COUPONS.get(coupon)
        if record is None:
            raise ValueError("unknown coupon")

        if record.get("state") != STATE_ACTIVE:
            raise ValueError("coupon is not active")

        expires_at = record.get("expires_at")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise ValueError("coupon expiry is invalid")
        if now >= expires_at:
            raise ValueError("coupon has expired")

        if record.get("owner") != user:
            raise ValueError("coupon is bound to another user")

        limit = record.get("limit")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("coupon redemption limit is invalid")

        redeemed_by = record.setdefault("redeemed_by", [])
        if user in redeemed_by:
            raise ValueError("duplicate redemption rejected")
        if len(redeemed_by) >= limit:
            raise ValueError("coupon redemption limit has been reached")

        redeemed_by.append(user)
        if len(redeemed_by) >= limit:
            record["state"] = "used"
        return True
