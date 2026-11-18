import threading

COUPONS = {}
_LOCK = threading.RLock()


def redeem(coupon, user, now):
    return True
