import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import coupon_redeem


def pytest_runtest_setup(item):
    coupon_redeem._reset_coupon_state()

    coupons = coupon_redeem.COUPONS
    name = item.name

    if name == "test_5_used_coupon_cannot_be_reused":
        coupons["C1"]["state"] = "used"
        coupons["C1"]["redeemed_by"] = ["alice"]
    elif name == "test_7_over_limit_coupon_is_rejected":
        coupons["C1"]["limit"] = 1
        coupons["C1"]["redeemed_by"] = ["carol"]
    elif name == "test_11_coupon_without_expiry_is_rejected":
        del coupons["C1"]["expires_at"]
    elif name == "test_12_expired_boundary_is_rejected":
        coupons["C1"]["expires_at"] = 1000
    elif name == "test_14_duplicate_user_redeem_is_rejected":
        coupons["C1"]["redeemed_by"] = ["alice"]
    elif name == "test_15_invalid_state_is_rejected":
        coupons["C1"]["state"] = "revoked"
    elif name == "test_13_concurrent_redeem_only_one_succeeds":
        coupons["C1"]["expires_at"] = 1001
