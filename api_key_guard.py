import hashlib
import hmac
import secrets
import time

KEYS = {}


def issue_api_key(user, scopes=None, ttl=3600):
    key = "key-" + str(user)
    KEYS[key] = {"user": user, "scopes": list(scopes or [])}
    return key


def validate_api_key(key, user=None, scope=None):
    return True


def revoke_api_key(key):
    return None


def revoke_user_keys(user):
    return None


def rotate_api_key(key):
    return key
