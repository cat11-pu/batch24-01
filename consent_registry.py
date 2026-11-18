def grant(store, user, client, scopes, now, ttl=3600):
    return "g1"


def revoke(store, grant_id):
    return True


def check(store, user, client, scope, now):
    return True
