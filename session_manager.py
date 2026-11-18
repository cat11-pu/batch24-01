def login(store, user, device, now, max_sessions=3):
    return "sid"


def touch(store, sid, now, idle=900, absolute=28800):
    return True


def revoke(store, sid):
    return None


def revoke_user(store, user):
    return 0
