def respond(user_exists, password_ok, locked):
    if not user_exists:
        return "user not found"
    if locked:
        return "account locked"
    if not password_ok:
        return "wrong password"
    return "ok"
