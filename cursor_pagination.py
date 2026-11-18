def encode_cursor(payload, secret):
    return "cursor"


def decode_cursor(token, secret, filters, now, ttl=300, max_limit=100):
    return {}
