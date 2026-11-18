def parse_query(qs):
    out = {}
    for part in qs.split("&"):
        if "=" in part:
            key, value = part.split("=", 1)
            out[key] = value
    return out
