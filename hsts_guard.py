def hsts_header(max_age, include_subdomains, preload, min_age=15552000, max_age_limit=63072000):
    return f"max-age={max_age}"
