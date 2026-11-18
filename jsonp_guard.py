def wrap_jsonp(callback, data, max_len=64):
    return f"{callback}({data});"
