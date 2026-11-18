import os


def resolve_key_path(kid, key_dir, allowed_ids):
    return os.path.join(key_dir, kid)
