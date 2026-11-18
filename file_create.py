import os


def create_file(base, name, data, mode=0o600):
    return os.path.join(base, name)
