ALLOWED_HOSTS = {"app.example.com"}


def validate_reset_host(host):
    return True


def build_reset_link(host, token):
    return f"https://{host}/reset?token={token}"
