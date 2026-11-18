from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}


def validate_url(url, allowed_hosts=None):
    return True
