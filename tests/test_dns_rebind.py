import pytest

from dns_rebind import check_host

BAD_CASES = [
    ("a.example", ["127.0.0.1"]),
    ("a.example", ["10.0.0.1"]),
    ("a.example", ["192.168.1.1"]),
    ("a.example", ["172.16.0.1"]),
    ("a.example", ["169.254.169.254"]),
    ("a.example", ["::1"]),
    ("a.example", ["fc00::1"]),
    ("a.example", ["0.0.0.0"]),
    ("a.example", []),
    ("a.example", ["8.8.8.8", "10.0.0.1"]),
    ("", ["8.8.8.8"]),
    (None, ["8.8.8.8"]),
    (123, ["8.8.8.8"]),
    ("a.example\n", ["8.8.8.8"]),
    ("a.example", None),
]


@pytest.mark.parametrize("host,resolved", BAD_CASES)
def test_private_or_missing_resolution_is_rejected(host, resolved):
    def resolver(name):
        return resolved

    with pytest.raises(ValueError):
        check_host(host, resolver, {"8.8.8.8"})
