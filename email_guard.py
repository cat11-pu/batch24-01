import ipaddress
import unicodedata
from email.utils import getaddresses


_ATEXT = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!#$%&'*+-/=?^_`{|}~."
)
_LINE_BREAK_CATEGORIES = frozenset({"Cc", "Zl", "Zp"})


def _check_header_text(value, field_name):
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")

    for character in value:
        if character in "\r\n\x00":
            raise ValueError(f"{field_name} contains a forbidden control character")
        if unicodedata.category(character) in _LINE_BREAK_CATEGORIES:
            raise ValueError(f"{field_name} contains a forbidden control character")


def _split_addr_spec(address):
    in_quotes = False
    escaped = False
    at_index = None

    for index, character in enumerate(address):
        if escaped:
            escaped = False
            continue
        if in_quotes and character == "\\":
            escaped = True
        elif character == '"':
            in_quotes = not in_quotes
        elif character == "@" and not in_quotes:
            if at_index is not None:
                return None
            at_index = index

    if in_quotes or escaped or at_index is None:
        return None

    return address[:at_index], address[at_index + 1 :]


def _valid_local_part(local):
    if not local or len(local) > 64:
        return False

    if local.startswith('"') or local.endswith('"'):
        if len(local) < 2 or not local.startswith('"') or not local.endswith('"'):
            return False
        escaped = False
        for character in local[1:-1]:
            if escaped:
                escaped = False
                continue
            if character == "\\":
                escaped = True
            elif character == '"':
                return False
        return not escaped

    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    return all(character in _ATEXT for character in local)


def _valid_domain(domain):
    if not domain or len(domain) > 253:
        return False

    if domain.startswith("[") and domain.endswith("]"):
        literal = domain[1:-1]
        if literal.lower().startswith("ipv6:"):
            literal = literal[5:]
        try:
            ipaddress.ip_address(literal)
        except ValueError:
            return False
        return True

    if "." not in domain or domain.endswith("."):
        return False

    labels = domain.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(
            character.isascii()
            and (character.isalnum() or character == "-")
            for character in label
        ):
            return False

    return True


def _valid_addr_spec(address):
    if not isinstance(address, str) or not address or len(address) > 254:
        return False

    parts = _split_addr_spec(address)
    if parts is None:
        return False

    local, domain = parts
    return _valid_local_part(local) and _valid_domain(domain)


def _validate_address_field(value, field_name, required):
    if value is None:
        if required:
            raise ValueError(f"{field_name} is required")
        return

    if isinstance(value, str):
        _check_header_text(value, field_name)
        if not value.strip():
            if required:
                raise ValueError(f"{field_name} is required")
            return
        chunks = [value]
    elif isinstance(value, (list, tuple)):
        if not value:
            if required:
                raise ValueError(f"{field_name} is required")
            return
        chunks = list(value)
    else:
        raise ValueError(f"{field_name} must be a string or a sequence of strings")

    found_address = False
    for chunk in chunks:
        _check_header_text(chunk, field_name)
        if not chunk.strip():
            raise ValueError(f"{field_name} contains an empty address")

        parsed_addresses = getaddresses([chunk])
        if not parsed_addresses:
            raise ValueError(f"{field_name} contains an invalid address")

        for display_name, address in parsed_addresses:
            _check_header_text(display_name, f"{field_name} display name")
            if not address or not _valid_addr_spec(address):
                raise ValueError(f"{field_name} contains an invalid address")
            found_address = True

    if required and not found_address:
        raise ValueError(f"{field_name} is required")


def validate_email(to, subject, body="", cc=None, bcc=None):
    _check_header_text(subject, "subject")
    if not subject.strip():
        raise ValueError("subject is required")

    _validate_address_field(to, "recipient", required=True)
    _validate_address_field(cc, "cc", required=False)
    _validate_address_field(bcc, "bcc", required=False)

    return True
