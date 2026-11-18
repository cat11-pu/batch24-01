import re


_HEADER_NAME_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_CONTENT_LENGTH_RE = re.compile(r"[0-9]+")


def _as_text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("latin-1")
    raise ValueError("header names and values must be text or bytes")


def _validate_header_name(name):
    if not name or _HEADER_NAME_RE.fullmatch(name) is None:
        raise ValueError("invalid header name")


def _validate_header_value(value):
    for char in value:
        codepoint = ord(char)
        if codepoint == 0 or codepoint == 0x7F:
            raise ValueError("invalid header value")
        if codepoint < 0x20 and char != "\t":
            raise ValueError("invalid header value")


def _validate_content_length(value):
    if _CONTENT_LENGTH_RE.fullmatch(value) is None:
        raise ValueError("invalid Content-Length")


def _validate_transfer_encoding(value):
    if value != "chunked":
        raise ValueError("invalid Transfer-Encoding")


def parse_request(headers, body):
    parsed_headers = list(headers)
    content_length_seen = False
    transfer_encoding_seen = False

    for header in parsed_headers:
        if not isinstance(header, (list, tuple)) or len(header) != 2:
            raise ValueError("headers must contain name/value pairs")

        name = _as_text(header[0])
        value = _as_text(header[1])
        _validate_header_name(name)
        _validate_header_value(value)

        canonical_name = name.lower()
        if canonical_name == "content-length":
            if content_length_seen:
                raise ValueError("duplicate Content-Length")
            content_length_seen = True
            _validate_content_length(value)
        elif canonical_name == "transfer-encoding":
            if transfer_encoding_seen:
                raise ValueError("duplicate Transfer-Encoding")
            transfer_encoding_seen = True
            _validate_transfer_encoding(value)

    if content_length_seen and transfer_encoding_seen:
        raise ValueError("Content-Length and Transfer-Encoding cannot coexist")

    return {"headers": parsed_headers, "body": body}
