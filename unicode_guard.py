"""Unicode-aware path validation.

ASCII-only checks miss visually equivalent slash/dot characters, zero-width
marks and bidi controls, which lets crafted paths bypass traversal guards.
The input is percent-decoded (rejecting invalid/overlong encodings and
double encoding), NFKC-normalized, and then inspected with Unicode
property tables from :mod:`unicodedata` instead of a hardcoded denylist.
"""

import re
import unicodedata
import urllib.parse


# A residual percent-encoded triplet after one decode round means the value
# was encoded more than once (or percent signs themselves were encoded).
_PERCENT_TRIPLET = re.compile(r"%[0-9A-Fa-f]{2}")

# Name fragments shared by every slash-like codepoint in the Unicode
# database; matched dynamically so new confusables are covered for free.
_SLASH_NAME_FRAGMENTS = ("SOLIDUS", "SLASH", "BACKSLASH")

_ASCII_SEPARATORS = ("/", "\\")


def _has_forbidden_codepoint(text):
    """Return a reason string if *text* contains a dangerous codepoint."""
    for char in text:
        category = unicodedata.category(char)
        # C* covers control, format (zero-width marks, bidi controls),
        # surrogates, private-use and unassigned codepoints.
        if category.startswith("C"):
            return "control/format/invisible character U+%04X" % ord(char)
        # S* covers math symbols such as division/fraction slashes and
        # set-minus, none of which are legitimate in portable file names.
        if category.startswith("S"):
            return "symbol character U+%04X" % ord(char)
        if char in _ASCII_SEPARATORS:
            continue
        name = unicodedata.name(char, "")
        if any(fragment in name for fragment in _SLASH_NAME_FRAGMENTS):
            return "slash-like character U+%04X" % ord(char)
    return None


def _decode_percent(value):
    """Decode percent-escaped bytes once, rejecting overlong/bad UTF-8."""
    raw = urllib.parse.unquote_to_bytes(value)
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid or overlong percent-encoded UTF-8: %s" % exc)
    if _PERCENT_TRIPLET.search(decoded):
        raise ValueError("double percent-encoding is not allowed")
    return decoded


def _has_traversal_segment(text):
    """Check normalized text for dot segments on any slash separator."""
    for segment in re.split(r"[\\/]", text):
        if segment.startswith(".."):
            return True
    return False


def validate(value):
    """Validate a user-supplied path fragment.

    Raises :class:`TypeError` for non-strings and :class:`ValueError` for
    any value containing traversal segments, slash lookalikes, invisible
    controls, bidi marks or suspicious percent-encoding.
    """
    if not isinstance(value, str):
        raise TypeError("path value must be a string, got %s" % type(value).__name__)

    decoded = _decode_percent(value)
    normalized = unicodedata.normalize("NFKC", decoded)

    reason = _has_forbidden_codepoint(decoded) or _has_forbidden_codepoint(normalized)
    if reason is not None:
        raise ValueError("unsafe path value: %s" % reason)

    if _has_traversal_segment(normalized):
        raise ValueError("unsafe path value: dot-segment traversal detected")

    return True
