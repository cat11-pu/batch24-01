import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

_DEFAULT_AUDIENCE = "app"
_DEFAULT_RECIPIENT = "https://app/cb"

_FORBIDDEN_MARKUP = ("<!doctype", "<!entity")


def _local_name(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _attr(element, name):
    for key, value in element.attrib.items():
        if _local_name(key) == name:
            return value
    return None


def _parse_instant(raw, field):
    text = raw.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"invalid {field}: {raw!r}") from None
    if moment.tzinfo is None:
        raise ValueError(f"{field} must carry a timezone: {raw!r}")
    return moment.astimezone(timezone.utc)


def _expected(value, env_name, default):
    if value is not None:
        return value
    return os.environ.get(env_name, default)


def validate(value, audience=None, recipient=None, now=None):
    expected_audience = _expected(audience, "SAML_AUDIENCE", _DEFAULT_AUDIENCE)
    expected_recipient = _expected(recipient, "SAML_RECIPIENT", _DEFAULT_RECIPIENT)
    if not expected_audience or not expected_recipient:
        raise ValueError("expected audience/recipient must be non-empty")

    if not isinstance(value, str):
        raise TypeError("SAML response must be a string")
    if not value.strip():
        raise ValueError("empty SAML response")
    lowered = value.lower()
    if any(token in lowered for token in _FORBIDDEN_MARKUP):
        raise ValueError("DOCTYPE/ENTITY declarations are not allowed")

    try:
        root = ET.fromstring(value)
    except ET.ParseError as exc:
        raise ValueError(f"malformed XML: {exc}") from None

    if _local_name(root.tag) != "Response":
        raise ValueError("root element must be a Response")

    if _attr(root, "Audience") != expected_audience:
        raise ValueError("Audience mismatch")
    if _attr(root, "Recipient") != expected_recipient:
        raise ValueError("Recipient mismatch")

    moment_now = now if now is not None else datetime.now(timezone.utc)
    if moment_now.tzinfo is None:
        moment_now = moment_now.replace(tzinfo=timezone.utc)

    not_before = _attr(root, "NotBefore")
    if not_before is not None and _parse_instant(not_before, "NotBefore") > moment_now:
        raise ValueError("response is not yet valid (NotBefore in the future)")

    not_on_or_after = _attr(root, "NotOnOrAfter")
    if not_on_or_after is None:
        raise ValueError("missing NotOnOrAfter")
    if moment_now >= _parse_instant(not_on_or_after, "NotOnOrAfter"):
        raise ValueError("response has expired (NotOnOrAfter in the past)")

    assertions = [el for el in root.iter() if _local_name(el.tag) == "Assertion"]
    if not assertions:
        raise ValueError("response carries no Assertion")

    assertion_ids = []
    for assertion in assertions:
        assertion_id = _attr(assertion, "ID")
        if not assertion_id:
            raise ValueError("Assertion without ID")
        if assertion_id in assertion_ids:
            raise ValueError("duplicate Assertion ID")
        assertion_ids.append(assertion_id)

    signatures = [el for el in root.iter() if _local_name(el.tag) == "Signature"]
    if not signatures:
        raise ValueError("response is not signed")

    referenced = []
    for signature in signatures:
        references = [el for el in signature.iter() if _local_name(el.tag) == "Reference"]
        if not references:
            raise ValueError("Signature without Reference")
        for reference in references:
            uri = _attr(reference, "URI") or ""
            if not uri.startswith("#") or len(uri) == 1:
                raise ValueError("Reference must point to a local fragment")
            fragment = uri[1:]
            if fragment not in assertion_ids:
                raise ValueError("Reference does not cover an Assertion")
            if fragment in referenced:
                raise ValueError("duplicate signature Reference")
            referenced.append(fragment)

    for assertion_id in assertion_ids:
        if assertion_id not in referenced:
            raise ValueError("Assertion is not covered by any signature Reference")

    return True
