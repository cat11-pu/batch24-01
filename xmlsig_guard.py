"""Guarded XML signature validation.

Accepts only a strict document shape:
- well-formed XML, no DTD or entity declarations
- exactly one ``Signature`` element, a direct child of the root
- the root element carries the protected ``ID`` attribute
- ``Signature/@Reference`` must be ``#<root ID>``
- no duplicate ``ID`` attributes anywhere in the document
"""

import xml.etree.ElementTree as ET

_ID_ATTR = "ID"
_SIG_TAG = "Signature"
_REF_ATTR = "Reference"


def validate(value):
    if not isinstance(value, str):
        raise TypeError("expected an XML string")
    if not value.strip():
        raise ValueError("empty document")
    if "<!DOCTYPE" in value or "<!ENTITY" in value:
        raise ValueError("DTD and entity declarations are not allowed")
    try:
        root = ET.fromstring(value)
    except ET.ParseError as exc:
        raise ValueError(f"malformed XML: {exc}") from exc

    seen_ids = {}
    for element in root.iter():
        element_id = element.get(_ID_ATTR)
        if element_id is None:
            continue
        if element_id in seen_ids:
            raise ValueError(f"duplicate ID: {element_id!r}")
        seen_ids[element_id] = element

    signatures = [el for el in root.iter() if el.tag == _SIG_TAG]
    if len(signatures) != 1:
        raise ValueError("document must contain exactly one Signature element")
    signature = signatures[0]

    if not any(child is signature for child in root):
        raise ValueError("Signature must be a direct child of the root element")

    reference = signature.get(_REF_ATTR)
    if not reference or not reference.startswith("#") or len(reference) == 1:
        raise ValueError("Signature Reference must be a non-empty fragment")

    target_id = reference[1:]
    target = seen_ids.get(target_id)
    if target is None:
        raise ValueError(f"Reference target not found: {target_id!r}")
    if target is not root:
        raise ValueError("Reference must target the protected root element")

    return True
