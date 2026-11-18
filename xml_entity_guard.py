"""Hardened XML validation guard against XXE and entity expansion attacks.

Threat model covered by :func:`validate`:

* internal general entities (e.g. ``<!ENTITY x 'y'>``)
* external general entities (e.g. ``<!ENTITY x SYSTEM 'file:///etc/passwd'>``)
* external DTDs (``<!DOCTYPE root SYSTEM 'http://...'>``)
* parameter entities (``<!ENTITY % p ...>``)
* "billion laughs" style recursive entity expansion bombs
* malformed input, null bytes and empty values

The guard is built on the standard-library ``expat`` parser and never
instantiates a resolver, so external resources cannot be fetched.  Every
DOCTYPE declaration is rejected outright, which makes entity declarations
unreachable in well-formed documents; the remaining handlers and budgets are
kept as defence in depth.
"""

import xml.parsers.expat

__all__ = ["validate", "XmlValidationError"]


class XmlValidationError(ValueError):
    """Raised when a value is not safe, well-formed XML."""


# Maximum number of bytes of textual content produced after all entity
# expansion.  A single compact entity reference can otherwise expand into
# gigabytes ("billion laughs"), so the expanded size is bounded explicitly.
MAX_EXPANDED_BYTES = 10 * 1024 * 1024

# Maximum number of entity declarations tolerated inside one document.  Safe
# documents do not declare any entities because every DOCTYPE is rejected;
# this bound exists purely as an additional resource cap.
MAX_ENTITY_DECLARATIONS = 64


class _SafeXmlParser:
    """Stateful wrapper around expat with every DTD/entity feature disabled."""

    def __init__(self):
        parser = xml.parsers.expat.ParserCreate()
        self._parser = parser
        self._expanded_bytes = 0
        self._entity_declarations = 0

        # A DOCTYPE is the carrier of every DTD-based attack: internal and
        # external entities, parameter entities, external DTDs and ELEMENT /
        # ATTLIST / NOTATION declarations.  Rejecting it at the very first
        # callback prevents any of those constructs from taking effect.
        parser.StartDoctypeDeclHandler = self._reject_doctype

        # Defence in depth: even if a declaration slips past the DOCTYPE
        # gate, refuse it explicitly instead of letting expat use it.
        parser.EntityDeclHandler = self._reject_entity_declaration
        parser.ElementDeclHandler = self._reject_dtd_declaration
        parser.AttlistDeclHandler = self._reject_dtd_declaration
        parser.NotationDeclHandler = self._reject_dtd_declaration

        # Never follow external references of any kind.  Returning 0 tells
        # expat that the external entity could not be processed; the handler
        # itself raises so the failure reason is unambiguous.
        parser.ExternalEntityRefHandler = self._reject_external_reference

        # Parameter entities are only meaningful inside DTDs; disable them at
        # the parser level as well as via the DOCTYPE rejection above.
        parser.SetParamEntityParsing(
            xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER
        )

        parser.StartElementHandler = self._check_attributes
        parser.CharacterDataHandler = self._account_text

    def parse(self, value):
        try:
            self._parser.Parse(value, True)
        except XmlValidationError:
            raise
        except TypeError:
            raise
        except xml.parsers.expat.ExpatError as exc:
            raise XmlValidationError(
                "malformed or unsafe XML: %s" % exc
            ) from exc

    def _reject_doctype(self, name, sysid, pubid, has_internal_subset):
        raise XmlValidationError(
            "DOCTYPE declarations are forbidden (external DTD, internal "
            "subset and entity declarations are not allowed)"
        )

    def _reject_entity_declaration(self, *args):
        self._entity_declarations += 1
        if self._entity_declarations > MAX_ENTITY_DECLARATIONS:
            raise XmlValidationError(
                "entity declaration limit of %d exceeded"
                % MAX_ENTITY_DECLARATIONS
            )
        raise XmlValidationError("ENTITY declarations are forbidden")

    def _reject_dtd_declaration(self, *args):
        raise XmlValidationError("DTD declarations are forbidden")

    def _reject_external_reference(self, context, base, system_id, public_id):
        raise XmlValidationError(
            "external entity references are forbidden (system_id=%r)"
            % (system_id,)
        )

    def _account_text(self, data):
        self._expanded_bytes += len(data.encode("utf-8", "replace"))
        if self._expanded_bytes > MAX_EXPANDED_BYTES:
            raise XmlValidationError(
                "entity expansion limit of %d bytes exceeded"
                % MAX_EXPANDED_BYTES
            )

    def _check_attributes(self, name, attributes):
        for value in attributes.values():
            self._account_text(value)


def validate(value):
    """Validate that ``value`` is safe, well-formed XML.

    ``value`` must be a non-empty ``str`` (or UTF-8 ``bytes``) containing a
    well-formed XML document without a DOCTYPE, entity declarations, external
    references or excessive entity expansion.

    Returns ``True`` for safe input and raises :class:`TypeError` for the
    wrong type or :class:`XmlValidationError` (a ``ValueError`` subclass) for
    every other rejection.
    """
    if value is None:
        raise TypeError("XML value must not be None")
    if not isinstance(value, (str, bytes)):
        raise TypeError(
            "XML value must be str or bytes, got %s"
            % type(value).__name__
        )
    if not value or not value.strip():
        raise XmlValidationError("XML value must not be empty")

    _SafeXmlParser().parse(value)
    return True
