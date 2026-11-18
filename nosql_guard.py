"""Guard against MongoDB operator injection in user-supplied filters.

Only flat ``{field: scalar}`` mappings are accepted. Operator keys
(anything starting with ``$``), nested objects and array values are
rejected with ``ValueError`` before the filter reaches the driver.
"""

from collections.abc import Mapping

_FORBIDDEN_VALUE_TYPES = (list, tuple, set, frozenset)


def sanitize_filter(user_input):
    if not isinstance(user_input, Mapping):
        raise ValueError(
            "invalid filter: expected a dict of field/value pairs, "
            f"got {type(user_input).__name__}"
        )

    safe_filter = {}
    for field, value in user_input.items():
        if not isinstance(field, str):
            raise ValueError(
                "invalid filter: field names must be strings, "
                f"got {type(field).__name__}"
            )
        if field.startswith("$"):
            raise ValueError(
                f"invalid filter: MongoDB operators are forbidden ('{field}')"
            )
        if isinstance(value, Mapping):
            raise ValueError(
                f"invalid filter: nested objects are forbidden for field "
                f"'{field}'; use flat field/value pairs only"
            )
        if isinstance(value, _FORBIDDEN_VALUE_TYPES):
            raise ValueError(
                f"invalid filter: array values are forbidden for field '{field}'"
            )
        safe_filter[field] = value

    return safe_filter
