"""Field-level permission projection for the auth middleware.

The caller supplies a role table in the shape of a schema: each field maps
to a policy declaring the roles allowed to ``read`` and ``write`` it.
Nested objects are projected recursively.  A field whose role list is
empty (e.g. password hashes) is invisible to every role, including the
wildcard role ``*``.  Projection always returns a fresh object and never
mutates the record passed in.
"""

READ = "read"
WRITE = "write"
DIRECTIONS = (READ, WRITE)
WILDCARD = "*"


def _validate_policy(policy, known_roles):
    if not isinstance(policy, dict):
        raise ValueError("field policy must be a dict")
    for direction in DIRECTIONS:
        if direction not in policy:
            raise ValueError("field policy is missing %r entry" % direction)
        allowed_roles = policy[direction]
        if not isinstance(allowed_roles, list):
            raise ValueError("%r roles must be a list" % direction)
        for entry in allowed_roles:
            if not isinstance(entry, str) or not entry:
                raise ValueError("role names must be non-empty strings")
            known_roles.add(entry)
    nested = policy.get("fields")
    if nested is not None:
        if not isinstance(nested, dict):
            raise ValueError("nested 'fields' policy must be a dict")
        for sub_policy in nested.values():
            _validate_policy(sub_policy, known_roles)


def _is_allowed(allowed_roles, role):
    if WILDCARD in allowed_roles:
        return True
    if role == WILDCARD:
        # The wildcard role only matches an explicit wildcard grant; an
        # empty list marks a sensitive field and is never bypassable.
        return False
    return role in allowed_roles


def _project(record, role, direction, schema):
    result = {}
    for field, value in record.items():
        policy = schema.get(field)
        if policy is None or not _is_allowed(policy[direction], role):
            if direction == WRITE:
                raise ValueError(
                    "role %r is not allowed to write field %r" % (role, field)
                )
            continue
        nested_schema = policy.get("fields")
        if isinstance(nested_schema, dict) and isinstance(value, dict):
            result[field] = _project(value, role, direction, nested_schema)
        else:
            result[field] = value
    return result


def project(record, role, direction, schema):
    if not isinstance(record, dict):
        raise ValueError("record must be a dict")
    if not isinstance(schema, dict):
        raise ValueError("schema must be a dict")
    if not isinstance(role, str) or not role:
        raise ValueError("role must be a non-empty string")
    if direction not in DIRECTIONS:
        raise ValueError("direction must be 'read' or 'write'")

    known_roles = set()
    for policy in schema.values():
        _validate_policy(policy, known_roles)

    if role != WILDCARD and role not in known_roles:
        raise ValueError("unknown role %r" % role)

    return _project(record, role, direction, schema)
