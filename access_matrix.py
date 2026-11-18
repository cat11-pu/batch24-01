from collections.abc import Mapping


_OWNER_ACTIONS = frozenset(("read", "write"))


def _role_names(value, field):
    if isinstance(value, str) or not isinstance(
        value, (list, tuple, set, frozenset)
    ):
        raise ValueError("%s must be a collection of role names" % field)

    names = []
    for name in value:
        if not isinstance(name, str):
            raise ValueError("%s must contain only strings" % field)
        names.append(name)
    return names


def _compile_policy(policy):
    if not isinstance(policy, Mapping):
        raise ValueError("policy must be a mapping")
    if "roles" not in policy:
        raise ValueError("policy is missing roles")
    if "grants" not in policy or "denies" not in policy:
        raise ValueError("policy is missing grants or denies")

    raw_roles = policy["roles"]
    if not isinstance(raw_roles, Mapping):
        raise ValueError("roles must be a mapping")

    role_parents = {}
    for role, parents in raw_roles.items():
        if not isinstance(role, str):
            raise ValueError("role names must be strings")
        role_parents[role] = tuple(_role_names(parents, "parents of %r" % role))

    for parents in role_parents.values():
        for parent in parents:
            if parent not in role_parents:
                raise ValueError("unknown parent role: %r" % parent)

    _check_role_cycles(role_parents)

    grants = _compile_rules(policy["grants"], role_parents, "grants")
    denies = _compile_rules(policy["denies"], role_parents, "denies")

    actions = set(_OWNER_ACTIONS)
    actions.update(rule[1] for rule in grants)
    actions.update(rule[1] for rule in denies)
    resource_types = {rule[2] for rule in grants}
    resource_types.update(rule[2] for rule in denies)

    return role_parents, actions, resource_types, grants, denies


def _compile_rules(entries, role_parents, field):
    if isinstance(entries, str) or not isinstance(
        entries, (list, tuple, set, frozenset)
    ):
        raise ValueError("%s must be a collection" % field)

    rules = []
    for entry in entries:
        if isinstance(entry, Mapping):
            try:
                role = entry["role"]
                action = entry["action"]
                resource_type = entry["resource"]
            except KeyError as exc:
                raise ValueError("%s entry is missing a field" % field) from exc
        elif isinstance(entry, (list, tuple)) and len(entry) == 3:
            role, action, resource_type = entry
        else:
            raise ValueError("invalid %s entry" % field)

        if not isinstance(role, str):
            raise ValueError("%s role must be a string" % field)
        if role not in role_parents:
            raise ValueError("unknown role in %s: %r" % (field, role))
        if not isinstance(action, str):
            raise ValueError("%s action must be a string" % field)
        if not isinstance(resource_type, str):
            raise ValueError("%s resource must be a string" % field)

        rules.append((role, action, resource_type))

    return tuple(rules)


def _check_role_cycles(role_parents):
    state = {}
    for start in role_parents:
        if state.get(start, 0) != 0:
            continue

        state[start] = 1
        stack = [(start, iter(role_parents[start]))]
        while stack:
            role, parents = stack[-1]
            try:
                parent = next(parents)
            except StopIteration:
                state[role] = 2
                stack.pop()
                continue

            parent_state = state.get(parent, 0)
            if parent_state == 1:
                raise ValueError("role inheritance contains a cycle")
            if parent_state == 0:
                state[parent] = 1
                stack.append((parent, iter(role_parents[parent])))


def _effective_roles(role_parents, roots):
    effective = set()
    stack = list(roots)
    while stack:
        role = stack.pop()
        if role in effective:
            continue
        effective.add(role)
        stack.extend(role_parents[role])
    return effective


def authorize(policy, user, action, resource):
    role_parents, actions, resource_types, grants, denies = _compile_policy(policy)

    if not isinstance(user, Mapping):
        raise ValueError("user must be a mapping")
    if "roles" not in user:
        raise ValueError("user is missing roles")
    user_roles = _role_names(user["roles"], "user roles")

    if not isinstance(action, str):
        raise ValueError("action must be a string")
    if not isinstance(resource, Mapping):
        raise ValueError("resource must be a mapping")

    resource_type = resource.get("type")
    if not isinstance(resource_type, str):
        raise ValueError("resource type must be a string")

    for role in user_roles:
        if role not in role_parents:
            raise ValueError("unknown role: %r" % role)
    if action not in actions:
        raise ValueError("unknown action: %r" % action)
    if resource_type not in resource_types:
        raise ValueError("unknown resource type: %r" % resource_type)

    if resource.get("deleted", False):
        return False
    if user.get("tenant") != resource.get("tenant"):
        return False
    if not user_roles:
        return False

    effective = _effective_roles(role_parents, user_roles)

    for role, rule_action, rule_resource in denies:
        if (
            role in effective
            and rule_action == action
            and rule_resource == resource_type
        ):
            return False

    for role, rule_action, rule_resource in grants:
        if (
            role in effective
            and rule_action == action
            and rule_resource == resource_type
        ):
            return True

    user_id = user.get("id")
    if (
        action in _OWNER_ACTIONS
        and user_id is not None
        and resource.get("owner") == user_id
    ):
        return True

    return False
