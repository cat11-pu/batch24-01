"""Acceptance stress check for mask_fields.project.

Generates 1200 random records/roles/schemas and projects them from 24
threads concurrently.  Every run asserts that sensitive fields never leak
(even for the wildcard role), write requests can only touch writable
fields, rejected inputs raise ValueError, the original record is never
mutated, and projected objects are freshly built at every nesting level.

Run with: python3 acceptance_check.py
"""

import copy
import random
from concurrent.futures import ThreadPoolExecutor

from mask_fields import project

CASE_COUNT = 1200
THREAD_COUNT = 24
ROLE_POOL = ["user", "admin", "auditor", "guest", "support"]
WILDCARD = "*"


def make_policy(rng, depth):
    sensitive = rng.random() < 0.2
    read_roles = [] if sensitive else [
        role for role in ROLE_POOL if rng.random() < 0.5
    ]
    write_roles = [] if sensitive else [
        role for role in ROLE_POOL if rng.random() < 0.4
    ]
    if not sensitive and rng.random() < 0.2:
        read_roles.append(WILDCARD)
    if not sensitive and rng.random() < 0.1:
        write_roles.append(WILDCARD)
    policy = {"read": read_roles, "write": write_roles}
    if depth > 0 and rng.random() < 0.4:
        policy["fields"] = {
            "sub_%d" % index: make_policy(rng, depth - 1)
            for index in range(rng.randint(1, 4))
        }
    return policy


def make_schema(rng):
    return {
        "field_%d" % index: make_policy(rng, rng.randint(0, 2))
        for index in range(rng.randint(3, 8))
    }


def make_record(rng, schema):
    record = {}
    for key, policy in schema.items():
        if rng.random() >= 0.15:
            nested = policy.get("fields")
            if isinstance(nested, dict):
                record[key] = make_record(rng, nested)
            else:
                record[key] = rng.choice([1, "value", True, None, 3.14])
    if rng.random() < 0.2:
        record["undeclared_%d" % rng.randint(0, 999)] = "unmapped"
    return record


def collect_roles(schema):
    roles = set()
    for policy in schema.values():
        roles.update(policy["read"])
        roles.update(policy["write"])
        nested = policy.get("fields")
        if isinstance(nested, dict):
            roles.update(collect_roles(nested))
    return roles


def allowed(role_list, role):
    if WILDCARD in role_list:
        return True
    if role == WILDCARD:
        return False
    return role in role_list


def assert_projection(output, original, role, direction, schema):
    assert isinstance(output, dict)
    assert output is not original
    for key, value in output.items():
        assert key in schema, "undeclared field %r leaked" % key
        policy = schema[key]
        assert allowed(policy[direction], role), (
            "field %r visible to role %r without %s permission"
            % (key, role, direction)
        )
        assert len(policy[direction]) > 0, "sensitive field %r leaked" % key
        nested = policy.get("fields")
        if isinstance(nested, dict) and isinstance(value, dict):
            assert value is not original[key], "nested object was not rebuilt"
            assert_projection(value, original[key], role, direction, nested)
        else:
            assert value == original[key]


def expect_write_error(record, role, schema):
    for key, value in record.items():
        policy = schema.get(key)
        if policy is None or not allowed(policy["write"], role):
            return True
        nested = policy.get("fields")
        if isinstance(nested, dict) and isinstance(value, dict):
            if expect_write_error(value, role, nested):
                return True
    return False


def build_case(rng, index):
    schema = make_schema(rng)
    record = make_record(rng, schema)
    declared = collect_roles(schema)

    roll = rng.random()
    if roll < 0.05:
        return record, "ghost_%d" % index, "read", schema, "error"
    if roll < 0.08:
        return record, "", "read", schema, "error"
    if roll < 0.11:
        return record, "user", "delete", schema, "error"
    if roll < 0.14:
        return "not-a-dict", "user", "read", schema, "error"
    if roll < 0.17:
        return record, "user", "read", "broken-schema", "error"

    role = rng.choice(list(declared) + [WILDCARD])
    direction = rng.choice(["read", "write"])
    if direction == "write" and expect_write_error(record, role, schema):
        expectation = "error"
    else:
        expectation = "ok"
    return record, role, direction, schema, expectation


def run_case(case):
    record, role, direction, schema, expectation = case
    snapshot = copy.deepcopy(record)
    try:
        output = project(record, role, direction, schema)
    except ValueError:
        assert expectation == "error", "unexpected ValueError"
    else:
        assert expectation == "ok", "expected ValueError but projection succeeded"
        assert_projection(output, record, role, direction, schema)
    assert record == snapshot, "original record was mutated"


def main():
    rng = random.Random(20261119)
    cases = [build_case(rng, index) for index in range(CASE_COUNT)]
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as pool:
        for round_index in range(3):
            list(pool.map(run_case, cases))
            print("round %d: %d cases across %d threads ok"
                  % (round_index + 1, CASE_COUNT, THREAD_COUNT))
    print("acceptance check passed")


if __name__ == "__main__":
    main()
