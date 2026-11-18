import re

_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*$")
_HASH_RE = re.compile(r"^[0-9a-f]+$")


def _parse_version(value):
    if not isinstance(value, str) or not _VERSION_RE.fullmatch(value):
        return None
    return tuple(int(part) for part in value.split("."))


def _pad_version(version, length):
    return version + (0,) * (length - len(version))


def verify(lockfile, policy):
    if not isinstance(lockfile, dict):
        raise ValueError("lockfile must be a dict")
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict")

    allowed = policy.get("allowed")
    if not isinstance(allowed, dict) or not allowed:
        raise ValueError("policy 'allowed' must be a non-empty dict")

    banned = policy.get("banned", [])
    if not isinstance(banned, list):
        raise ValueError("policy 'banned' must be a list")

    parsed_rules = {}
    for package_name, rule in allowed.items():
        if not isinstance(package_name, str) or not package_name:
            raise ValueError("allowed package name must be a non-empty string")
        if not isinstance(rule, dict):
            raise ValueError("policy rule for %r must be a dict" % package_name)
        expected_hash = rule.get("hash")
        if not isinstance(expected_hash, str) or not _HASH_RE.fullmatch(expected_hash):
            raise ValueError("invalid policy hash for %r" % package_name)
        min_version = _parse_version(rule.get("min_version"))
        if min_version is None:
            raise ValueError("invalid min_version for %r" % package_name)
        parsed_rules[package_name] = (expected_hash, min_version)

    banned_names = set()
    for package_name in banned:
        if not isinstance(package_name, str) or not package_name:
            raise ValueError("banned package names must be non-empty strings")
        banned_names.add(package_name)

    for package_name, entry in lockfile.items():
        if not isinstance(package_name, str) or not package_name:
            raise ValueError("package name must be a non-empty string")
        if package_name in banned_names:
            raise ValueError("package %r is banned" % package_name)
        if package_name not in parsed_rules:
            raise ValueError("package %r is not in the allowed list" % package_name)
        if not isinstance(entry, dict):
            raise ValueError("lockfile entry for %r must be a dict" % package_name)

        version = entry.get("version")
        parsed_version = _parse_version(version)
        if parsed_version is None:
            raise ValueError(
                "package %r has a missing, non-string or unpinned version: %r"
                % (package_name, version)
            )

        expected_hash, min_version = parsed_rules[package_name]
        version_length = max(len(parsed_version), len(min_version))
        if _pad_version(parsed_version, version_length) < _pad_version(min_version, version_length):
            raise ValueError(
                "package %r version %s is below minimum version %s"
                % (package_name, version, ".".join(str(part) for part in min_version))
            )

        package_hash = entry.get("hash")
        if not isinstance(package_hash, str) or not _HASH_RE.fullmatch(package_hash):
            raise ValueError("package %r has a missing or malformed hash" % package_name)
        if package_hash != expected_hash:
            raise ValueError("package %r hash does not match the policy hash" % package_name)

    return True
