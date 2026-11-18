# Secret exposure scanning over an in-memory file collection.
#
# The scanner is pure: it keeps no mutable module-level state, so concurrent
# scans (including scans run from many threads at once) always produce the
# same result for the same inputs.

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

DEFAULT_BLOCK_SEVERITY = "high"


def _validate_files(files):
    if not isinstance(files, dict):
        raise ValueError("files must be a dict mapping path to content")
    for path, content in files.items():
        if not isinstance(path, str):
            raise ValueError("file paths must be strings: %r" % (path,))
        if not isinstance(content, str):
            raise ValueError("file content must be a string: %r" % (path,))


def _validate_rules(rules):
    if not isinstance(rules, list):
        raise ValueError("rules must be a list")

    seen_ids = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("each rule must be a dict: %r" % (rule,))

        if "id" not in rule:
            raise ValueError("rule is missing required field 'id'")
        rule_id = rule["id"]
        if not isinstance(rule_id, str):
            raise ValueError("rule id must be a string: %r" % (rule_id,))
        if not rule_id:
            raise ValueError("rule id must not be empty")
        if rule_id in seen_ids:
            raise ValueError("duplicate rule id: %r" % (rule_id,))
        seen_ids.add(rule_id)

        if "pattern" not in rule:
            raise ValueError(
                "rule %r is missing required field 'pattern'" % rule_id
            )
        pattern = rule["pattern"]
        if not isinstance(pattern, str):
            raise ValueError("rule %r pattern must be a string" % rule_id)
        if not pattern:
            raise ValueError("rule %r pattern must not be empty" % rule_id)

        if "severity" not in rule:
            raise ValueError(
                "rule %r is missing required field 'severity'" % rule_id
            )
        severity = rule["severity"]
        if not isinstance(severity, str) or severity not in SEVERITY_RANK:
            raise ValueError(
                "rule %r has invalid severity: %r (expected one of %s)"
                % (rule_id, severity, ", ".join(SEVERITIES))
            )


def _validate_allowlist(allowlist):
    if allowlist is None:
        return frozenset()
    if isinstance(allowlist, str) or not isinstance(
        allowlist, (frozenset, set, list, tuple)
    ):
        raise ValueError("allowlist must be a collection of path strings")
    paths = set()
    for path in allowlist:
        if not isinstance(path, str):
            raise ValueError("allowlist entries must be strings: %r" % (path,))
        paths.add(path)
    return frozenset(paths)


def _normalize_block_severity(block_severity):
    # A single severity string blocks that severity and every higher one;
    # a collection of severities blocks exactly the listed severities.
    if block_severity is None:
        block_severity = DEFAULT_BLOCK_SEVERITY

    if isinstance(block_severity, str):
        if block_severity not in SEVERITY_RANK:
            raise ValueError(
                "invalid block severity: %r (expected one of %s)"
                % (block_severity, ", ".join(SEVERITIES))
            )
        threshold = SEVERITY_RANK[block_severity]
        return frozenset(
            name
            for name, rank in SEVERITY_RANK.items()
            if rank >= threshold
        )

    if isinstance(block_severity, (set, frozenset, list, tuple)):
        severities = set()
        for severity in block_severity:
            if not isinstance(severity, str) or severity not in SEVERITY_RANK:
                raise ValueError(
                    "invalid block severity: %r (expected one of %s)"
                    % (severity, ", ".join(SEVERITIES))
                )
            severities.add(severity)
        if not severities:
            raise ValueError("block severity collection must not be empty")
        return frozenset(severities)

    raise ValueError(
        "block severity must be a severity string or a collection of them"
    )


def scan(files, rules, allowlist=None, block_severity=None):
    # Scan file contents against secret-matching rules.
    #
    # files maps path strings to file-content strings; rules is a list of
    # dicts with a string id, a non-empty substring pattern and a valid
    # severity. allowlist is a caller-provided collection of paths exempt
    # from scanning. block_severity lets the caller choose which severities
    # block the change: a single severity string means "this severity and
    # above" (default "high"), a collection means exactly those severities.
    #
    # Returns {"findings": [...], "blocked": bool}; every finding records
    # the hit path and the full identity of the matched rule.
    _validate_files(files)
    _validate_rules(rules)
    allowed_paths = _validate_allowlist(allowlist)
    blocking_severities = _normalize_block_severity(block_severity)

    findings = []
    blocked = False

    for path in sorted(files):
        if path in allowed_paths:
            continue
        content = files[path]
        for rule in rules:
            if rule["pattern"] in content:
                severity = rule["severity"]
                findings.append(
                    {
                        "path": path,
                        "rule": rule["id"],
                        "rule_id": rule["id"],
                        "pattern": rule["pattern"],
                        "severity": severity,
                    }
                )
                if severity in blocking_severities:
                    blocked = True

    return {"findings": findings, "blocked": blocked}
