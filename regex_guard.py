"""Validation helpers for user supplied regular expressions."""

import re
import warnings

try:
    from re import _constants as _constants
    from re import _parser as _parser
except ImportError:
    import sre_constants as _constants
    import sre_parse as _parser


MAX_PATTERN_LENGTH = 1000
MAX_REPEAT_COUNT = 1000
MAX_BOUNDED_BRANCH_REPEAT = 8
MAX_CODEPOINT = 0x10FFFF


class RegexValidationError(ValueError, TypeError):
    """Raised when a pattern is unsafe or is not a valid regular expression."""


_MAX_REPEAT = getattr(_constants, "MAX_REPEAT", None)
_MIN_REPEAT = getattr(_constants, "MIN_REPEAT", None)
_POSSESSIVE_REPEAT = getattr(_constants, "POSSESSIVE_REPEAT", None)
_REPEAT_OPS = {
    op for op in (_MAX_REPEAT, _MIN_REPEAT, _POSSESSIVE_REPEAT) if op is not None
}

_SUBPATTERN = getattr(_constants, "SUBPATTERN", None)
_BRANCH = getattr(_constants, "BRANCH", None)
_ATOMIC_GROUP = getattr(_constants, "ATOMIC_GROUP", None)
_ASSERT = getattr(_constants, "ASSERT", None)
_ASSERT_NOT = getattr(_constants, "ASSERT_NOT", None)
_AT = getattr(_constants, "AT", None)
_ANY = getattr(_constants, "ANY", None)
_ANY_ALL = getattr(_constants, "ANY_ALL", None)
_IN = getattr(_constants, "IN", None)
_LITERAL = getattr(_constants, "LITERAL", None)
_NOT_LITERAL = getattr(_constants, "NOT_LITERAL", None)
_CATEGORY = getattr(_constants, "CATEGORY", None)
_GROUPREF = getattr(_constants, "GROUPREF", None)
_GROUPREF_EXISTS = getattr(_constants, "GROUPREF_EXISTS", None)
_NEGATE = getattr(_constants, "NEGATE", None)
_RANGE = getattr(_constants, "RANGE", None)
_SUCCESS = getattr(_constants, "SUCCESS", None)
_FAILURE = getattr(_constants, "FAILURE", None)
_ZERO_WIDTH_OPS = {
    op for op in (_ASSERT, _ASSERT_NOT, _AT, _SUCCESS, _FAILURE) if op is not None
}
_IGNORECASE = re.IGNORECASE


def _normalize_ranges(ranges):
    ordered = sorted((int(lo), int(hi)) for lo, hi in ranges if int(lo) <= int(hi))
    if not ordered:
        return ()
    merged = [ordered[0]]
    for lo, hi in ordered[1:]:
        last_lo, last_hi = merged[-1]
        if lo <= last_hi + 1:
            merged[-1] = (last_lo, max(last_hi, hi))
        else:
            merged.append((lo, hi))
    return tuple(merged)


def _complement_ranges(ranges):
    ranges = _normalize_ranges(ranges)
    result = []
    cursor = 0
    for lo, hi in ranges:
        if cursor < lo:
            result.append((cursor, lo - 1))
        cursor = hi + 1
    if cursor <= MAX_CODEPOINT:
        result.append((cursor, MAX_CODEPOINT))
    return tuple(result)


def _category_ranges(category):
    name = str(category).upper()
    negated = "NOT_" in name
    if negated:
        name = name.replace("NOT_", "", 1)
    if "DIGIT" in name:
        ranges = ((ord("0"), ord("9")),)
    elif "WORD" in name:
        ranges = (
            (ord("0"), ord("9")),
            (ord("A"), ord("Z")),
            (ord("_"), ord("_")),
            (ord("a"), ord("z")),
        )
    elif "SPACE" in name:
        ranges = (
            (9, 13),
            (32, 32),
            (133, 133),
            (160, 160),
            (5760, 5760),
            (8192, 8202),
            (8232, 8233),
            (8239, 8239),
            (8287, 8287),
            (12288, 12288),
        )
    elif "LINEBREAK" in name:
        ranges = ((10, 10), (13, 13), (0x2028, 0x2029))
    else:
        ranges = ((0, MAX_CODEPOINT),)
    return _complement_ranges(ranges) if negated else _normalize_ranges(ranges)


def _literal_ranges(codepoint, ignorecase):
    value = int(codepoint)
    ranges = [(value, value)]
    if ignorecase:
        char = chr(value)
        for variant in (char.lower(), char.upper()):
            if len(variant) == 1:
                other = ord(variant)
                ranges.append((other, other))
    return _normalize_ranges(ranges)


def _in_ranges(terms, ignorecase):
    ranges = []
    negate = False
    for op, value in terms:
        if op is _NEGATE:
            negate = True
        elif op is _LITERAL:
            ranges.extend(_literal_ranges(value, ignorecase))
        elif op is _RANGE:
            lo, hi = value
            ranges.append((int(lo), int(hi)))
            touches_letters = (
                int(lo) <= ord("Z") and int(hi) >= ord("A")
            ) or (int(lo) <= ord("z") and int(hi) >= ord("a"))
            if ignorecase and touches_letters:
                ranges.extend(((ord("A"), ord("Z")), (ord("a"), ord("z"))))
        elif op is _CATEGORY:
            ranges.extend(_category_ranges(value))
        else:
            ranges.append((0, MAX_CODEPOINT))
    normalized = _normalize_ranges(ranges)
    return _complement_ranges(normalized) if negate else normalized


def _intersects(left, right):
    i = 0
    j = 0
    while i < len(left) and j < len(right):
        left_lo, left_hi = left[i]
        right_lo, right_hi = right[j]
        if left_hi < right_lo:
            i += 1
        elif right_hi < left_lo:
            j += 1
        else:
            return True
    return False


class _FirstSet:
    __slots__ = ("ranges", "nullable")

    def __init__(self, ranges=(), nullable=True):
        unique = {}
        for item in ranges:
            unique[item] = None
        self.ranges = tuple(unique)
        self.nullable = nullable


_EMPTY_FIRST = _FirstSet((), True)
_WILDCARD_FIRST = _FirstSet(((0, MAX_CODEPOINT),), False)


def _first_node(node, ignorecase):
    op, args = node
    if op is _LITERAL:
        return _FirstSet((_literal_ranges(args, ignorecase),), False)
    if op is _NOT_LITERAL:
        ranges = _complement_ranges(_literal_ranges(args, ignorecase))
        return _FirstSet((ranges,), False)
    if op is _IN:
        return _FirstSet((_in_ranges(args, ignorecase),), False)
    if op is _CATEGORY:
        return _FirstSet((_category_ranges(args),), False)
    if op is _ANY or op is _ANY_ALL:
        return _FirstSet(((0, MAX_CODEPOINT),), False)
    if op in _REPEAT_OPS:
        minimum, _maximum, body = args
        body_first = _first_sequence(body, ignorecase)
        return _FirstSet(body_first.ranges, minimum == 0 or body_first.nullable)
    if op is _BRANCH:
        _unused, alternatives = args
        ranges = []
        nullable = False
        for alternative in alternatives:
            alternative_first = _first_sequence(alternative, ignorecase)
            ranges.extend(alternative_first.ranges)
            nullable = nullable or alternative_first.nullable
        return _FirstSet(ranges, nullable)
    if op is _SUBPATTERN:
        _group, add_flags, del_flags, body = args
        return _first_sequence(body, _adjust_ignorecase(ignorecase, add_flags, del_flags))
    if op is _ATOMIC_GROUP:
        return _first_sequence(args, ignorecase)
    if op is _GROUPREF_EXISTS:
        _group, yes_body, no_body = args
        ranges = []
        nullable = no_body is None
        yes_first = _first_sequence(yes_body, ignorecase)
        ranges.extend(yes_first.ranges)
        nullable = nullable or yes_first.nullable
        if no_body is not None:
            no_first = _first_sequence(no_body, ignorecase)
            ranges.extend(no_first.ranges)
            nullable = nullable or no_first.nullable
        return _FirstSet(ranges, nullable)
    if op is _GROUPREF:
        return _WILDCARD_FIRST
    if op in _ZERO_WIDTH_OPS:
        return _EMPTY_FIRST
    return _WILDCARD_FIRST


def _first_sequence(items, ignorecase):
    ranges = []
    nullable = True
    for item in items:
        item_first = _first_node(item, ignorecase)
        ranges.extend(item_first.ranges)
        if not item_first.nullable:
            nullable = False
            break
    return _FirstSet(ranges, nullable)


def _last_node(node, ignorecase):
    op, args = node
    if op is _LITERAL:
        return _FirstSet((_literal_ranges(args, ignorecase),), False)
    if op is _NOT_LITERAL:
        ranges = _complement_ranges(_literal_ranges(args, ignorecase))
        return _FirstSet((ranges,), False)
    if op is _IN:
        return _FirstSet((_in_ranges(args, ignorecase),), False)
    if op is _CATEGORY:
        return _FirstSet((_category_ranges(args),), False)
    if op is _ANY or op is _ANY_ALL:
        return _FirstSet(((0, MAX_CODEPOINT),), False)
    if op in _REPEAT_OPS:
        minimum, _maximum, body = args
        body_last = _last_sequence(body, ignorecase)
        return _FirstSet(body_last.ranges, minimum == 0 or body_last.nullable)
    if op is _BRANCH:
        _unused, alternatives = args
        ranges = []
        nullable = False
        for alternative in alternatives:
            alternative_last = _last_sequence(alternative, ignorecase)
            ranges.extend(alternative_last.ranges)
            nullable = nullable or alternative_last.nullable
        return _FirstSet(ranges, nullable)
    if op is _SUBPATTERN:
        _group, add_flags, del_flags, body = args
        return _last_sequence(body, _adjust_ignorecase(ignorecase, add_flags, del_flags))
    if op is _ATOMIC_GROUP:
        return _last_sequence(args, ignorecase)
    if op is _GROUPREF_EXISTS:
        _group, yes_body, no_body = args
        ranges = []
        nullable = no_body is None
        yes_last = _last_sequence(yes_body, ignorecase)
        ranges.extend(yes_last.ranges)
        nullable = nullable or yes_last.nullable
        if no_body is not None:
            no_last = _last_sequence(no_body, ignorecase)
            ranges.extend(no_last.ranges)
            nullable = nullable or no_last.nullable
        return _FirstSet(ranges, nullable)
    if op is _GROUPREF:
        return _WILDCARD_FIRST
    if op in _ZERO_WIDTH_OPS:
        return _EMPTY_FIRST
    return _WILDCARD_FIRST


def _last_sequence(items, ignorecase):
    ranges = []
    nullable = True
    for item in reversed(items):
        item_last = _last_node(item, ignorecase)
        ranges.extend(item_last.ranges)
        if not item_last.nullable:
            nullable = False
            break
    return _FirstSet(ranges, nullable)


def _adjust_ignorecase(ignorecase, add_flags, del_flags):
    if add_flags & _IGNORECASE:
        ignorecase = True
    if del_flags & _IGNORECASE:
        ignorecase = False
    return ignorecase


def _is_unbounded(maximum):
    return maximum == _constants.MAXREPEAT or int(maximum) == int(_constants.MAXREPEAT)


def _can_repeat(maximum):
    return _is_unbounded(maximum) or int(maximum) > 1


def _contains_unbounded(items):
    for node in items:
        op, args = node
        if op in _REPEAT_OPS:
            _minimum, maximum, body = args
            if _is_unbounded(maximum) or _contains_unbounded(body):
                return True
        elif op is _SUBPATTERN:
            if _contains_unbounded(args[3]):
                return True
        elif op is _ATOMIC_GROUP:
            if _contains_unbounded(args):
                return True
        elif op is _BRANCH:
            if any(_contains_unbounded(alt) for alt in args[1]):
                return True
        elif op in (_ASSERT, _ASSERT_NOT):
            if _contains_unbounded(args[1]):
                return True
        elif op is _GROUPREF_EXISTS:
            _group, yes_body, no_body = args
            if _contains_unbounded(yes_body):
                return True
            if no_body is not None and _contains_unbounded(no_body):
                return True
    return False


def _branch_nodes(items):
    for node in items:
        op, args = node
        if op is _BRANCH:
            yield node
            for alternative in args[1]:
                yield from _branch_nodes(alternative)
        elif op in _REPEAT_OPS:
            yield from _branch_nodes(args[2])
        elif op is _SUBPATTERN:
            yield from _branch_nodes(args[3])
        elif op is _ATOMIC_GROUP:
            yield from _branch_nodes(args)
        elif op in (_ASSERT, _ASSERT_NOT):
            yield from _branch_nodes(args[1])
        elif op is _GROUPREF_EXISTS:
            _group, yes_body, no_body = args
            yield from _branch_nodes(yes_body)
            if no_body is not None:
                yield from _branch_nodes(no_body)


class _Signature:
    __slots__ = ("tokens", "deterministic")

    def __init__(self, tokens, deterministic):
        self.tokens = tuple(tokens)
        self.deterministic = deterministic


def _signature_sequence(items, ignorecase):
    tokens = []
    for node in items:
        op, args = node
        if op is _LITERAL:
            tokens.append(_literal_ranges(args, ignorecase))
        elif op is _NOT_LITERAL:
            tokens.append(_complement_ranges(_literal_ranges(args, ignorecase)))
        elif op is _IN:
            tokens.append(_in_ranges(args, ignorecase))
        elif op is _CATEGORY:
            tokens.append(_category_ranges(args))
        elif op is _ANY or op is _ANY_ALL:
            tokens.append((0, MAX_CODEPOINT))
        elif op in _ZERO_WIDTH_OPS:
            continue
        elif op is _SUBPATTERN:
            _group, add_flags, del_flags, body = args
            inner_ignorecase = _adjust_ignorecase(ignorecase, add_flags, del_flags)
            inner = _signature_sequence(body, inner_ignorecase)
            tokens.extend(inner.tokens)
            if not inner.deterministic:
                return _Signature(tokens, False)
        elif op is _ATOMIC_GROUP:
            inner = _signature_sequence(args, ignorecase)
            tokens.extend(inner.tokens)
            if not inner.deterministic:
                return _Signature(tokens, False)
        else:
            return _Signature(tokens, False)
    return _Signature(tokens, True)


def _signatures_overlap(left, right):
    for left_token, right_token in zip(left.tokens, right.tokens):
        if not _intersects(left_token, right_token):
            return False
    return True


def _ambiguous_alternatives(node, ignorecase):
    _unused, alternatives = node[1]
    first_sets = [
        _first_sequence(alternative, ignorecase) for alternative in alternatives
    ]
    signatures = [
        _signature_sequence(alternative, ignorecase) for alternative in alternatives
    ]
    for index, first in enumerate(first_sets):
        if first.nullable:
            return True
        for other_index in range(index + 1, len(first_sets)):
            other = first_sets[other_index]
            if other.nullable:
                return True
            left_signature = signatures[index]
            right_signature = signatures[other_index]
            if left_signature.deterministic and right_signature.deterministic:
                if _signatures_overlap(left_signature, right_signature):
                    return True
                continue
            if any(
                _intersects(left, right)
                for left in first.ranges
                for right in other.ranges
            ):
                return True
    return False


def _needs_branch_check(maximum):
    return _is_unbounded(maximum) or int(maximum) > MAX_BOUNDED_BRANCH_REPEAT


class _Unit:
    __slots__ = ("first", "last", "unbounded")

    def __init__(self, first, last, unbounded):
        self.first = first
        self.last = last
        self.unbounded = unbounded


def _units(items, ignorecase):
    units = []
    for node in items:
        op, args = node
        if op in _ZERO_WIDTH_OPS:
            continue
        if op in _REPEAT_OPS:
            _minimum, maximum, body = args
            first = _first_sequence(body, ignorecase)
            last = _last_sequence(body, ignorecase)
            if not first.ranges and first.nullable:
                continue
            unbounded = _is_unbounded(maximum) or _contains_unbounded(body)
            units.append(_Unit(first.ranges, last.ranges, unbounded))
        elif op is _SUBPATTERN:
            _group, add_flags, del_flags, body = args
            inner_ignorecase = _adjust_ignorecase(ignorecase, add_flags, del_flags)
            first = _first_sequence(body, inner_ignorecase)
            last = _last_sequence(body, inner_ignorecase)
            if not first.ranges and first.nullable:
                continue
            units.append(
                _Unit(first.ranges, last.ranges, _contains_unbounded(body))
            )
        elif op is _ATOMIC_GROUP:
            first = _first_sequence(args, ignorecase)
            last = _last_sequence(args, ignorecase)
            if not first.ranges and first.nullable:
                continue
            units.append(_Unit(first.ranges, last.ranges, _contains_unbounded(args)))
        elif op is _BRANCH:
            first = _first_sequence([node], ignorecase)
            last = _last_sequence([node], ignorecase)
            units.append(_Unit(first.ranges, last.ranges, _contains_unbounded([node])))
        elif op is _GROUPREF_EXISTS:
            first = _first_sequence([node], ignorecase)
            last = _last_sequence([node], ignorecase)
            units.append(_Unit(first.ranges, last.ranges, _contains_unbounded([node])))
        elif op is _GROUPREF:
            units.append(_Unit(_WILDCARD_FIRST.ranges, _WILDCARD_FIRST.ranges, True))
        else:
            first = _first_node(node, ignorecase)
            last = _last_node(node, ignorecase)
            if not first.ranges and first.nullable:
                continue
            units.append(_Unit(first.ranges, last.ranges, False))
    return units


def _check_adjacent_repeats(items, ignorecase):
    units = _units(items, ignorecase)
    for previous, current in zip(units, units[1:]):
        if not previous.unbounded or not current.unbounded:
            continue
        if any(
            _intersects(left, right)
            for left in previous.last
            for right in current.first
        ):
            raise RegexValidationError(
                "pattern contains overlapping unbounded repetitions"
            )


def _count_unbounded_wildcards(items, inside_unbounded=False):
    count = 0
    for node in items:
        op, args = node
        if op in _REPEAT_OPS:
            _minimum, maximum, body = args
            count += _count_unbounded_wildcards(
                body, inside_unbounded or _is_unbounded(maximum)
            )
        elif op is _ANY or op is _ANY_ALL:
            if inside_unbounded:
                count += 1
        elif op is _SUBPATTERN:
            count += _count_unbounded_wildcards(args[3], inside_unbounded)
        elif op is _ATOMIC_GROUP:
            count += _count_unbounded_wildcards(args, inside_unbounded)
        elif op is _BRANCH:
            for alternative in args[1]:
                count += _count_unbounded_wildcards(alternative, inside_unbounded)
        elif op in (_ASSERT, _ASSERT_NOT):
            count += _count_unbounded_wildcards(args[1], inside_unbounded)
        elif op is _GROUPREF_EXISTS:
            _group, yes_body, no_body = args
            count += _count_unbounded_wildcards(yes_body, inside_unbounded)
            if no_body is not None:
                count += _count_unbounded_wildcards(no_body, inside_unbounded)
    return count


def _check_sequence(items, ignorecase, ancestors):
    _check_adjacent_repeats(items, ignorecase)
    for node in items:
        op, args = node
        if op in _REPEAT_OPS:
            _minimum, maximum, body = args
            if not _is_unbounded(maximum) and int(maximum) > MAX_REPEAT_COUNT:
                raise RegexValidationError("repetition count is too large")
            if _can_repeat(maximum):
                for ancestor_maximum, _ancestor_ignorecase in ancestors:
                    if not _can_repeat(ancestor_maximum):
                        continue
                    if _is_unbounded(maximum) or _is_unbounded(ancestor_maximum):
                        raise RegexValidationError(
                            "pattern contains nested quantifiers"
                        )
                if _needs_branch_check(maximum):
                    body_first = _first_sequence(body, ignorecase)
                    if body_first.nullable:
                        raise RegexValidationError(
                            "repeated group can match the empty string"
                        )
                    for branch in _branch_nodes(body):
                        if _ambiguous_alternatives(branch, ignorecase):
                            raise RegexValidationError(
                                "repeated alternatives can match the same text"
                            )
            _check_sequence(
                body,
                ignorecase,
                ancestors + ((maximum, ignorecase),),
            )
        elif op is _SUBPATTERN:
            _group, add_flags, del_flags, body = args
            inner_ignorecase = _adjust_ignorecase(ignorecase, add_flags, del_flags)
            _check_sequence(body, inner_ignorecase, ancestors)
        elif op is _ATOMIC_GROUP:
            _check_sequence(args, ignorecase, ancestors)
        elif op is _BRANCH:
            for alternative in args[1]:
                _check_sequence(alternative, ignorecase, ancestors)
        elif op in (_ASSERT, _ASSERT_NOT):
            _check_sequence(args[1], ignorecase, ancestors)
        elif op is _GROUPREF_EXISTS:
            _group, yes_body, no_body = args
            _check_sequence(yes_body, ignorecase, ancestors)
            if no_body is not None:
                _check_sequence(no_body, ignorecase, ancestors)


def _analyze(parsed):
    ignorecase = bool(
        getattr(getattr(parsed, "state", None), "flags", 0) & _IGNORECASE
    )
    if _count_unbounded_wildcards(parsed) > 1:
        raise RegexValidationError("pattern contains repeated wildcards")
    _check_sequence(parsed, ignorecase, ())


def validate(value):
    """Validate a user supplied regular expression.

    Returns ``True`` for a syntactically valid pattern that is not considered
    vulnerable to catastrophic backtracking.  Raises ``RegexValidationError``
    (a ``ValueError`` and ``TypeError``) otherwise.
    """

    if not isinstance(value, str):
        raise RegexValidationError("pattern must be a string")
    if not value:
        raise RegexValidationError("pattern must not be empty")
    if len(value) > MAX_PATTERN_LENGTH:
        raise RegexValidationError(
            "pattern exceeds the maximum length of %d" % MAX_PATTERN_LENGTH
        )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            parsed = _parser.parse(value)
        except (re.error, RecursionError, OverflowError) as exc:
            raise RegexValidationError("invalid regular expression") from exc
        try:
            _analyze(parsed)
        except RegexValidationError:
            raise
        except (RecursionError, OverflowError) as exc:
            raise RegexValidationError("pattern nesting is too deep") from exc
        try:
            re.compile(value)
        except (re.error, RecursionError, OverflowError) as exc:
            raise RegexValidationError("invalid regular expression") from exc
    return True
