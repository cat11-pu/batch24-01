"""Small, dependency-free GraphQL query guard.

The guard parses executable GraphQL documents and applies deterministic
complexity limits before a query is handed to an executor.  It deliberately
does not keep any module-level mutable state, so concurrent calls are safe.
"""

from __future__ import annotations


DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_COST = 100
DEFAULT_MAX_ALIASES = 100
DEFAULT_MAX_FRAGMENT_DEPTH = 10
DEFAULT_MAX_QUERY_LENGTH = 10_000
DEFAULT_MAX_VARIABLES = 4
DEFAULT_MAX_DIRECTIVES_PER_FIELD = 2

_OPERATION_TYPES = frozenset(("query", "mutation", "subscription"))
_NAME_START = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
)
_NAME_CONTINUE = _NAME_START | frozenset("0123456789")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_NON_ZERO_DIGITS = frozenset("123456789")
_EXPONENT_MARKERS = frozenset("eE")
_SIGNS = frozenset("+-")
_STRING_ESCAPES = frozenset('"\\/bfnrt')
_IGNORED = frozenset(" \t\n\r,\ufeff")
_PUNCTUATORS = frozenset("!$&():=@[]{|}")


class _Token:
    __slots__ = ("kind", "value", "line", "column")

    def __init__(self, kind, value, line, column):
        self.kind = kind
        self.value = value
        self.line = line
        self.column = column

    def location(self):
        return f"line {self.line}, column {self.column}"


class _Lexer:
    def __init__(self, source):
        self.source = source
        self.length = len(source)
        self.index = 0
        self.line = 1
        self.column = 1

    def tokenize(self):
        tokens = []
        while True:
            self._skip_ignored()
            if self.index >= self.length:
                tokens.append(_Token("EOF", None, self.line, self.column))
                return tokens
            tokens.append(self._next_token())

    def _peek(self, offset=0):
        index = self.index + offset
        if index >= self.length:
            return ""
        return self.source[index]

    def _advance(self, count=1):
        for _ in range(count):
            if self.index >= self.length:
                return
            character = self.source[self.index]
            self.index += 1
            if character == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1

    def _skip_ignored(self):
        while self.index < self.length:
            character = self._peek()
            if character in _IGNORED:
                self._advance()
                continue
            if character == "#":
                while self.index < self.length and self._peek() not in "\r\n":
                    self._advance()
                continue
            return

    def _next_token(self):
        line, column = self.line, self.column
        character = self._peek()

        if character in _NAME_START:
            start = self.index
            self._advance()
            while self._peek() in _NAME_CONTINUE:
                self._advance()
            return _Token("NAME", self.source[start : self.index], line, column)

        if character == '"':
            value = self._read_string()
            return _Token("STRING", value, line, column)

        if character == "-" or character.isdigit():
            value = self._read_number()
            kind = "FLOAT" if ("." in value or "e" in value or "E" in value) else "INT"
            return _Token(kind, value, line, column)

        if character == ".":
            if self.source.startswith("...", self.index):
                self._advance(3)
                return _Token("PUNCT", "...", line, column)
            raise ValueError(f"invalid character '.' at line {line}, column {column}")

        if character in _PUNCTUATORS:
            self._advance()
            return _Token("PUNCT", character, line, column)

        raise ValueError(
            f"invalid character {character!r} at line {line}, column {column}"
        )

    def _read_number(self):
        start = self.index
        if self._peek() == "-":
            self._advance()
            if not self._peek().isdigit():
                raise ValueError(
                    f"invalid number at line {self.line}, column {self.column}"
                )

        if self._peek() == "0":
            self._advance()
            if self._peek().isdigit():
                raise ValueError(
                    f"invalid number at line {self.line}, column {self.column}"
                )
        elif self._peek() in _NON_ZERO_DIGITS:
            while self._peek().isdigit():
                self._advance()
        else:
            raise ValueError(
                f"invalid number at line {self.line}, column {self.column}"
            )

        if self._peek() == ".":
            self._advance()
            if not self._peek().isdigit():
                raise ValueError(
                    f"invalid number at line {self.line}, column {self.column}"
                )
            while self._peek().isdigit():
                self._advance()

        if self._peek() in _EXPONENT_MARKERS:
            self._advance()
            if self._peek() in _SIGNS:
                self._advance()
            if not self._peek().isdigit():
                raise ValueError(
                    f"invalid number at line {self.line}, column {self.column}"
                )
            while self._peek().isdigit():
                self._advance()

        if self._peek() in _NAME_START or self._peek() == ".":
            raise ValueError(
                f"invalid number at line {self.line}, column {self.column}"
            )
        return self.source[start : self.index]

    def _read_string(self):
        if self.source.startswith('"""', self.index):
            return self._read_block_string()

        self._advance()
        while self.index < self.length:
            character = self._peek()
            if character == '"':
                self._advance()
                return True
            if character in "\r\n":
                raise ValueError(
                    f"unterminated string at line {self.line}, column {self.column}"
                )
            if ord(character) < 0x20:
                raise ValueError(
                    f"invalid control character in string at line {self.line}, "
                    f"column {self.column}"
                )
            if character == "\\":
                self._advance()
                escaped = self._peek()
                if escaped in _STRING_ESCAPES:
                    self._advance()
                    continue
                if escaped == "u":
                    self._advance()
                    for _ in range(4):
                        if self._peek() not in _HEX_DIGITS:
                            raise ValueError(
                                f"invalid unicode escape at line {self.line}, "
                                f"column {self.column}"
                            )
                        self._advance()
                    continue
                raise ValueError(
                    f"invalid string escape at line {self.line}, "
                    f"column {self.column}"
                )
            self._advance()
        raise ValueError("unterminated string")

    def _read_block_string(self):
        self._advance(3)
        while self.index < self.length:
            if self.source.startswith('"""', self.index):
                self._advance(3)
                return True
            if self.source.startswith('\\"""', self.index):
                self._advance(4)
                continue
            self._advance()
        raise ValueError("unterminated block string")


class _SelectionSet:
    __slots__ = ("selections",)

    def __init__(self, selections):
        self.selections = selections


class _Field:
    __slots__ = ("alias", "name", "arguments", "directives", "selection", "token")

    def __init__(self, alias, name, arguments, directives, selection, token):
        self.alias = alias
        self.name = name
        self.arguments = arguments
        self.directives = directives
        self.selection = selection
        self.token = token


class _FragmentSpread:
    __slots__ = ("name", "directives", "token")

    def __init__(self, name, directives, token):
        self.name = name
        self.directives = directives
        self.token = token


class _InlineFragment:
    __slots__ = ("type_condition", "directives", "selection", "token")

    def __init__(self, type_condition, directives, selection, token):
        self.type_condition = type_condition
        self.directives = directives
        self.selection = selection
        self.token = token


class _Operation:
    __slots__ = ("operation_type", "name", "variables", "directives", "selection")

    def __init__(self, operation_type, name, variables, directives, selection):
        self.operation_type = operation_type
        self.name = name
        self.variables = variables
        self.directives = directives
        self.selection = selection


class _Fragment:
    __slots__ = ("name", "type_condition", "directives", "selection", "token")

    def __init__(self, name, type_condition, directives, selection, token):
        self.name = name
        self.type_condition = type_condition
        self.directives = directives
        self.selection = selection
        self.token = token


class _Document:
    __slots__ = ("operations", "fragments")

    def __init__(self, operations, fragments):
        self.operations = operations
        self.fragments = fragments


class _Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.index = 0
        self.operations = []
        self.fragments = {}

    def _current(self):
        return self.tokens[self.index]

    def _peek(self, offset=0):
        index = min(self.index + offset, len(self.tokens) - 1)
        return self.tokens[index]

    def _advance(self):
        token = self._current()
        if token.kind != "EOF":
            self.index += 1
        return token

    def _expect_punct(self, value):
        token = self._current()
        if token.kind != "PUNCT" or token.value != value:
            raise ValueError(
                f"expected {value!r} at {token.location()}, got {self._describe(token)}"
            )
        return self._advance()

    def _expect_name(self, what="name"):
        token = self._current()
        if token.kind != "NAME":
            raise ValueError(
                f"expected {what} at {token.location()}, got {self._describe(token)}"
            )
        return self._advance()

    def _take_punct(self, value):
        token = self._current()
        if token.kind == "PUNCT" and token.value == value:
            self._advance()
            return True
        return False

    def _describe(self, token):
        if token.kind == "EOF":
            return "end of query"
        return repr(token.value)

    def parse(self):
        while self._current().kind != "EOF":
            token = self._current()
            if token.kind == "PUNCT" and token.value == "{":
                self.operations.append(self._parse_operation(shorthand=True))
            elif token.kind == "NAME" and token.value == "fragment":
                self._parse_fragment_definition()
            elif token.kind == "NAME" and token.value in _OPERATION_TYPES:
                self.operations.append(self._parse_operation(shorthand=False))
            else:
                raise ValueError(
                    f"expected an operation or fragment definition at "
                    f"{token.location()}, got {self._describe(token)}"
                )

        if not self.operations:
            raise ValueError("query must contain at least one operation")
        return _Document(self.operations, self.fragments)

    def _parse_operation(self, shorthand):
        if shorthand:
            selection = self._parse_selection_set()
            return _Operation("query", None, [], [], selection)

        operation_token = self._advance()
        operation_type = operation_token.value
        name = None
        if self._current().kind == "NAME":
            name = self._advance().value

        variables = self._parse_variable_definitions()
        directives = self._parse_directives()
        selection = self._parse_selection_set()
        return _Operation(operation_type, name, variables, directives, selection)

    def _parse_fragment_definition(self):
        fragment_token = self._advance()
        name_token = self._expect_name("fragment name")
        if name_token.value == "on":
            raise ValueError(
                f"'on' cannot be used as a fragment name at {name_token.location()}"
            )
        on_token = self._expect_name("'on'")
        if on_token.value != "on":
            raise ValueError(
                f"expected 'on' at {on_token.location()}, got {on_token.value!r}"
            )
        type_condition = self._expect_name("type condition").value
        directives = self._parse_directives()
        selection = self._parse_selection_set()
        if name_token.value in self.fragments:
            raise ValueError(
                f"duplicate fragment definition {name_token.value!r} at "
                f"{name_token.location()}"
            )
        self.fragments[name_token.value] = _Fragment(
            name_token.value,
            type_condition,
            directives,
            selection,
            fragment_token,
        )

    def _parse_variable_definitions(self):
        if not self._take_punct("("):
            return []
        if self._take_punct(")"):
            token = self._current()
            raise ValueError(
                f"variable definitions cannot be empty at {token.location()}"
            )

        definitions = []
        while True:
            self._expect_punct("$")
            name = self._expect_name("variable name")
            self._expect_punct(":")
            self._parse_type_reference()
            if self._take_punct("="):
                self._parse_value()
            self._parse_directives()
            definitions.append((name.value, True))
            if self._take_punct(")"):
                break
            if self._current().kind == "EOF":
                raise ValueError("unterminated variable definitions")
        return definitions

    def _parse_type_reference(self):
        if self._take_punct("["):
            self._parse_type_reference()
            self._expect_punct("]")
        else:
            self._expect_name("type name")
        self._take_punct("!")

    def _parse_selection_set(self):
        self._expect_punct("{")
        selections = []
        if self._take_punct("}"):
            token = self._current()
            raise ValueError(
                f"selection set cannot be empty at {token.location()}"
            )

        while True:
            if self._current().kind == "EOF":
                raise ValueError("unterminated selection set")
            if self._take_punct("}"):
                break
            selections.append(self._parse_selection())
        return _SelectionSet(selections)

    def _parse_selection(self):
        token = self._current()
        if token.kind == "PUNCT" and token.value == "...":
            return self._parse_fragment_like()
        if token.kind == "NAME":
            return self._parse_field()
        raise ValueError(
            f"expected a field or fragment at {token.location()}, "
            f"got {self._describe(token)}"
        )

    def _parse_field(self):
        token = self._expect_name("field name")
        alias = None
        name = token.value
        if self._take_punct(":"):
            alias = name
            name_token = self._expect_name("field name")
            name = name_token.value
            field_token = name_token
        else:
            field_token = token

        arguments = self._parse_arguments()
        directives = self._parse_directives()
        selection = None
        if self._current().kind == "PUNCT" and self._current().value == "{":
            selection = self._parse_selection_set()
        return _Field(alias, name, arguments, directives, selection, field_token)

    def _parse_fragment_like(self):
        spread_token = self._advance()
        if self._current().kind == "NAME" and self._current().value == "on":
            self._advance()
            type_condition = self._expect_name("type condition").value
            directives = self._parse_directives()
            selection = self._parse_selection_set()
            return _InlineFragment(
                type_condition, directives, selection, spread_token
            )

        if self._current().kind == "PUNCT" and self._current().value in ("{", "@"):
            directives = self._parse_directives()
            selection = self._parse_selection_set()
            return _InlineFragment(None, directives, selection, spread_token)

        if self._current().kind == "NAME":
            name = self._advance().value
            directives = self._parse_directives()
            return _FragmentSpread(name, directives, spread_token)

        raise ValueError(
            f"expected a fragment name, type condition, or selection set at "
            f"{self._current().location()}"
        )

    def _parse_arguments(self):
        if not self._take_punct("("):
            return []
        if self._take_punct(")"):
            token = self._current()
            raise ValueError(f"arguments cannot be empty at {token.location()}")

        arguments = []
        while True:
            name = self._expect_name("argument name")
            self._expect_punct(":")
            self._parse_value()
            arguments.append(name.value)
            if self._take_punct(")"):
                break
            if self._current().kind == "EOF":
                raise ValueError("unterminated arguments")
        return arguments

    def _parse_directives(self):
        directives = []
        while self._take_punct("@"):
            token = self._expect_name("directive name")
            arguments = self._parse_arguments()
            directives.append((token.value, arguments))
        return directives

    def _parse_value(self):
        token = self._current()
        if token.kind == "PUNCT" and token.value == "$":
            self._advance()
            self._expect_name("variable name")
            return
        if token.kind in ("INT", "FLOAT", "STRING"):
            self._advance()
            return
        if token.kind == "NAME":
            self._advance()
            return
        if token.kind == "PUNCT" and token.value == "[":
            self._advance()
            while not self._take_punct("]"):
                if self._current().kind == "EOF":
                    raise ValueError("unterminated list value")
                self._parse_value()
            return
        if token.kind == "PUNCT" and token.value == "{":
            self._advance()
            while not self._take_punct("}"):
                if self._current().kind == "EOF":
                    raise ValueError("unterminated object value")
                self._expect_name("object field name")
                self._expect_punct(":")
                self._parse_value()
            return
        raise ValueError(
            f"expected a value at {token.location()}, got {self._describe(token)}"
        )


def _iter_selections(selection_set):
    for selection in selection_set.selections:
        yield selection
        if isinstance(selection, _Field):
            if selection.selection is not None:
                yield from _iter_selections(selection.selection)
        elif isinstance(selection, _InlineFragment):
            yield from _iter_selections(selection.selection)


def _collect_spreads(selection_set, spreads):
    for selection in selection_set.selections:
        if isinstance(selection, _Field):
            if selection.selection is not None:
                _collect_spreads(selection.selection, spreads)
        elif isinstance(selection, _InlineFragment):
            _collect_spreads(selection.selection, spreads)
        else:
            spreads.append(selection)


class _Usage:
    __slots__ = ("depth", "cost", "aliases")

    def __init__(self, depth=0, cost=0, aliases=0):
        self.depth = depth
        self.cost = cost
        self.aliases = aliases


class _Analyzer:
    def __init__(self, document, options):
        self.document = document
        self.options = options
        self.fragment_spreads = {}
        self.fragment_usage = {}
        self.fragment_chain = {}

    def analyze(self):
        self._check_fragment_references()
        self._check_fragment_cycles()
        self._check_fragment_chains()
        self._check_fields_and_directives()
        self._check_operations()

    def _check_fragment_references(self):
        for fragment in self.document.fragments.values():
            spreads = []
            _collect_spreads(fragment.selection, spreads)
            names = []
            for spread in spreads:
                if spread.name not in self.document.fragments:
                    raise ValueError(
                        f"undefined fragment {spread.name!r} at "
                        f"{spread.token.location()}"
                    )
                names.append(spread.name)
            self.fragment_spreads[fragment.name] = names

        for operation in self.document.operations:
            spreads = []
            _collect_spreads(operation.selection, spreads)
            for spread in spreads:
                if spread.name not in self.document.fragments:
                    raise ValueError(
                        f"undefined fragment {spread.name!r} at "
                        f"{spread.token.location()}"
                    )

    def _check_fragment_cycles(self):
        state = {}

        def visit(name, path):
            status = state.get(name, 0)
            if status == 1:
                cycle_start = path.index(name)
                cycle = path[cycle_start:] + [name]
                raise ValueError(
                    "cyclic fragment reference: " + " -> ".join(cycle)
                )
            if status == 2:
                return
            state[name] = 1
            path.append(name)
            for child in self.fragment_spreads.get(name, ()):
                visit(child, path)
            path.pop()
            state[name] = 2

        for fragment_name in self.document.fragments:
            visit(fragment_name, [])

    def _check_fragment_chains(self):
        def chain_depth(name):
            if name in self.fragment_chain:
                return self.fragment_chain[name]
            depth = 1
            for child in self.fragment_spreads.get(name, ()):
                depth = max(depth, 1 + chain_depth(child))
            self.fragment_chain[name] = depth
            return depth

        for fragment_name in self.document.fragments:
            depth = chain_depth(fragment_name)
            if depth > self.options.max_fragment_depth:
                raise ValueError(
                    f"fragment nesting depth {depth} exceeds limit "
                    f"{self.options.max_fragment_depth}"
                )

    def _check_fields_and_directives(self):
        for operation in self.document.operations:
            self._check_directive_count(operation.directives, "operation")
            self._check_selection_fields(operation.selection)
        for fragment in self.document.fragments.values():
            self._check_directive_count(
                fragment.directives, f"fragment {fragment.name!r}"
            )
            if _is_introspection_type(fragment.type_condition):
                raise ValueError(
                    f"introspection type {fragment.type_condition!r} is not "
                    f"allowed at {fragment.token.location()}"
                )
            self._check_selection_fields(fragment.selection)

    def _check_selection_fields(self, selection_set):
        for selection in _iter_selections(selection_set):
            if isinstance(selection, _Field):
                if _is_introspection_field(selection.name):
                    raise ValueError(
                        f"introspection field {selection.name!r} is not allowed at "
                        f"{selection.token.location()}"
                    )
                label = f"field {selection.name!r}"
            elif isinstance(selection, _InlineFragment):
                if (
                    selection.type_condition is not None
                    and _is_introspection_type(selection.type_condition)
                ):
                    raise ValueError(
                        f"introspection type {selection.type_condition!r} is not "
                        f"allowed at {selection.token.location()}"
                    )
                label = "inline fragment"
            else:
                label = f"fragment spread {selection.name!r}"
            self._check_directive_count(selection.directives, label)

    def _check_directive_count(self, directives, label):
        directive_count = len(directives)
        if directive_count > self.options.max_directives:
            raise ValueError(
                f"{label} has {directive_count} directives; maximum is "
                f"{self.options.max_directives}"
            )

    def _check_operations(self):
        names = set()
        for operation in self.document.operations:
            if operation.name is not None:
                if operation.name in names:
                    raise ValueError(
                        f"duplicate operation name {operation.name!r}"
                    )
                names.add(operation.name)
            if len(operation.variables) > self.options.max_variables:
                raise ValueError(
                    f"operation defines {len(operation.variables)} variables; "
                    f"maximum is {self.options.max_variables}"
                )
            usage = self._selection_usage(operation.selection, [])
            usage.cost += len(operation.directives)
            self._enforce_operation_usage(operation, usage)

        if len(self.document.operations) > 1:
            for operation in self.document.operations:
                if operation.name is None:
                    raise ValueError(
                        "anonymous operation must be the only operation in a query"
                    )

        for fragment_name in self.document.fragments:
            usage = self._fragment_usage(fragment_name, [])
            self._enforce_fragment_usage(fragment_name, usage)

    def _selection_usage(self, selection_set, fragment_stack):
        depth = 0
        cost = 0
        aliases = 0

        for selection in selection_set.selections:
            if isinstance(selection, _Field):
                field_depth = 1
                field_cost = 1 + len(selection.arguments) + len(selection.directives)
                field_aliases = 1 if selection.alias is not None else 0
                if selection.selection is not None:
                    child = self._selection_usage(selection.selection, fragment_stack)
                    field_depth += child.depth
                    field_cost += child.cost
                    field_aliases += child.aliases
                depth = max(depth, field_depth)
                cost += field_cost
                aliases += field_aliases
            elif isinstance(selection, _InlineFragment):
                child = self._selection_usage(selection.selection, fragment_stack)
                depth = max(depth, child.depth)
                cost += child.cost + len(selection.directives)
                aliases += child.aliases
            else:
                child = self._fragment_usage(selection.name, fragment_stack)
                depth = max(depth, child.depth)
                cost += child.cost + len(selection.directives)
                aliases += child.aliases

        return _Usage(depth, cost, aliases)

    def _fragment_usage(self, name, fragment_stack):
        cached = self.fragment_usage.get(name)
        if cached is not None:
            return cached
        if name in fragment_stack:
            raise ValueError(f"cyclic fragment reference involving {name!r}")
        fragment_stack.append(name)
        try:
            usage = self._selection_usage(
                self.document.fragments[name].selection, fragment_stack
            )
        finally:
            fragment_stack.pop()
        self.fragment_usage[name] = usage
        return usage

    def _enforce_operation_usage(self, operation, usage):
        label = (
            f"operation {operation.name!r}"
            if operation.name is not None
            else "anonymous operation"
        )
        if usage.depth > self.options.max_depth:
            raise ValueError(
                f"{label} depth {usage.depth} exceeds limit "
                f"{self.options.max_depth}"
            )
        if usage.aliases > self.options.max_aliases:
            raise ValueError(
                f"{label} uses {usage.aliases} aliases; maximum is "
                f"{self.options.max_aliases}"
            )
        if usage.cost > self.options.max_cost:
            raise ValueError(
                f"{label} cost {usage.cost} exceeds limit {self.options.max_cost}"
            )

    def _enforce_fragment_usage(self, name, usage):
        if usage.depth > self.options.max_depth:
            raise ValueError(
                f"fragment {name!r} depth {usage.depth} exceeds limit "
                f"{self.options.max_depth}"
            )
        if usage.aliases > self.options.max_aliases:
            raise ValueError(
                f"fragment {name!r} uses {usage.aliases} aliases; maximum is "
                f"{self.options.max_aliases}"
            )
        if usage.cost > self.options.max_cost:
            raise ValueError(
                f"fragment {name!r} cost {usage.cost} exceeds limit "
                f"{self.options.max_cost}"
            )


def _is_introspection_field(name):
    if name == "__typename":
        return False
    return name.startswith("__")


def _is_introspection_type(name):
    return name.startswith("__")


class _Options:
    __slots__ = (
        "max_depth",
        "max_cost",
        "max_aliases",
        "max_fragment_depth",
        "max_query_length",
        "max_variables",
        "max_directives",
    )

    def __init__(
        self,
        max_depth,
        max_cost,
        max_aliases,
        max_fragment_depth,
        max_query_length,
        max_variables,
        max_directives,
    ):
        self.max_depth = _require_limit("max_depth", max_depth)
        self.max_cost = _require_limit("max_cost", max_cost)
        self.max_aliases = _require_limit("max_aliases", max_aliases)
        self.max_fragment_depth = _require_limit(
            "max_fragment_depth", max_fragment_depth
        )
        self.max_query_length = _require_limit(
            "max_query_length", max_query_length
        )
        self.max_variables = _require_limit("max_variables", max_variables)
        self.max_directives = _require_limit(
            "max_directives", max_directives
        )


def _require_limit(name, value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def validate_query(
    query,
    max_depth=DEFAULT_MAX_DEPTH,
    max_cost=DEFAULT_MAX_COST,
    *,
    max_aliases=DEFAULT_MAX_ALIASES,
    max_fragment_depth=DEFAULT_MAX_FRAGMENT_DEPTH,
    max_query_length=DEFAULT_MAX_QUERY_LENGTH,
    max_variables=DEFAULT_MAX_VARIABLES,
    max_directives=DEFAULT_MAX_DIRECTIVES_PER_FIELD,
):
    """Validate a GraphQL query against complexity and security limits.

    ``query`` must be a non-empty string.  Invalid documents raise
    :class:`ValueError`; values of the wrong type raise :class:`TypeError`.
    A valid, within-limit query returns ``True``.

    The optional keyword limits tighten or relax the individual protections:
    query size, nesting depth, expanded field/directive/argument cost, alias
    count, fragment nesting, variable count, and directives per field.
    """

    if not isinstance(query, str):
        raise TypeError("query must be a string")

    options = _Options(
        max_depth,
        max_cost,
        max_aliases,
        max_fragment_depth,
        max_query_length,
        max_variables,
        max_directives,
    )

    if not query.strip():
        raise ValueError("query must not be empty")
    if len(query) > options.max_query_length:
        raise ValueError(
            f"query length {len(query)} exceeds limit "
            f"{options.max_query_length}"
        )

    try:
        tokens = _Lexer(query).tokenize()
        document = _Parser(tokens).parse()
        _Analyzer(document, options).analyze()
    except RecursionError as error:
        raise ValueError("query is nested too deeply to analyze") from error

    return True
