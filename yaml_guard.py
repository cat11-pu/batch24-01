import math
import re

import yaml

MAX_DEPTH = 100

_SAFE_NODE_TAGS = frozenset({
    "tag:yaml.org,2002:null",
    "tag:yaml.org,2002:bool",
    "tag:yaml.org,2002:int",
    "tag:yaml.org,2002:float",
    "tag:yaml.org,2002:str",
    "tag:yaml.org,2002:seq",
    "tag:yaml.org,2002:map",
})

_SAFE_SCALAR_TYPES = (str, int, float, bool, type(None))

_UNSAFE_SCALAR_TOKEN = re.compile(r"(?:^|[^a-zA-Z])(?:nan|inf(?:inity)?)(?:[^a-zA-Z]|$)", re.IGNORECASE)


def _reject(message):
    raise ValueError("unsafe YAML: %s" % message)


def _check_tokens(text):
    try:
        tokens = yaml.scan(text, Loader=yaml.SafeLoader)
        for token in tokens:
            if isinstance(token, yaml.tokens.AnchorToken):
                _reject("anchors are not allowed")
            if isinstance(token, yaml.tokens.AliasToken):
                _reject("aliases are not allowed")
    except yaml.YAMLError as exc:
        _reject("cannot be parsed (%s)" % exc)


def _check_nodes(text):
    try:
        documents = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError as exc:
        _reject("cannot be composed (%s)" % exc)
    except RecursionError:
        _reject("nesting too deep")
    if not documents:
        _reject("empty document")
    for document in documents:
        if document is None:
            _reject("empty document")
        stack = [(document, 1)]
        while stack:
            node, depth = stack.pop()
            if depth > MAX_DEPTH:
                _reject("nesting deeper than %d levels" % MAX_DEPTH)
            if node.tag not in _SAFE_NODE_TAGS:
                _reject("unsupported tag %r" % node.tag)
            if isinstance(node, yaml.MappingNode):
                for key_node, value_node in node.value:
                    stack.append((key_node, depth + 1))
                    stack.append((value_node, depth + 1))
            elif isinstance(node, yaml.SequenceNode):
                for child in node.value:
                    stack.append((child, depth + 1))


def _check_data(data, depth=1):
    if depth > MAX_DEPTH:
        _reject("nesting deeper than %d levels" % MAX_DEPTH)
    if isinstance(data, dict):
        for key, item in data.items():
            if not isinstance(key, _SAFE_SCALAR_TYPES):
                _reject("unsafe mapping key of type %s" % type(key).__name__)
            _check_scalar(key)
            _check_data(item, depth + 1)
    elif isinstance(data, list):
        for item in data:
            _check_data(item, depth + 1)
    elif isinstance(data, _SAFE_SCALAR_TYPES):
        _check_scalar(data)
    else:
        _reject("value of type %s is not allowed" % type(data).__name__)


def _check_scalar(value):
    if isinstance(value, float) and not math.isfinite(value):
        _reject("non-finite float")
    if isinstance(value, str) and _UNSAFE_SCALAR_TOKEN.search(value):
        _reject("suspicious scalar %r" % value)


def _validate_text(text):
    if not text.strip():
        _reject("empty input")
    _check_tokens(text)
    _check_nodes(text)
    try:
        documents = list(yaml.load_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError as exc:
        _reject("cannot be loaded (%s)" % exc)
    except RecursionError:
        _reject("nesting too deep")
    if not documents:
        _reject("empty document")
    for document in documents:
        if not isinstance(document, (dict, list)):
            _reject("top-level value must be a mapping or sequence")
        _check_data(document)
    return True


def validate(value):
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("unsafe YAML: not valid UTF-8") from exc
    if isinstance(value, str):
        return _validate_text(value)
    if isinstance(value, (dict, list)):
        return _check_data(value) or True
    raise TypeError("validate() expects a YAML string, got %s" % type(value).__name__)
