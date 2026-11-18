import io
import pickle
import pickletools

# 危险 opcode 名单：任何一条出现即拒绝。
_FORBIDDEN_OPCODES = frozenset({
    "GLOBAL",
    "STACK_GLOBAL",
    "REDUCE",
    "BUILD",
    "INST",
    "OBJ",
    "NEWOBJ",
    "NEWOBJ_EX",
    "EXT1",
    "EXT2",
    "EXT4",
    "PERSID",
    "BINPERSID",
})

# 白名单：仅允许构造基本标量、列表和字典所需的 opcode。
_ALLOWED_OPCODES = frozenset({
    "PROTO",
    "FRAME",
    "STOP",
    "MARK",
    "POP",
    "POP_MARK",
    "DUP",
    "NONE",
    "NEWTRUE",
    "NEWFALSE",
    "INT",
    "BININT",
    "BININT1",
    "BININT2",
    "LONG",
    "LONG1",
    "LONG4",
    "FLOAT",
    "BINFLOAT",
    "STRING",
    "BINSTRING",
    "SHORT_BINSTRING",
    "UNICODE",
    "BINUNICODE",
    "SHORT_BINUNICODE",
    "BINUNICODE8",
    "BINBYTES",
    "SHORT_BINBYTES",
    "EMPTY_LIST",
    "APPEND",
    "APPENDS",
    "LIST",
    "EMPTY_DICT",
    "DICT",
    "SETITEM",
    "SETITEMS",
    "GET",
    "BINGET",
    "LONG_BINGET",
    "PUT",
    "BINPUT",
    "LONG_BINPUT",
    "MEMOIZE",
})


class _RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise ValueError("global references are not allowed: %r.%r" % (module, name))


def _scan_opcodes(data):
    try:
        opcodes = list(pickletools.genops(data))
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("malformed pickle data") from exc
    for opcode, _arg, _pos in opcodes:
        name = opcode.name
        if name in _FORBIDDEN_OPCODES:
            raise ValueError("forbidden pickle opcode: %s" % name)
        if name not in _ALLOWED_OPCODES:
            raise ValueError("unsupported pickle opcode: %s" % name)


def loads_safe(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError("expected a bytes-like object")
    data = bytes(data)
    _scan_opcodes(data)
    try:
        return _RestrictedUnpickler(io.BytesIO(data)).load()
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("malformed pickle data") from exc
