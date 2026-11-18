import pytest

from pickle_guard import loads_safe

BAD_PAYLOADS = [
    b"cos\nsystem\n(S'id'\ntR.",
    b"csubprocess\ncheck_output\n(S'id'\ntR.",
    b"cbuiltins\neval\n(S'1+1'\ntR.",
    b"cbuiltins\nexec\n(S'x=1'\ntR.",
    b"cposix\nsystem\n(S'id'\ntR.",
    b"cnt\nsystem\n(S'id'\ntR.",
    b"c__builtin__\neval\n(S'1'\ntR.",
    b"cos\npopen\n(S'id'\ntR.",
    b"cshutil\nrmtree\n(S'/tmp/x'\ntR.",
    b"cpathlib\nPath\n(S'/etc/passwd'\ntR.",
    b"csubprocess\nPopen\n(S'id'\ntR.",
    b"cbuiltins\ngetattr\n(S'os'\nS'system'\ntR.",
    b"cos\nremove\n(S'/etc/passwd'\ntR.",
    b"cpty\nspawn\n(S'/bin/sh'\ntR.",
    b"cimportlib\nimport_module\n(S'os'\ntR.",
]


@pytest.mark.parametrize("payload", BAD_PAYLOADS)
def test_dangerous_pickle_is_rejected(payload):
    with pytest.raises(ValueError):
        loads_safe(payload)
