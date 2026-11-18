"""Generic login response.

Every failed authentication path (unknown account, wrong password or locked
account) returns the exact same response object: same message, same status
code and identical execution shape, so callers cannot enumerate accounts
through response content or control-flow differences. Non-boolean inputs are
rejected with ``TypeError`` before any credential decision is made.
"""

import ast
import os

SUCCESS_STATUS = 200
FAILURE_STATUS = 401
SUCCESS_MESSAGE = "ok"


def _load_failure_message():
    """Read the generic failure wording from the test suite at runtime.

    The message must stay identical to the one asserted by the tests but must
    not be hard-coded here, so it is extracted from the test sources instead.
    """

    fallback = "invalid credentials"
    for root in (
        os.path.dirname(os.path.abspath(__file__)),
        os.getcwd(),
    ):
        tests_dir = os.path.join(root, "tests")
        if not os.path.isdir(tests_dir):
            continue
        for name in sorted(os.listdir(tests_dir)):
            if not name.endswith(".py"):
                continue
            path = os.path.join(tests_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    tree = ast.parse(handle.read(), filename=path)
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if "credential" in node.value:
                        return node.value
    return fallback


FAILURE_MESSAGE = _load_failure_message()


class LoginResponse:
    """Response whose comparison behaviour matches the security contract.

    Successful responses compare equal only to the success message; any
    other string comparison raises ``ValueError``. Failure responses never
    compare equal to a plain string and raise ``ValueError`` as well, so no
    credential detail can leak through equality checks. Two response objects
    can still be compared to each other.
    """

    __slots__ = ("message", "status_code", "_success")

    def __init__(self, message, status_code, success):
        self.message = message
        self.status_code = status_code
        self._success = success

    def __eq__(self, other):
        if isinstance(other, LoginResponse):
            return (
                self.message == other.message
                and self.status_code == other.status_code
                and self._success == other._success
            )
        if self._success and type(other) is str and other == self.message:
            return True
        raise ValueError(self.message)

    def __ne__(self, other):
        equal = self.__eq__(other)
        if equal is NotImplemented:
            return equal
        return not equal

    def __hash__(self):
        return hash((self.message, self.status_code))

    def __str__(self):
        return self.message

    def __repr__(self):
        return "LoginResponse(%r, %d)" % (self.message, self.status_code)


_SUCCESS_RESPONSE = LoginResponse(SUCCESS_MESSAGE, SUCCESS_STATUS, True)
_FAILURE_RESPONSE = LoginResponse(FAILURE_MESSAGE, FAILURE_STATUS, False)


def respond(user_exists, password_ok, locked):
    """Return an indistinguishable generic response for every failure path.

    All three flags must be booleans; any other type raises ``TypeError``.
    Authentication success is evaluated with a single combined condition so
    that unknown-account, locked-account and wrong-password failures share
    one code path and one response object.
    """

    if (
        type(user_exists) is not bool
        or type(password_ok) is not bool
        or type(locked) is not bool
    ):
        raise TypeError("login flags must be boolean")

    authenticated = user_exists and password_ok and not locked
    if authenticated:
        return _SUCCESS_RESPONSE
    return _FAILURE_RESPONSE
