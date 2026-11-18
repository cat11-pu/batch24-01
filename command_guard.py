import re


ALLOWED_COMMANDS = frozenset({"backup", "restore"})

# Arguments are single, shell-safe tokens.  Nothing outside this set is
# permitted, so shell metacharacters, whitespace, quotes, globs, and path
# separators can never reach the command executor.
_SAFE_ARGUMENT = re.compile(r"[A-Za-z0-9_.-]+")


def validate_command(name, args):
    """Validate a whitelisted command and its shell-safe arguments.

    Returns ``True`` when the command may be executed.  Malformed types raise
    ``TypeError``; unsupported commands or unsafe argument values raise
    ``ValueError``.
    """
    if not isinstance(name, str):
        raise TypeError("command name must be a string")
    if not isinstance(args, list):
        raise TypeError("arguments must be a list")

    if not name:
        raise ValueError("command name must not be empty")
    if name not in ALLOWED_COMMANDS:
        raise ValueError("command is not allowed")

    for arg in args:
        if not isinstance(arg, str):
            raise TypeError("each argument must be a string")
        if _SAFE_ARGUMENT.fullmatch(arg) is None:
            raise ValueError("argument contains disallowed characters")
        if arg == "." or ".." in arg:
            raise ValueError("path traversal is not allowed")

    return True
