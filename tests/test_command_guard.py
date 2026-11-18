import pytest

from command_guard import validate_command


def test_1_semicolon_is_rejected():
    with pytest.raises(ValueError):
        validate_command("backup", ["data;rm -rf /"])


def test_2_pipe_is_rejected():
    with pytest.raises(ValueError):
        validate_command("backup", ["data|cat /etc/passwd"])


def test_3_ampersand_is_rejected():
    with pytest.raises(ValueError):
        validate_command("backup", ["data&whoami"])


def test_4_command_substitution_is_rejected():
    with pytest.raises(ValueError):
        validate_command("backup", ["$(id)"])


def test_5_backticks_are_rejected():
    with pytest.raises(ValueError):
        validate_command("backup", ["`id`"])


def test_6_newline_is_rejected():
    with pytest.raises(ValueError):
        validate_command("backup", ["data\nwhoami"])


def test_7_output_redirect_is_rejected():
    with pytest.raises(ValueError):
        validate_command("backup", ["data>/tmp/out"])


def test_8_input_redirect_is_rejected():
    with pytest.raises(ValueError):
        validate_command("backup", ["data</etc/passwd"])


def test_9_path_traversal_is_rejected():
    with pytest.raises(ValueError):
        validate_command("backup", ["../../etc/passwd"])


def test_10_unknown_command_is_rejected():
    with pytest.raises(ValueError):
        validate_command("shell", ["data"])


def test_11_empty_command_is_rejected():
    with pytest.raises(ValueError):
        validate_command("", ["data"])


def test_12_non_string_command_is_rejected():
    with pytest.raises(TypeError):
        validate_command(123, ["data"])


def test_13_non_list_args_are_rejected():
    with pytest.raises(TypeError):
        validate_command("backup", "data")


def test_14_argument_with_space_is_rejected():
    with pytest.raises(ValueError):
        validate_command("backup", ["two words"])


def test_15_argument_with_quote_is_rejected():
    with pytest.raises(ValueError):
        validate_command("backup", ["data'quote"])
