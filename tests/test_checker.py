import io
import json
import os
import sys
from pathlib import Path

import pytest

from bashlex_perms.checker import RULES, inspect_shell_source, main
from bashlex_perms.config import Rule

REJECTED_COMMANDS = (
    "grep foo file",
    "grep foo file | sort",
    "cat file | grep foo",
    "FOO=bar grep foo file",
    "sudo grep foo file",
    "env LC_ALL=C grep foo file",
    "command grep foo file",
    "$(grep foo file)",
    'echo "$(grep foo file)"',
    "if grep -q foo file; then echo yes; fi",
    'for x in foo; do grep "$x" file; done',
    "/usr/bin/grep foo file",
)

ALLOWED_COMMANDS = (
    "echo grep",
    'echo "grep foo"',
    "printf '%s\\n' 'use grep instead'",
    "rg 'grep'",
    "cat README.md  # contains the word grep",
)

RECURSIVE_REJECTED_COMMANDS = (
    "xargs grep foo",
    "xargs -0 grep foo",
    "xargs -P 4 grep foo",
    "xargs --max-procs=4 /usr/bin/grep foo",
    "find . -print0 | xargs -0 grep foo",
    "sh -c 'grep foo file'",
    "bash -c 'find . -type f'",
    "bash -eux -c 'grep foo file'",
    "xargs -0 sh -c 'grep \"$@\"' sh",
    "xargs -P 8 bash -c 'find \"$1\" -type f' _",
    "sh -c 'printf \"%s\\n\" foo | xargs grep'",
    "xargs sh -c 'bash -c \"grep foo file\"'",
)


def violations_for(source):
    violations = set()
    inspect_shell_source(source, violations)
    return {rule.command for rule in violations}


def pre_tool_use_input(command):
    return {
        "session_id": "test-session",
        "transcript_path": "/tmp/transcript.jsonl",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": "/tmp",
        "tool_input": {"command": command},
    }


@pytest.mark.parametrize("source", REJECTED_COMMANDS)
def test_rejects_forbidden_executables(source):
    assert "grep" in violations_for(source)


@pytest.mark.parametrize("source", ALLOWED_COMMANDS)
def test_allows_forbidden_names_that_are_not_executables(source):
    assert violations_for(source) == set()


@pytest.mark.parametrize("source", RECURSIVE_REJECTED_COMMANDS)
def test_rejects_nested_forbidden_executables(source):
    assert violations_for(source)


@pytest.mark.parametrize(
    "source",
    (
        'cmd=grep; "$cmd" foo file',
        'xargs "$COMMAND"',
        'sh -c "$SOME_STRING"',
    ),
)
def test_allows_dynamic_commands_that_cannot_be_resolved(source):
    assert violations_for(source) == set()


def test_main_allows_safe_hook_input(monkeypatch, capsys):
    hook_input = pre_tool_use_input("rg foo file")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(hook_input)))

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    ("command", "replacement", "reason"),
    (
        ("grep", "ugrep", "Prefer ugrep for search"),
        (
            "egrep",
            "ugrep",
            "Prefer ugrep for extended regular expression search",
        ),
        ("fgrep", "ugrep", "Prefer ugrep for fixed-string search"),
        ("find", "fd", "Prefer fd for filesystem search"),
    ),
)
def test_main_returns_configured_reason(
    command, replacement, reason, monkeypatch, capsys
):
    hook_input = pre_tool_use_input(command)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(hook_input)))

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2
    assert capsys.readouterr().err == (
        f"Shell command rejected: `{command}` is forbidden; "
        f"use `{replacement}` instead: {reason}\n"
    )


def test_main_rejects_hook_input_with_sorted_unique_message(monkeypatch, capsys):
    hook_input = pre_tool_use_input("grep foo file; find .; grep bar other")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(hook_input)))

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2
    assert capsys.readouterr().err == (
        "Shell command rejected: `find` is forbidden; use `fd` instead: "
        "Prefer fd for filesystem search; `grep` is forbidden; use `ugrep` instead: "
        "Prefer ugrep for search\n"
    )


@pytest.mark.parametrize(
    "source",
    (
        "find . -exec grep foo {} \\;",
        "find . -type f -execdir grep foo {} +",
        "find . -ok /usr/bin/grep foo {} \\;",
        "fd -x grep foo",
        "fd --exec-batch grep foo ; echo",
        "fdfind -e py -x sudo grep foo {}",
        "find . -exec sh -c 'grep foo \"$1\"' _ {} \\;",
    ),
)
def test_rejects_commands_run_by_find_and_fd(source):
    assert "grep" in violations_for(source)


def test_find_exec_does_not_flag_terminated_arguments():
    assert violations_for("fd -x echo {} ; ls") == set()
    assert violations_for("find . -exec echo {} \\; -name grep") == {"find"}


@pytest.fixture
def arg_rules():
    saved = list(RULES)
    RULES[:] = [
        Rule("git", args=("push", "--force")),
        Rule("rm", args=("-r", "-f"), decision="ask"),
    ]
    yield
    RULES[:] = saved


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("git push --force origin", {"git"}),
        ("git push --force=yes", {"git"}),
        ("git push origin", set()),
        ("git --force status", set()),
        ("rm -rf x", {"rm"}),
        ("rm -r -f x", {"rm"}),
        ("rm -r x", set()),
        ("find . -exec rm -fr {} +", {"rm"}),
    ),
)
def test_argument_rules(arg_rules, source, expected):
    assert violations_for(source) == expected


def run_main(command, monkeypatch, capsys, config):
    cfg = Path(os.environ["XDG_CONFIG_HOME"]) / "bashlex-perms" / "config.toml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(config)
    monkeypatch.setattr(
        sys, "stdin", io.StringIO(json.dumps(pre_tool_use_input(command)))
    )
    with pytest.raises(SystemExit) as exc_info:
        main()
    return exc_info.value.code, capsys.readouterr()


CONFIG = """
[[rule]]
commands = ["rm"]
args = ["-rf"]
decision = "ask"

[[rule]]
command = "git"
args = ["push", "--force"]
use = "git push --force-with-lease"
"""


def test_main_ask_decision(monkeypatch, capsys):
    code, out = run_main("rm -rf x", monkeypatch, capsys, CONFIG)
    assert code == 0
    decision = json.loads(out.out)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "ask"
    assert "`rm -rf` needs confirmation" in decision["permissionDecisionReason"]


def test_main_deny_wins_over_ask(monkeypatch, capsys):
    code, out = run_main("rm -rf x; git push --force", monkeypatch, capsys, CONFIG)
    assert code == 2
    assert (
        "`git push --force` is forbidden; use `git push --force-with-lease`" in out.err
    )
    assert "rm" not in out.err


def test_main_disable_default(monkeypatch, capsys):
    code, _ = run_main("find .", monkeypatch, capsys, CONFIG)
    assert code == 0
