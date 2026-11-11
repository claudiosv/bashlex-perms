import io
import json
import os
import sys
from pathlib import Path

import pytest

from bashlex_perms.checker import GUARD, RULES, inspect_shell_source, main
from bashlex_perms.config import GuardConfig, Rule

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


@pytest.mark.parametrize("source", ["a=$((1+2))", "case x in x) echo;; esac"])
def test_unsupported_syntax_is_ignored(source):
    assert violations_for(source) == set()


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "a.txt").write_text("x")
    (root / "nested" / ".git").mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(root))
    monkeypatch.chdir(root)
    monkeypatch.setattr(GUARD, "config", GuardConfig())
    return root


def guard_violations(source):
    violations = set()
    inspect_shell_source(source, violations)
    return {r for r in violations if "deletion guard" in r.reason}


@pytest.mark.parametrize(
    "source",
    (
        "rm sub/a.txt",
        "rm -rf sub",
        "rm -rf -- sub/a.txt",
        "sudo rm -f sub/a.txt",
        "find sub -type f -name x -delete",
        "git clean -fd -- sub",
        "echo rm",
        "fd -e txt sub",
        "ls sub; rm sub/a.txt",
    ),
)
def test_guard_allows_literal_paths_below_root(project, source):
    assert guard_violations(source) == set()


HARD_DENIED = (
    "rm -rf .",
    "rm -rf ..",
    "rm -rf /",
    "rm -rf /*",
    "rm -rf .*",
    "rm -rf sub/.*",
    "rm -rf .git",
    "rm -rf .git/*",
    "rm -rf .claude/settings.json",
    "rm -rf nested",  # contains a nested .git
    "rm -rf ../other",
    "rm -rf ../*",
    "rm -rf sub/../..",
    "rm -x sub",
    "find . -delete",
    "find sub -type f -user bob -delete",
    "git clean -fdx",
    "git clean -fd -- :/",
    "git -C sub clean -fd -- sub",
    "bash -c 'rm -rf /'",
    "env -i rm -rf ..",
    "rm -rf $HOME/x ..",
    "rm -rf ~/x",  # expanded, outside the project
)

# Targets that cannot be verified statically: ask by default, per `unverifiable`.
UNVERIFIABLE = (
    "rm -rf $X",
    "xargs rm",
    "find sub -exec rm {} +",
    "cd sub && rm a.txt",
    "fd -e tmp -x rm {}",
    "fd -e tmp --exec rm {}",
    "fd -e tmp -X rm {}",
    "fd -e tmp --exec-batch rm -f {}",
    "fd . sub -x sudo rm -rf {/}",
)


@pytest.mark.parametrize("source", HARD_DENIED)
def test_guard_denies_unsafe_deletions(project, source):
    rules = guard_violations(source)
    assert rules
    assert {r.decision for r in rules} == {"deny"}


@pytest.mark.parametrize("source", UNVERIFIABLE)
def test_guard_asks_when_unverifiable(project, source):
    rules = guard_violations(source)
    assert rules
    assert {r.decision for r in rules} == {"ask"}


@pytest.mark.parametrize("source", UNVERIFIABLE)
def test_guard_unverifiable_deny(project, monkeypatch, source):
    monkeypatch.setattr(GUARD, "config", GuardConfig(unverifiable="deny"))
    rules = guard_violations(source)
    assert rules
    assert {r.decision for r in rules} == {"deny"}


@pytest.mark.parametrize("source", UNVERIFIABLE)
def test_guard_unverifiable_allow(project, monkeypatch, source):
    monkeypatch.setattr(GUARD, "config", GuardConfig(unverifiable="allow"))
    assert guard_violations(source) == set()


@pytest.mark.parametrize("source", ("rm -rf sub/*", "rm *.pyc", "rm -f sub/a.*"))
def test_guard_checks_glob_directory(project, source):
    assert guard_violations(source) == set()


def test_guard_deny_wins_over_unverifiable(project):
    assert {r.decision for r in guard_violations("rm $X ..")} == {"deny"}


def test_guard_symlink_escape(project, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (project / "link").symlink_to(outside)
    assert {r.decision for r in guard_violations("rm -rf link/x")} == {"deny"}


def test_guard_denies_via_main(project, monkeypatch, capsys):
    code, out = run_main("rm -rf ..", monkeypatch, capsys, "")
    assert code == 2
    assert "deletion guard" in out.err


def test_guard_can_be_disabled(project, monkeypatch, capsys):
    code, _ = run_main(
        "rm -rf ..", monkeypatch, capsys, "[deletion_guard]\nenabled = false\n"
    )
    assert code == 0


def test_guard_allowed_paths(project, tmp_path, monkeypatch):
    target = tmp_path / "scratch"
    target.mkdir()
    # Outside the project and not in the default /tmp allowance.
    assert guard_violations(f"rm -rf {target}")
    monkeypatch.setattr(GUARD, "config", GuardConfig(allowed=(str(tmp_path),)))
    assert guard_violations(f"rm -rf {target}") == set()
    assert guard_violations(f"rm -rf {tmp_path}")  # the allowed root itself
    assert guard_violations(f"rm -rf {target}/.git")
