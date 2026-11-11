#!/usr/bin/env python3
"""Conservative Claude Code Bash deletion guard (Python 3.14+).

Accident prevention, not a security boundary. Does not inspect scripts,
interpreters, aliases, functions, other tools, or filesystem races.
Never evaluates shell input. Exit 0 defers to normal Claude permissions.
"""

import json
import os
from pathlib import Path
import re
import shlex
import sys


def deny(reason: str) -> None:
    """Block the pending tool call."""
    print(f"Deletion guard: {reason}", file=sys.stderr)
    raise SystemExit(2)


def check_target(value: str, root: Path, cwd: Path) -> Path:
    """Validate one literal target, conservatively resolving symlinks."""
    if not value or any(c in value for c in "$`~*?[]{}\\\n\r\x00"):
        deny("use explicit literal paths; no expansions, globs, or empty paths")
    path = Path(value)
    if ".git" in path.parts or ".claude" in path.parts:
        deny("Git metadata and Claude configuration are protected")
    resolved = (path if path.is_absolute() else cwd / path).resolve()
    if resolved == root or not resolved.is_relative_to(root):
        deny(f"target must be strictly below project root: {value!r}")
    if resolved == Path.home().resolve():
        deny("home directory is protected")
    if any(p in {".git", ".claude"} for p in resolved.relative_to(root).parts):
        deny("target resolves into protected metadata")
    # Also protect nested repositories and Claude configuration in subtrees.
    if resolved.is_dir():
        for directory, directories, files in os.walk(resolved, followlinks=False):
            if {".git", ".claude"}.intersection(directories + files):
                deny(f"subtree contains protected metadata: {directory!r}")
    return resolved


def check_rm(args: list[str], root: Path, cwd: Path) -> None:
    """Accept only ordinary rm flags and literal operands."""
    targets: list[str] = []
    options = True
    for arg in args:
        if options and arg == "--":
            options = False
        elif options and arg.startswith("-"):
            if len(arg) < 2 or not set(arg[1:]) <= set("fRrivd"):
                deny(f"unsupported rm option: {arg!r}")
        else:
            targets.append(arg)
    if not targets:
        deny("rm needs explicit targets")
    for target in targets:
        check_target(target, root, cwd)


def check_find(args: list[str], root: Path, cwd: Path) -> None:
    """Accept find [-P] PATH [simple AND predicates] -delete."""
    if args and args[0] == "-P":
        args = args[1:]
    if not args or args[0].startswith("-"):
        deny("find deletion requires an explicit starting directory")
    target = check_target(args[0], root, cwd)
    if not target.is_dir():
        deny("find starting path must be an existing directory")
    expression = args[1:]
    if not expression or expression[-1] != "-delete":
        deny("supported syntax: find [-P] PATH [predicates] -delete")
    i = 0
    while i < len(expression) - 1:
        token = expression[i]
        if token in {"-depth", "-xdev"}:
            i += 1
            continue
        if token not in {
            "-name",
            "-iname",
            "-type",
            "-mindepth",
            "-maxdepth",
            "-mtime",
            "-mmin",
        }:
            deny(f"unsupported find predicate: {token!r}")
        if i + 1 >= len(expression) - 1:
            deny("missing find predicate argument")
        value = expression[i + 1]
        if token == "-type" and value not in {"f", "d", "l"}:
            deny("supported find types: f, d, l")
        if token in {"-mindepth", "-maxdepth"} and not re.fullmatch(r"\d+", value):
            deny("find depth must be a nonnegative integer")
        if token in {"-mtime", "-mmin"} and not re.fullmatch(r"[+-]?\d+", value):
            deny("unsupported find time argument")
        i += 2


def check_clean(args: list[str], root: Path, cwd: Path) -> None:
    """Require git clean FLAGS -- literal paths; prohibit Git pathspec magic."""
    if "--" not in args:
        deny("use git clean FLAGS -- explicit/subdirectory")
    separator = args.index("--")
    for flag in args[:separator]:
        if (
            not flag.startswith("-")
            or len(flag) < 2
            or not set(flag[1:]) <= set("fdxXnq")
        ):
            deny(f"unsupported git clean option: {flag!r}")
    paths = args[separator + 1 :]
    if not paths:
        deny("git clean needs explicit targets")
    for path in paths:
        if ":" in path:
            deny("Git pathspec magic is unsupported")
        check_target(path, root, cwd)


def main() -> None:
    """Inspect the JSON hook payload from stdin."""
    payload = json.load(sys.stdin)
    if payload["tool_name"] != "Bash":
        return
    command = payload["tool_input"]["command"]
    # shlex is a tokenizer, not a Bash parser. Only the narrow forms below
    # are accepted for recognized deletion commands.
    tokens = shlex.split(command, comments=False, posix=True)
    names = [Path(token).name for token in tokens]
    suspicious = (
        "rm" in names
        or "-delete" in tokens
        or "-exec" in tokens
        or "-execdir" in tokens
        or ("git" in names and "clean" in tokens)
        or re.search(r"\b(?:rm|git\s+clean)\b|\-delete\b", command)
    )
    if not suspicious:
        return
    if not tokens or any(c in command for c in "$`~;&|<>(){}\\\n\r"):
        deny(
            "split deletion into a single command with literal paths; no shell expansions or operators"
        )
    quote = ""
    for character in command:
        if quote:
            if character == quote:
                quote = ""
        elif character in {"'", '"'}:
            quote = character
        elif character in "*?[]":
            deny("unquoted glob patterns are unsupported")
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    if not project or not Path(project).is_absolute():
        deny("CLAUDE_PROJECT_DIR must be an absolute path")
    root = Path(project).resolve(strict=True)
    cwd = Path(payload["cwd"]).resolve(strict=True)
    if not root.is_dir() or not cwd.is_dir() or not cwd.is_relative_to(root):
        deny("working directory must be within the project")
    program = tokens[0]
    name = Path(program).name
    if program not in {name, f"/bin/{name}", f"/usr/bin/{name}"}:
        deny("unsupported executable path or wrapper")
    if name == "rm":
        check_rm(tokens[1:], root, cwd)
    elif name == "find":
        check_find(tokens[1:], root, cwd)
    elif name == "git" and len(tokens) > 1 and tokens[1] == "clean":
        check_clean(tokens[2:], root, cwd)
    else:
        deny(
            "unsupported deletion syntax or wrapper; use direct rm, find, or git clean"
        )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        deny(f"validation failed ({type(error).__name__}): {error}")
