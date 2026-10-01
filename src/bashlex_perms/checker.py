import os
import sys
from typing import NoReturn

import bashlex
from cchooks import PreToolUseContext, safe_create_context

FORBIDDEN = {
    "grep": {
        "replacement": "ugrep",
        "reason": "Prefer ugrep for search",
    },
    "egrep": {
        "replacement": "ugrep",
        "reason": "Prefer ugrep for extended regular expression search",
    },
    "fgrep": {
        "replacement": "ugrep",
        "reason": "Prefer ugrep for fixed-string search",
    },
    "find": {
        "replacement": "fd",
        "reason": "Prefer fd for filesystem search",
    },
}

SHELLS = {
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
}

# Options where the next argv item is an option argument.
SUDO_OPTIONS_WITH_ARG = {
    "-C",
    "--close-from",
    "-D",
    "--chdir",
    "-g",
    "--group",
    "-h",
    "--host",
    "-p",
    "--prompt",
    "-R",
    "--chroot",
    "-r",
    "--role",
    "-t",
    "--type",
    "-T",
    "--command-timeout",
    "-u",
    "--user",
}

ENV_OPTIONS_WITH_ARG = {
    "-C",
    "--chdir",
    "-S",
    "--split-string",
    "-u",
    "--unset",
}

# Common xargs options consuming the following argv element.
XARGS_OPTIONS_WITH_ARG = {
    "-a",
    "--arg-file",
    "-d",
    "--delimiter",
    "-E",
    "-e",
    "--eof",
    "-I",
    "--replace",
    "-L",
    "--max-lines",
    "-n",
    "--max-args",
    "-P",
    "--max-procs",
    "-s",
    "--max-chars",
}


def basename(command: str) -> str:
    return os.path.basename(command)


def literal_word(node):
    """
    Return the literal value of a shell word, or None if it contains
    expansions/substitutions whose runtime value we cannot determine.
    """
    if node.kind != "word":
        return None

    # bashlex represents ordinary quoted strings as words just fine, but
    # expansions/substitutions appear in .parts.
    for part in getattr(node, "parts", ()):
        if part.kind in {
            "parameter",
            "commandsubstitution",
            "processsubstitution",
        }:
            return None

    return node.word


def command_words(node):
    return [literal_word(part) for part in node.parts if part.kind == "word"]


def skip_options(words, i, options_with_arg):
    """
    Skip command-line options, including known options that consume the
    following argv element.

    Returns the index of the first non-option argument.
    """
    while i < len(words):
        word = words[i]

        if word is None:
            return i

        if word == "--":
            return i + 1

        if not word.startswith("-") or word == "-":
            return i

        # --foo=value consumes itself.
        if word.startswith("--") and "=" in word:
            i += 1
            continue

        if word in options_with_arg:
            i += 2
            continue

        i += 1

    return i


def unwrap_command(words):
    """
    Strip common wrappers and return (executable, argv), where argv starts
    with the executable itself.

    For example, ``sudo env LC_ALL=C /usr/bin/grep foo`` becomes
    ``("grep", ["/usr/bin/grep", "foo"])``.
    """
    i = 0

    while i < len(words):
        word = words[i]

        if word is None:
            return None, []

        # Leading variable assignments, such as LC_ALL=C grep foo.
        if "=" in word and not word.startswith("="):
            name = word.split("=", 1)[0]
            if name and all(c.isalnum() or c == "_" for c in name):
                i += 1
                continue

        command = basename(word)

        if command == "sudo":
            i += 1
            i = skip_options(words, i, SUDO_OPTIONS_WITH_ARG)
            continue

        if command == "env":
            i += 1

            while i < len(words):
                word = words[i]

                if word is None:
                    return None, []

                if word == "--":
                    i += 1
                    break

                if word.startswith("-"):
                    old_i = i
                    i = skip_options(words, i, ENV_OPTIONS_WITH_ARG)
                    if i != old_i:
                        continue

                if "=" in word and not word.startswith("="):
                    name = word.split("=", 1)[0]
                    if name and all(c.isalnum() or c == "_" for c in name):
                        i += 1
                        continue

                break

            continue

        if command in {"command", "exec", "nohup"}:
            i += 1

            # command has options such as -p / -v / -V.
            while i < len(words) and words[i] is not None and words[i].startswith("-"):
                i += 1

            continue

        return command, words[i:]

    return None, []


def walk(node):
    yield node

    for attr in ("parts", "list"):
        children = getattr(node, attr, None)
        if children:
            for child in children:
                yield from walk(child)

    for attr in ("command", "output", "input"):
        child = getattr(node, attr, None)
        if hasattr(child, "kind"):
            yield from walk(child)


def inspect_shell_source(source, violations, *, depth=0):
    """
    Parse shell source and inspect every executable command.

    Recurses into literal shell ``-c`` strings. A depth limit protects against
    pathologically nested input.
    """
    if depth > 8:
        return

    try:
        trees = bashlex.parse(source)
    except bashlex.errors.ParsingError:
        return

    for tree in trees:
        for node in walk(tree):
            if node.kind != "command":
                continue

            words = command_words(node)
            executable, argv = unwrap_command(words)

            if executable is None:
                continue

            if executable in FORBIDDEN:
                violations.add(executable)

            inspect_special_command(executable, argv, violations, depth=depth)


def inspect_special_command(executable, argv, violations, *, depth):
    if executable in SHELLS:
        inspect_shell_c(argv, violations, depth=depth + 1)
    elif executable == "xargs":
        inspect_xargs(argv, violations, depth=depth + 1)


def inspect_shell_c(argv, violations, *, depth):
    """Inspect literal source passed to a shell's ``-c`` option."""
    i = 1

    while i < len(argv):
        arg = argv[i]

        if arg is None:
            return

        if arg == "--":
            i += 1
            continue

        if arg == "-c":
            if i + 1 < len(argv):
                source = argv[i + 1]
                if source is not None:
                    inspect_shell_source(source, violations, depth=depth)
            return

        # Combined short options can include c, e.g. bash -ec '...'.
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            if i + 1 < len(argv):
                source = argv[i + 1]
                if source is not None:
                    inspect_shell_source(source, violations, depth=depth)
            return

        i += 1


def inspect_xargs(argv, violations, *, depth):
    """Inspect the command that xargs will execute, if one is provided."""
    i = skip_options(argv, 1, XARGS_OPTIONS_WITH_ARG)

    if i >= len(argv):
        return

    executable, unwrapped_argv = unwrap_command(argv[i:])

    if executable is None:
        return

    if executable in FORBIDDEN:
        violations.add(executable)

    inspect_special_command(executable, unwrapped_argv, violations, depth=depth)


def main() -> NoReturn:
    context = safe_create_context(stdin=sys.stdin)

    if not isinstance(context, PreToolUseContext):
        # This hook is only ever registered for PreToolUse; anything else
        # is a misconfiguration we shouldn't block on.
        sys.exit(0)

    source = context.tool_input.get("command")
    violations = set()

    if isinstance(source, str):
        inspect_shell_source(source, violations)

    if not violations:
        context.output.exit_success()

    messages = []
    for command in sorted(violations):
        policy = FORBIDDEN[command]
        messages.append(
            f"`{command}` is forbidden; use `{policy['replacement']}` instead: "
            f"{policy['reason']}"
        )
    context.output.exit_block("Shell command rejected: " + "; ".join(messages))
