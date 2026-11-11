"""Conservative deletion guard for rm, find -delete and git clean.

Accident prevention, not a security boundary. Only literal paths strictly
below the project root are accepted. Never evaluates shell input.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from bashlex_perms.config import GuardConfig, Rule

BAD_CHARS = set("$`~*?[]{}\\\n\r\x00")
RM_FLAGS = set("fRrivd")
CLEAN_FLAGS = set("fdxXnq")
FIND_FLAGS = {"-depth", "-xdev"}
FIND_PREDICATES = {
    "-name",
    "-iname",
    "-type",
    "-mindepth",
    "-maxdepth",
    "-mtime",
    "-mmin",
}
DIR_CHANGERS = {"cd", "pushd", "popd"}


class Denied(Exception):
    pass


@dataclass
class DeletionGuard:
    config: GuardConfig = field(default_factory=GuardConfig)
    root: Path | None = None
    cwd: Path | None = None
    moved: bool = False  # a cd/pushd/popd ran earlier, so relative paths are unreliable

    def reset(self, cwd: str | None = None) -> None:
        """Start a new command. Root: CLAUDE_PROJECT_DIR, else the working dir."""
        self.cwd = Path(cwd or os.getcwd()).resolve()
        self.root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or self.cwd).resolve()
        self.moved = False

    def check(self, executable: str, argv: list) -> Rule | None:
        """Return a deny Rule if this command is a deletion we don't accept."""
        if not self.config.enabled:
            return None
        if executable in DIR_CHANGERS:
            self.moved = True
            return None
        args = argv[1:]
        call: tuple[str, ...] = ()
        try:
            if executable == "rm":
                self._rm(args)
            elif executable == "find" and "-delete" in args:
                self._find(args)
                call = ("-delete",)
            elif executable == "git" and "clean" in args:
                if args[0] != "clean":
                    raise Denied("put `clean` directly after `git`")
                self._clean(args[1:])
                call = ("clean",)
            else:
                return None
        except Denied as error:
            return Rule(executable, reason=f"deletion guard: {error}", args=call)
        return None

    def _target(self, value: str | None) -> Path:
        if self.root is None or self.cwd is None:
            self.reset()
        root, cwd = self.root, self.cwd
        assert root is not None and cwd is not None
        if value is None:
            raise Denied("target is not a literal path")
        if "{" in value:
            raise Denied(
                "find/fd placeholders cannot be validated; pass explicit paths"
            )
        if not value or BAD_CHARS & set(value):
            raise Denied(
                "use explicit literal paths; no expansions, globs, or empty paths"
            )
        path = Path(value)
        protected = set(self.config.protected)
        if protected & set(path.parts):
            raise Denied("Git metadata and Claude configuration are protected")
        if self.moved and not path.is_absolute():
            raise Denied("relative path after cd/pushd/popd; use absolute paths")
        resolved = (path if path.is_absolute() else cwd / path).resolve()
        bases = [root, *(Path(a).expanduser().resolve() for a in self.config.allowed)]
        base = next(
            (b for b in bases if resolved != b and resolved.is_relative_to(b)), None
        )
        if base is None:
            raise Denied(
                f"target must be strictly below the project dir or an allowed path: "
                f"{value!r}"
            )
        if resolved == Path.home().resolve():
            raise Denied("home directory is protected")
        if protected & set(resolved.relative_to(base).parts):
            raise Denied("target resolves into protected metadata")
        if resolved.is_dir():
            for directory, directories, files in os.walk(resolved, followlinks=False):
                if protected & {*directories, *files}:
                    raise Denied(f"subtree contains protected metadata: {directory!r}")
        return resolved

    def _rm(self, args: list) -> None:
        targets = []
        options = True
        for arg in args:
            if options and arg == "--":
                options = False
            elif options and arg is not None and arg.startswith("-"):
                if len(arg) < 2 or not set(arg[1:]) <= RM_FLAGS:
                    raise Denied(f"unsupported rm option: {arg!r}")
            else:
                targets.append(arg)
        if not targets:
            raise Denied("rm needs explicit targets")
        for target in targets:
            self._target(target)

    def _find(self, args: list) -> None:
        if args and args[0] == "-P":
            args = args[1:]
        if not args or args[0] is None or args[0].startswith("-"):
            raise Denied("find deletion requires an explicit starting directory")
        if not self._target(args[0]).is_dir():
            raise Denied("find starting path must be an existing directory")
        expression = args[1:]
        if not expression or expression[-1] != "-delete":
            raise Denied("supported syntax: find [-P] PATH [predicates] -delete")
        i = 0
        while i < len(expression) - 1:
            token = expression[i]
            if token in FIND_FLAGS:
                i += 1
                continue
            if token not in FIND_PREDICATES:
                raise Denied(f"unsupported find predicate: {token!r}")
            if i + 1 >= len(expression) - 1:
                raise Denied("missing find predicate argument")
            value = expression[i + 1]
            if value is None:
                raise Denied("find predicate argument is not literal")
            if token == "-type" and value not in {"f", "d", "l"}:
                raise Denied("supported find types: f, d, l")
            if token in {"-mindepth", "-maxdepth"} and not re.fullmatch(r"\d+", value):
                raise Denied("find depth must be a nonnegative integer")
            if token in {"-mtime", "-mmin"} and not re.fullmatch(r"[+-]?\d+", value):
                raise Denied("unsupported find time argument")
            i += 2

    def _clean(self, args: list) -> None:
        if "--" not in args:
            raise Denied("use git clean FLAGS -- explicit/subdirectory")
        sep = args.index("--")
        for flag in args[:sep]:
            if (
                flag is None
                or not flag.startswith("-")
                or len(flag) < 2
                or not set(flag[1:]) <= CLEAN_FLAGS
            ):
                raise Denied(f"unsupported git clean option: {flag!r}")
        paths = args[sep + 1 :]
        if not paths:
            raise Denied("git clean needs explicit targets")
        for path in paths:
            if path is not None and ":" in path:
                raise Denied("Git pathspec magic is unsupported")
            self._target(path)
