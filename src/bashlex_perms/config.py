"""Load rules from ~/.config/bashlex-perms/config.toml (honors XDG_CONFIG_HOME)."""

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Rule:
    command: str
    use: str = ""
    reason: str = ""
    args: tuple[str, ...] = ()
    decision: str = "deny"  # "deny" blocks, "ask" prompts the user

    def describe(self) -> str:
        call = " ".join((self.command, *self.args))
        verb = "is forbidden" if self.decision == "deny" else "needs confirmation"
        use = f"; use `{self.use}` instead" if self.use else ""
        reason = f": {self.reason}" if self.reason else ""
        return f"`{call}` {verb}{use}{reason}"


@dataclass(frozen=True)
class GuardConfig:
    enabled: bool = True
    protected: tuple[str, ...] = (".git", ".claude")
    allowed: tuple[str, ...] = ("/tmp",)  # extra roots besides the project dir
    unverifiable: str = "ask"  # targets that cannot be validated: allow, ask or deny


UNVERIFIABLE_MODES = ("allow", "ask", "deny")
DEFAULT_CONFIG = Path(__file__).with_name("default_config.toml")

RULE_KEYS = {"command", "commands", "use", "reason", "args", "decision"}


def config_path() -> Path:
    # ponytail: not platformdirs, it returns ~/Library/Application Support on macOS.
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "bashlex-perms" / "config.toml"


def _parse_rule(entry: dict, path: Path) -> list[Rule]:
    def bad(msg):
        return ValueError(f"{path}: [[rule]] {msg}: {entry}")

    if unknown := entry.keys() - RULE_KEYS:
        raise bad(f"unknown keys {sorted(unknown)}")
    if ("command" in entry) == ("commands" in entry):
        raise bad("needs exactly one of 'command' or 'commands'")
    commands = entry.get("commands", [entry.get("command")])
    args = entry.get("args", [])
    decision = entry.get("decision", "deny")
    if not (commands and all(isinstance(c, str) and c for c in commands)):
        raise bad("command(s) must be non-empty strings")
    if not (isinstance(args, list) and all(isinstance(a, str) for a in args)):
        raise bad("'args' must be a list of strings")
    if decision not in {"deny", "ask"}:
        raise bad("'decision' must be 'deny' or 'ask'")
    return [
        Rule(c, entry.get("use", ""), entry.get("reason", ""), tuple(args), decision)
        for c in commands
    ]


def _read(path: Path | None) -> tuple[dict, Path]:
    path = path or config_path()
    if not path.exists():
        path = DEFAULT_CONFIG
    with path.open("rb") as f:
        return tomllib.load(f), path


def load_rules(path: Path | None = None) -> list[Rule]:
    """Rules from the config file, or the packaged defaults if it doesn't exist."""
    data, path = _read(path)
    return [rule for entry in data.get("rule", []) for rule in _parse_rule(entry, path)]


def load_guard(path: Path | None = None) -> GuardConfig:
    """The [deletion_guard] table, or defaults (enabled) if absent."""
    data, path = _read(path)
    table = data.get("deletion_guard", {})
    if unknown := table.keys() - {"enabled", "protected", "allowed", "unverifiable"}:
        raise ValueError(f"{path}: [deletion_guard] unknown keys {sorted(unknown)}")
    enabled = table.get("enabled", True)
    protected = table.get("protected", list(GuardConfig.protected))
    if not isinstance(enabled, bool):
        raise ValueError(f"{path}: [deletion_guard] 'enabled' must be a boolean")
    if not (
        isinstance(protected, list) and all(isinstance(p, str) and p for p in protected)
    ):
        raise ValueError(
            f"{path}: [deletion_guard] 'protected' must be a list of names"
        )
    allowed = table.get("allowed", list(GuardConfig.allowed))
    if not (
        isinstance(allowed, list)
        and all(
            isinstance(a, str) and os.path.isabs(os.path.expanduser(a)) for a in allowed
        )
    ):
        raise ValueError(
            f"{path}: [deletion_guard] 'allowed' must be a list of absolute paths"
        )
    unverifiable = table.get("unverifiable", GuardConfig.unverifiable)
    if unverifiable not in UNVERIFIABLE_MODES:
        raise ValueError(
            f"{path}: [deletion_guard] 'unverifiable' must be one of "
            f"{', '.join(map(repr, UNVERIFIABLE_MODES))}"
        )
    return GuardConfig(enabled, tuple(protected), tuple(allowed), unverifiable)
