"""Install/uninstall the bashlex-perms Claude Code hook."""

import json
import shlex
import shutil
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()

MATCHER = "Bash"


def _default_command() -> str:
    return shutil.which("bashlex-perms") or "bashlex-perms"


def _settings_path(scope: str) -> Path:
    if scope == "project":
        return Path.cwd() / ".claude" / "settings.json"
    return Path.home() / ".claude" / "settings.json"


def _is_bashlex_perms_command(command: str) -> bool:
    try:
        head = shlex.split(command)[0]
    except ValueError, IndexError:
        head = command
    return Path(head).name == "bashlex-perms"


def _entry_is_ours(entry: dict) -> bool:
    return any(
        _is_bashlex_perms_command(hook.get("command", ""))
        for hook in entry.get("hooks", [])
        if isinstance(hook, dict)
    )


def _load_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _write_settings(path: Path, settings: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2) + "\n")


ScopeOption = Annotated[
    str,
    typer.Option(help="Where to install the hook: 'user' or 'project'."),
]
CommandOption = Annotated[
    str | None,
    typer.Option(help="Hook command to register."),
]
PathOption = Annotated[
    Path | None,
    typer.Option(hidden=True, help="Override the settings file path."),
]


@app.command()
def install(
    scope: ScopeOption = "user",
    command: CommandOption = None,
    path: PathOption = None,
) -> None:
    """Register bashlex-perms as a PreToolUse hook for the Bash tool."""
    settings_path = path or _settings_path(scope)
    resolved_command = command or _default_command()

    settings = _load_settings(settings_path)
    hooks = settings.setdefault("hooks", {})
    pre_tool_use = hooks.setdefault("PreToolUse", [])

    new_entry = {
        "matcher": MATCHER,
        "hooks": [{"type": "command", "command": resolved_command}],
    }

    for i, entry in enumerate(pre_tool_use):
        if isinstance(entry, dict) and _entry_is_ours(entry):
            pre_tool_use[i] = new_entry
            break
    else:
        pre_tool_use.append(new_entry)

    _write_settings(settings_path, settings)
    console.print(
        f"[green]Installed[/green] bashlex-perms hook in [bold]{settings_path}[/bold] "
        f"(command: [cyan]{resolved_command}[/cyan])"
    )


@app.command()
def uninstall(
    scope: ScopeOption = "user",
    path: PathOption = None,
) -> None:
    """Remove the bashlex-perms PreToolUse hook."""
    settings_path = path or _settings_path(scope)

    if not settings_path.exists():
        console.print(f"[yellow]Nothing to do[/yellow]: {settings_path} does not exist")
        return

    settings = _load_settings(settings_path)
    hooks = settings.get("hooks", {})
    pre_tool_use = hooks.get("PreToolUse", [])

    remaining = [
        entry
        for entry in pre_tool_use
        if not (isinstance(entry, dict) and _entry_is_ours(entry))
    ]

    if len(remaining) == len(pre_tool_use):
        console.print(
            f"[yellow]Nothing to do[/yellow]: no hook found in {settings_path}"
        )
        return

    if remaining:
        hooks["PreToolUse"] = remaining
    else:
        hooks.pop("PreToolUse", None)

    if not hooks:
        settings.pop("hooks", None)

    _write_settings(settings_path, settings)
    console.print(f"[green]Uninstalled[/green] hook from [bold]{settings_path}[/bold]")


if __name__ == "__main__":
    app()
