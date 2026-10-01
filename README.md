# bashlex-perms

A Claude Code `PreToolUse` hook that statically rejects `grep`, `egrep`,
`fgrep`, and `find` shell commands in favor of `rg` and `fd`. It recursively
inspects literal commands delegated through `sh -c`, other common shells, and
`xargs`. Built on the [cchooks](https://github.com/GowayLee/cchooks) SDK for
parsing and responding to Claude Code hook payloads.

Run it with uv:

```bash
printf '%s\n' '{
  "session_id": "s",
  "transcript_path": "/tmp/t.jsonl",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "cwd": "/tmp",
  "tool_input": {"command": "grep foo file"}
}' | uv run bashlex-perms
```

Allowed commands exit with status 0. Rejected commands print a reason to
standard error and exit with status 2.

Dynamic executable positions and dynamic shell source cannot be resolved
statically and are allowed:

```bash
cmd=grep
"$cmd" foo file
sh -c "$SOME_STRING"
```

## Configuration

`bashlex-perms-cli install` writes the default rules to
`~/.config/bashlex-perms/config.toml` (`$XDG_CONFIG_HOME` is honored) if it
doesn't exist yet. That file is then the only source of rules; without it the
packaged defaults ([`default_config.toml`](src/bashlex_perms/default_config.toml))
apply.

```toml
[[rule]]
commands = ["rm", "rmdir"]         # or: command = "rm"
args = ["-rf"]                     # all must be present; -rf matches -r and -f
decision = "ask"                   # "deny" (default) or "ask"
use = "trash"                      # optional replacement hint
reason = "Deletes recursively"     # optional
```

Commands run through `sudo`/`env`/`xargs`/shells and `find -exec` / `fd -x`
are checked too. If any matching rule is `deny`, the command is blocked;
otherwise matching `ask` rules prompt for confirmation.

## Installing the hook

Register or remove the `PreToolUse` hook in Claude Code settings with the
bundled CLI:

```bash
uv run bashlex-perms-cli install            # writes ~/.claude/settings.json
uv run bashlex-perms-cli install --scope project  # writes ./.claude/settings.json
uv run bashlex-perms-cli uninstall
```

Run the checks with:

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
```
