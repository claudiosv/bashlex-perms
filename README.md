# bashlex-perms

A Claude Code `PreToolUse` hook that statically rejects `grep`, `egrep`,
`fgrep`, and `find` shell commands in favor of `rg` and `fd`. It recursively
inspects literal commands delegated through `sh -c`, other common shells, and
`xargs`.

Run it with uv:

```bash
printf '%s\n' '{"tool_input":{"command":"grep foo file"}}' | uv run bashlex-perms
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
