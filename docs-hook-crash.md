# Hook crash: uncaught `NotImplementedError` from bashlex

## Symptom

Claude Code shows, for the `PreToolUse:Bash` hook (`bashlex-perms`):

```
PreToolUse:Bash hook error
Failed with non-blocking status code: Traceback (most recent call last):
```

The command still runs, but the hook gives no decision, so Claude Code falls back to its normal permission prompt.

## Cause

`src/bashlex_perms/checker.py` (around line 242) only catches `bashlex.errors.ParsingError`:

```python
try:
    trees = bashlex.parse(source)
except bashlex.errors.ParsingError:
    ...
```

bashlex raises `NotImplementedError` for some valid bash it does not support. That exception is not caught, so the process exits 1 with a traceback.

## Reproduction

Feed the hook a PreToolUse payload on stdin:

```sh
jq -n --arg c 'a=$((1+2))' '{session_id:"s",transcript_path:"/tmp/t.jsonl",hook_event_name:"PreToolUse",tool_name:"Bash",tool_input:{command:$c},cwd:"/tmp"}' | bashlex-perms; echo rc=$?
```

Confirmed failing inputs (exit code 1):

| Command | Error |
|---|---|
| `a=$((1+2))` | `NotImplementedError: arithmetic expansion` (bashlex/subst.py) |
| `case x in x) echo;; esac` | `NotImplementedError: type = {pattern}, token = {x}` (bashlex/parser.py) |

Confirmed fine (exit 0): plain commands, pipes, `$(...)`, backticks, heredocs, `[[ ]]`, `${x:-}`, `for` loops.

## Fix

Treat unsupported syntax like a parse failure: catch `NotImplementedError` alongside `ParsingError` and return "no opinion" (exit 0, no output) so Claude Code prompts as usual.

```python
except (bashlex.errors.ParsingError, NotImplementedError):
```

Check whether other `bashlex` calls (e.g. later tree walking) can also raise, and add tests in `tests/test_checker.py` for both commands above.
