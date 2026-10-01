import pytest

from bashlex_perms.config import DEFAULT_CONFIG, Rule, config_path, load_rules


def write(tmp_path, text):
    p = tmp_path / "config.toml"
    p.write_text(text)
    return p


def test_defaults_when_missing(tmp_path):
    assert load_rules(tmp_path / "nope.toml") == load_rules(DEFAULT_CONFIG)
    assert Rule("grep", "ugrep", "Prefer ugrep for search") in load_rules(
        DEFAULT_CONFIG
    )


def test_user_config_replaces_defaults(tmp_path):
    p = write(
        tmp_path,
        """
[[rule]]
command = "cat"
use = "bat"

[[rule]]
commands = ["rm", "rmdir"]
args = ["-rf"]
decision = "ask"
reason = "careful"
""",
    )
    rules = load_rules(p)
    assert all(r.command not in {"find", "grep"} for r in rules)
    assert Rule("cat", use="bat") in rules
    assert Rule("rm", "", "careful", ("-rf",), "ask") in rules
    assert Rule("rmdir", "", "careful", ("-rf",), "ask") in rules


@pytest.mark.parametrize(
    "entry",
    (
        'use = "x"',
        'command = "a"\ncommands = ["b"]',
        'command = "a"\ndecision = "allow"',
        'command = "a"\nargs = "x"',
        'command = "a"\ntypo = 1',
        "commands = []",
    ),
)
def test_invalid_rule(tmp_path, entry):
    with pytest.raises(ValueError):
        load_rules(write(tmp_path, f"[[rule]]\n{entry}\n"))


def test_config_path_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert config_path() == tmp_path / "bashlex-perms" / "config.toml"
