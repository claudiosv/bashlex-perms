import json

from typer.testing import CliRunner

from bashlex_perms.cli import app

runner = CliRunner()


def test_install_creates_settings(tmp_path):
    settings_path = tmp_path / "settings.json"

    result = runner.invoke(
        app,
        ["install", "--command", "bashlex-perms", "--path", str(settings_path)],
    )

    assert result.exit_code == 0
    settings = json.loads(settings_path.read_text())
    entries = settings["hooks"]["PreToolUse"]
    assert entries == [
        {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "bashlex-perms"}],
        }
    ]


def test_install_is_idempotent(tmp_path):
    settings_path = tmp_path / "settings.json"

    runner.invoke(
        app, ["install", "--command", "bashlex-perms", "--path", str(settings_path)]
    )
    runner.invoke(
        app,
        [
            "install",
            "--command",
            "/opt/bin/bashlex-perms",
            "--path",
            str(settings_path),
        ],
    )

    settings = json.loads(settings_path.read_text())
    entries = settings["hooks"]["PreToolUse"]
    assert len(entries) == 1
    assert entries[0]["hooks"][0]["command"] == "/opt/bin/bashlex-perms"


def test_install_preserves_existing_settings(tmp_path):
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "otherTopLevel": True,
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "*",
                            "hooks": [{"type": "command", "command": "other-hook"}],
                        }
                    ],
                    "PostToolUse": [{"matcher": "*", "hooks": []}],
                },
            }
        )
    )

    runner.invoke(
        app, ["install", "--command", "bashlex-perms", "--path", str(settings_path)]
    )

    settings = json.loads(settings_path.read_text())
    assert settings["otherTopLevel"] is True
    assert settings["hooks"]["PostToolUse"] == [{"matcher": "*", "hooks": []}]
    commands = {
        hook["command"]
        for entry in settings["hooks"]["PreToolUse"]
        for hook in entry["hooks"]
    }
    assert commands == {"other-hook", "bashlex-perms"}


def test_uninstall_removes_entry_and_empty_keys(tmp_path):
    settings_path = tmp_path / "settings.json"
    runner.invoke(
        app, ["install", "--command", "bashlex-perms", "--path", str(settings_path)]
    )

    result = runner.invoke(app, ["uninstall", "--path", str(settings_path)])

    assert result.exit_code == 0
    settings = json.loads(settings_path.read_text())
    assert "hooks" not in settings


def test_uninstall_keeps_unrelated_hooks(tmp_path):
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "*",
                            "hooks": [{"type": "command", "command": "other-hook"}],
                        },
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "bashlex-perms"}],
                        },
                    ]
                }
            }
        )
    )

    runner.invoke(app, ["uninstall", "--path", str(settings_path)])

    settings = json.loads(settings_path.read_text())
    assert len(settings["hooks"]["PreToolUse"]) == 1
    assert settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "other-hook"


def test_uninstall_no_settings_file_is_noop(tmp_path):
    settings_path = tmp_path / "does-not-exist.json"

    result = runner.invoke(app, ["uninstall", "--path", str(settings_path)])

    assert result.exit_code == 0
    assert not settings_path.exists()


def test_uninstall_no_matching_entry_is_noop(tmp_path):
    settings_path = tmp_path / "settings.json"
    original = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [{"type": "command", "command": "other-hook"}],
                }
            ]
        }
    }
    settings_path.write_text(json.dumps(original))

    result = runner.invoke(app, ["uninstall", "--path", str(settings_path)])

    assert result.exit_code == 0
    assert json.loads(settings_path.read_text()) == original
