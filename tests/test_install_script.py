"""Tests for install.sh one-line installer."""

import os
import subprocess
import pathlib

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "install.sh"


class TestInstallScriptSyntax:
    """Validate the install script is well-formed bash."""

    def test_script_exists(self):
        assert SCRIPT.exists(), f"{SCRIPT} not found"

    def test_script_is_executable(self):
        assert os.access(SCRIPT, os.X_OK), f"{SCRIPT} is not executable"

    def test_bash_syntax_check(self):
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Syntax error: {result.stderr}"


class TestInstallScriptHelp:
    """Verify --help output contains expected information."""

    @pytest.fixture()
    def help_output(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        return result.stdout

    def test_help_mentions_venv(self, help_output):
        assert "--venv" in help_output

    def test_help_mentions_ide(self, help_output):
        assert "--ide" in help_output

    def test_help_mentions_profile(self, help_output):
        assert "--profile" in help_output

    def test_help_mentions_version(self, help_output):
        assert "--version" in help_output

    def test_help_lists_ide_choices(self, help_output):
        for ide in ("claude", "cursor", "copilot", "codex", "windsurf"):
            assert ide in help_output

    def test_help_shows_usage(self, help_output):
        assert "curl" in help_output

    def test_help_mentions_whl(self, help_output):
        assert ".whl" in help_output

    def test_help_mentions_passthrough(self, help_output):
        assert "passed through" in help_output

    def test_help_mentions_no_mcp(self, help_output):
        assert "--no-mcp" in help_output
