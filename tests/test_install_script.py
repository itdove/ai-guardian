"""Tests for install.sh and install.ps1 installers."""

import os
import shutil
import subprocess
import pathlib
import sys

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "install.sh"
PS1_SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "install.ps1"

_skip_no_bash = pytest.mark.skipif(
    sys.platform == "win32",
    reason="bash install script tests not applicable on Windows",
)


@_skip_no_bash
class TestInstallScriptSyntax:
    """Validate the install script is well-formed bash."""

    def test_script_exists(self):
        assert SCRIPT.exists(), f"{SCRIPT} not found"

    @pytest.mark.skipif(sys.platform == "win32", reason="executable bit not meaningful on Windows")
    def test_script_is_executable(self):
        assert os.access(SCRIPT, os.X_OK), f"{SCRIPT} is not executable"

    def test_bash_syntax_check(self):
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Syntax error: {result.stderr}"


@_skip_no_bash
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

    def test_help_mentions_pip(self, help_output):
        assert "--pip" in help_output

    def test_help_mentions_uv(self, help_output):
        assert "--uv" in help_output

    def test_help_mentions_whl(self, help_output):
        assert ".whl" in help_output

    def test_help_mentions_passthrough(self, help_output):
        assert "passed through" in help_output

    def test_help_mentions_no_mcp(self, help_output):
        assert "--no-mcp" in help_output

    def test_help_mentions_no_setup(self, help_output):
        assert "--no-setup" in help_output


class TestInstallScriptContent:
    """Verify the script body contains expected post-install content."""

    @pytest.fixture()
    def script_content(self):
        return SCRIPT.read_text()

    def test_doctor_verification_step(self, script_content):
        assert "ai_guardian" in script_content
        assert "doctor" in script_content

    def test_next_steps_daemon_start(self, script_content):
        assert "ai-guardian daemon start" in script_content

    def test_next_steps_tray_start(self, script_content):
        assert "ai-guardian tray start" in script_content

    def test_has_detect_installed_agents(self, script_content):
        assert "detect_installed_agents" in script_content

    def test_has_no_setup_flag(self, script_content):
        assert "NO_SETUP" in script_content


@_skip_no_bash
class TestInstallScriptModes:
    """Verify install mode flags work correctly."""

    def test_mutually_exclusive_pip_uv(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--pip", "--uv"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "mutually exclusive" in result.stderr

    def test_mutually_exclusive_pip_venv(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--pip", "--venv"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "mutually exclusive" in result.stderr

    def test_mutually_exclusive_venv_uv(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--venv", "--uv"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "mutually exclusive" in result.stderr

    def test_script_has_auto_detect(self):
        content = SCRIPT.read_text()
        assert "Auto-detect" in content or "auto-detect" in content

    def test_script_has_uv_tool_install(self):
        content = SCRIPT.read_text()
        assert "uv tool install" in content

    def test_script_has_has_uv_helper(self):
        content = SCRIPT.read_text()
        assert "has_uv" in content

    def test_no_setup_flag_accepted(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--no-setup", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0


@_skip_no_bash
class TestInstallScriptAgentDetection:
    """Verify agent detection covers all expected agents."""

    @pytest.fixture()
    def script_content(self):
        return SCRIPT.read_text()

    @pytest.mark.parametrize("agent_path", [
        "CLAUDE_CONFIG_DIR",
        ".cursor/hooks.json",
        ".github/hooks/hooks.json",
        ".codex/hooks.json",
        ".codeium/windsurf/hooks.json",
        ".gemini/settings.json",
        ".augment/settings.json",
        ".config/opencode/plugins/ai-guardian.ts",
        ".aider-desk/extensions/ai-guardian/index.ts",
        ".openclaw/plugins/ai-guardian/index.ts",
    ])
    def test_detection_checks_agent_path(self, script_content, agent_path):
        assert agent_path in script_content, f"Detection missing path: {agent_path}"


class TestInstallPs1:
    """Tests for install.ps1 PowerShell installer."""

    def test_ps1_script_exists(self):
        assert PS1_SCRIPT.exists(), f"{PS1_SCRIPT} not found"

    def test_ps1_contains_doctor(self):
        content = PS1_SCRIPT.read_text()
        assert "ai_guardian doctor" in content

    def test_ps1_contains_daemon_start(self):
        content = PS1_SCRIPT.read_text()
        assert "ai-guardian daemon start" in content

    def test_ps1_contains_tray_start(self):
        content = PS1_SCRIPT.read_text()
        assert "ai-guardian tray start" in content

    def test_ps1_contains_appdata(self):
        content = PS1_SCRIPT.read_text()
        assert "APPDATA" in content

    def test_ps1_contains_venv_option(self):
        content = PS1_SCRIPT.read_text()
        assert "Venv" in content

    def test_ps1_contains_ide_option(self):
        content = PS1_SCRIPT.read_text()
        assert "IDE" in content

    def test_ps1_contains_no_setup(self):
        content = PS1_SCRIPT.read_text()
        assert "NoSetup" in content

    def test_ps1_contains_detect_function(self):
        content = PS1_SCRIPT.read_text()
        assert "Detect-InstalledAgents" in content

    @pytest.mark.skipif(
        shutil.which("pwsh") is None,
        reason="pwsh not available",
    )
    def test_ps1_syntax_check(self):
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-Command",
             f"$null = [System.Management.Automation.Language.Parser]::ParseFile('{PS1_SCRIPT}', [ref]$null, [ref]$errors); $errors.Count"],
            capture_output=True,
            text=True,
        )
        assert result.stdout.strip() == "0", f"PowerShell syntax errors: {result.stdout}"
