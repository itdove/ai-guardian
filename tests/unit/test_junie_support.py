"""Tests for Junie (JetBrains) MCP-only support (Issue #637)."""

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from ai_guardian.setup import (
    IDESetup,
    _MCP_IDE_CONFIGS,
    _RULES_IDE_CONFIGS,
    _RULES_FILE_CONTENT,
    _handle_rules_setup,
)


class TestJunieMCPConfig:
    """Test MCP configuration for Junie."""

    def test_junie_in_mcp_ide_configs(self):
        """Junie has MCP config entry."""
        assert "junie" in _MCP_IDE_CONFIGS
        junie_mcp = _MCP_IDE_CONFIGS["junie"]
        assert junie_mcp["config_file"] == "~/.junie/mcp.json"
        assert junie_mcp["config_key"] == "mcpServers"
        assert junie_mcp["skill_dir"] == ".junie/skills"


class TestJunieSetupConfig:
    """Test IDE setup configuration for Junie."""

    def test_junie_in_ide_configs(self):
        """Junie has IDE config entry with mcp_only flag."""
        assert "junie" in IDESetup.IDE_CONFIGS
        junie_config = IDESetup.IDE_CONFIGS["junie"]
        assert junie_config["name"] == "Junie"
        assert junie_config["mcp_only"] is True

    def test_junie_no_hooks(self):
        """Junie config does not define hooks or script_based."""
        junie_config = IDESetup.IDE_CONFIGS["junie"]
        assert "hooks" not in junie_config
        assert "script_based" not in junie_config
        assert "hook_scripts" not in junie_config


class TestJunieSetupFlow:
    """Test setup flow for mcp-only IDEs."""

    def test_setup_ide_hooks_mcp_only_returns_success(self):
        """setup_ide_hooks returns success for mcp-only IDEs."""
        setup = IDESetup()
        success, message = setup.setup_ide_hooks("junie")
        assert success is True
        assert "does not support hooks" in message

    def test_setup_ide_hooks_mcp_only_suggests_flags(self):
        """setup_ide_hooks suggests --mcp and --rules for mcp-only IDEs."""
        setup = IDESetup()
        success, message = setup.setup_ide_hooks("junie")
        assert "--mcp" in message
        assert "--rules" in message

    def test_setup_ide_hooks_mcp_only_mentions_ide_name(self):
        """setup_ide_hooks message includes the IDE display name."""
        setup = IDESetup()
        success, message = setup.setup_ide_hooks("junie")
        assert "Junie" in message


class TestJunieRulesConfig:
    """Test rules/guidelines configuration for Junie."""

    def test_junie_in_rules_ide_configs(self):
        """Junie has rules config entry."""
        assert "junie" in _RULES_IDE_CONFIGS
        junie_rules = _RULES_IDE_CONFIGS["junie"]
        assert junie_rules["rules_dir"] == ".junie"
        assert junie_rules["rules_file"] == "guidelines.md"

    def test_rules_content_has_mcp_tools(self):
        """Rules file content references ai-guardian MCP tools."""
        assert "check_path" in _RULES_FILE_CONTENT
        assert "check_command" in _RULES_FILE_CONTENT
        assert "sanitize_text" in _RULES_FILE_CONTENT
        assert "get_violations" in _RULES_FILE_CONTENT

    def test_rules_content_mentions_security(self):
        """Rules file content is focused on security."""
        assert "Security" in _RULES_FILE_CONTENT or "security" in _RULES_FILE_CONTENT


class TestJunieRulesInstallation:
    """Test rules/guidelines file installation."""

    def test_install_rules_creates_file(self):
        """_handle_rules_setup creates the guidelines file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                _handle_rules_setup("junie")
                rules_path = Path(tmpdir) / ".junie" / "guidelines.md"
                assert rules_path.exists()
                content = rules_path.read_text()
                assert "AI Guardian" in content
                assert "check_path" in content
            finally:
                os.chdir(original_cwd)

    def test_install_rules_dry_run(self, capsys):
        """_handle_rules_setup in dry_run mode does not create file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                _handle_rules_setup("junie", dry_run=True)
                rules_path = Path(tmpdir) / ".junie" / "guidelines.md"
                assert not rules_path.exists()
                captured = capsys.readouterr()
                assert "Would create" in captured.out
            finally:
                os.chdir(original_cwd)

    def test_install_rules_no_overwrite(self, capsys):
        """_handle_rules_setup does not overwrite existing file without --force."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                junie_dir = Path(tmpdir) / ".junie"
                junie_dir.mkdir()
                rules_path = junie_dir / "guidelines.md"
                rules_path.write_text("existing content")
                _handle_rules_setup("junie")
                assert rules_path.read_text() == "existing content"
                captured = capsys.readouterr()
                assert "already exists" in captured.out
            finally:
                os.chdir(original_cwd)

    def test_install_rules_force_overwrite(self):
        """_handle_rules_setup overwrites existing file with --force."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                junie_dir = Path(tmpdir) / ".junie"
                junie_dir.mkdir()
                rules_path = junie_dir / "guidelines.md"
                rules_path.write_text("existing content")
                _handle_rules_setup("junie", force=True)
                content = rules_path.read_text()
                assert "AI Guardian" in content
                assert content != "existing content"
            finally:
                os.chdir(original_cwd)

    def test_install_rules_unsupported_ide(self, capsys):
        """_handle_rules_setup prints message for unsupported IDEs."""
        _handle_rules_setup("claude")
        captured = capsys.readouterr()
        assert "does not support guidelines" in captured.out


class TestJunieCLI:
    """Test CLI integration for Junie."""

    def test_junie_in_cli_choices(self):
        """'junie' is a valid --ide choice."""
        from ai_guardian.cli import main
        import argparse

        # Verify by checking IDE_CONFIGS which is used for validation
        assert "junie" in IDESetup.IDE_CONFIGS


class TestJunieConfigScanner:
    """Test that Junie guidelines file is in config scanner patterns."""

    def test_junie_guidelines_in_default_config_files(self):
        """Junie guidelines.md is scanned for config file threats."""
        from ai_guardian.config_scanner import ConfigFileScanner
        assert ".junie/guidelines.md" in ConfigFileScanner.DEFAULT_CONFIG_FILES

    def test_junie_guidelines_in_scanner_patterns(self):
        """Junie guidelines.md is in scanner CONFIG_FILE_PATTERNS."""
        from ai_guardian.scanner import CONFIG_FILE_PATTERNS
        assert ".junie/guidelines.md" in CONFIG_FILE_PATTERNS
