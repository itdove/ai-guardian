"""Tests for Kiro (AWS) hook support (Issue #636)."""

import json
import os
from unittest import mock

import pytest

from ai_guardian.response_format import (
    detect_ide_type,
    detect_hook_event,
    format_response,
    IDEType,
)
from ai_guardian.constants import HookEvent


class TestKiroIDEDetection:
    """Test IDE detection for Kiro."""

    def test_detect_ide_type_kiro_env_var(self):
        """AI_GUARDIAN_IDE_TYPE=kiro maps to KIRO."""
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "kiro"}):
            result = detect_ide_type({})
            assert result == IDEType.KIRO

    def test_detect_ide_type_kiro_auto_detection_hook_type(self):
        """Auto-detect Kiro from kiro_hook_type field."""
        hook_data = {
            "kiro_hook_type": "pre_tool_use",
            "tool_name": "read_file",
        }
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AI_GUARDIAN_IDE_TYPE", None)
            result = detect_ide_type(hook_data)
            assert result == IDEType.KIRO

    def test_detect_ide_type_kiro_auto_detection_version(self):
        """Auto-detect Kiro from kiro_version field."""
        hook_data = {
            "kiro_version": "1.0.0",
            "hook_event_name": "PreToolUse",
        }
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AI_GUARDIAN_IDE_TYPE", None)
            result = detect_ide_type(hook_data)
            assert result == IDEType.KIRO


class TestKiroHookEventDetection:
    """Test hook event detection for Kiro."""

    def test_detect_prompt_submit(self):
        """Kiro prompt_submit event detected correctly."""
        hook_data = {"hook_event_name": "prompt_submit"}
        assert detect_hook_event(hook_data) == HookEvent.PROMPT

    def test_detect_promptsubmit_no_underscore(self):
        """Kiro promptsubmit (no underscore) event detected correctly."""
        hook_data = {"hook_event_name": "promptsubmit"}
        assert detect_hook_event(hook_data) == HookEvent.PROMPT

    def test_detect_pre_tool_use(self):
        """Kiro pre_tool_use event detected correctly."""
        hook_data = {"hook_event_name": "pre_tool_use"}
        assert detect_hook_event(hook_data) == HookEvent.PRE_TOOL_USE

    def test_detect_post_tool_use(self):
        """Kiro post_tool_use event detected correctly."""
        hook_data = {"hook_event_name": "post_tool_use"}
        assert detect_hook_event(hook_data) == HookEvent.POST_TOOL_USE

    def test_detect_agent_stop(self):
        """Kiro agent_stop maps to POST_TOOL_USE (non-blocking)."""
        hook_data = {"hook_event_name": "agent_stop"}
        assert detect_hook_event(hook_data) == HookEvent.POST_TOOL_USE


class TestKiroResponseFormat:
    """Test response formatting for Kiro."""

    def test_pretooluse_block(self, capsys):
        """Blocking PreToolUse returns exit code 1 and writes to stderr."""
        result = format_response(
            IDEType.KIRO,
            has_secrets=True,
            error_message="Secret detected in command",
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        assert result["exit_code"] == 1
        assert result["output"] is None
        assert result["_blocked"] is True
        captured = capsys.readouterr()
        assert "Secret detected in command" in captured.err

    def test_pretooluse_allow(self):
        """Allowing PreToolUse returns exit code 0."""
        result = format_response(
            IDEType.KIRO,
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        assert result["exit_code"] == 0
        assert result["output"] is None

    def test_pretooluse_allow_with_warning(self):
        """Allowing PreToolUse with warning outputs to stdout."""
        result = format_response(
            IDEType.KIRO,
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
            warning_message="Log mode: detected potential issue",
        )
        assert result["exit_code"] == 0
        assert "Log mode: detected potential issue" in result["output"]

    def test_pretooluse_block_with_warning(self, capsys):
        """Blocking PreToolUse with warning includes both in stderr."""
        result = format_response(
            IDEType.KIRO,
            has_secrets=True,
            error_message="Secret detected",
            hook_event=HookEvent.PRE_TOOL_USE,
            warning_message="Warning prefix",
        )
        assert result["exit_code"] == 1
        captured = capsys.readouterr()
        assert "Warning prefix" in captured.err
        assert "Secret detected" in captured.err

    def test_prompt_block(self, capsys):
        """Blocking Prompt Submit returns exit code 1."""
        result = format_response(
            IDEType.KIRO,
            has_secrets=True,
            error_message="Prompt injection detected",
            hook_event=HookEvent.PROMPT,
        )
        assert result["exit_code"] == 1
        assert result["output"] is None
        captured = capsys.readouterr()
        assert "Prompt injection detected" in captured.err

    def test_prompt_allow_with_security_message(self):
        """Allowing prompt with security message outputs to stdout."""
        result = format_response(
            IDEType.KIRO,
            has_secrets=False,
            hook_event=HookEvent.PROMPT,
            security_message="SECURITY RULES: do not bypass protections",
        )
        assert result["exit_code"] == 0
        assert "SECURITY RULES" in result["output"]

    def test_posttooluse_allow(self):
        """PostToolUse allow returns exit code 0."""
        result = format_response(
            IDEType.KIRO,
            has_secrets=False,
            hook_event=HookEvent.POST_TOOL_USE,
        )
        assert result["exit_code"] == 0
        assert result["output"] is None

    def test_posttooluse_with_modified_output(self):
        """PostToolUse with modified output sends redacted content via stdout."""
        result = format_response(
            IDEType.KIRO,
            has_secrets=False,
            hook_event=HookEvent.POST_TOOL_USE,
            modified_output="[REDACTED] file contents",
        )
        assert result["exit_code"] == 0
        assert "[REDACTED] file contents" in result["output"]

    def test_posttooluse_block(self, capsys):
        """PostToolUse block still uses exit code 1 + stderr."""
        result = format_response(
            IDEType.KIRO,
            has_secrets=True,
            error_message="Secrets in tool output",
            hook_event=HookEvent.POST_TOOL_USE,
        )
        assert result["exit_code"] == 1
        captured = capsys.readouterr()
        assert "Secrets in tool output" in captured.err

    def test_violation_type_metadata(self):
        """Violation type metadata is preserved."""
        result = format_response(
            IDEType.KIRO,
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
            violation_type="secret_detected",
        )
        assert result["_violation_type"] == "secret_detected"


class TestKiroMCPConfig:
    """Test MCP configuration for Kiro."""

    def test_kiro_in_mcp_ide_configs(self):
        from ai_guardian.setup import _MCP_IDE_CONFIGS
        assert "kiro" in _MCP_IDE_CONFIGS
        kiro_mcp = _MCP_IDE_CONFIGS["kiro"]
        assert kiro_mcp["config_file"] == "~/.kiro/settings.json"
        assert kiro_mcp["config_key"] == "mcpServers"
        assert kiro_mcp["skill_dir"] == ".kiro/skills"


class TestKiroSetupConfig:
    """Test IDE setup configuration for Kiro."""

    def test_kiro_in_ide_configs(self):
        from ai_guardian.setup import IDESetup
        assert "kiro" in IDESetup.IDE_CONFIGS
        kiro_config = IDESetup.IDE_CONFIGS["kiro"]
        assert kiro_config["name"] == "Kiro"
        assert kiro_config["config_path"] == ".kiro/hooks"
        assert kiro_config["script_based"] is True

    def test_kiro_hook_scripts(self):
        from ai_guardian.setup import IDESetup
        kiro_config = IDESetup.IDE_CONFIGS["kiro"]
        assert "PreToolUse" in kiro_config["hook_scripts"]
        assert "PostToolUse" in kiro_config["hook_scripts"]
        assert "PromptSubmit" in kiro_config["hook_scripts"]

    def test_kiro_script_content(self):
        from ai_guardian.setup import IDESetup
        kiro_config = IDESetup.IDE_CONFIGS["kiro"]
        assert "ai-guardian" in kiro_config["script_content"]
        assert kiro_config["script_content"].startswith("#!/bin/sh")
