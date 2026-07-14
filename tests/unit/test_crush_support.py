"""Tests for Charmbracelet Crush hook adapter support (Issue #928)."""

import json
import os
from unittest import mock

import pytest

from ai_guardian.constants import HookEvent
from ai_guardian.hook_adapters import detect_adapter
from ai_guardian.hook_adapters.crush import CrushAdapter


class TestCrushDetection:
    """Test Crush adapter detection."""

    @pytest.fixture(autouse=True)
    def _clear_env(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AI_GUARDIAN_IDE_TYPE", None)
            os.environ.pop("CRUSH", None)
            os.environ.pop("AI_AGENT", None)
            yield

    def test_detect_from_crush_env_var(self):
        with mock.patch.dict(os.environ, {"CRUSH": "1"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, CrushAdapter)

    def test_detect_from_ai_agent_env_var(self):
        with mock.patch.dict(os.environ, {"AI_AGENT": "crush"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, CrushAdapter)

    def test_detect_from_event_field(self):
        adapter = detect_adapter(
            {"event": "PreToolUse", "tool_input": {"command": "ls"}}
        )
        assert isinstance(adapter, CrushAdapter)

    def test_env_var_override(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "crush"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, CrushAdapter)

    def test_ide_type_field(self):
        adapter = detect_adapter({"_ide_type": "crush"})
        assert isinstance(adapter, CrushAdapter)

    def test_name(self):
        assert CrushAdapter().name == "Crush"

    def test_can_handle_false_for_empty(self):
        assert CrushAdapter.can_handle({}) is False

    def test_can_handle_true_for_crush_env(self):
        with mock.patch.dict(os.environ, {"CRUSH": "1"}):
            assert CrushAdapter.can_handle({}) is True

    def test_can_handle_true_for_ai_agent_env(self):
        with mock.patch.dict(os.environ, {"AI_AGENT": "crush"}):
            assert CrushAdapter.can_handle({}) is True

    def test_can_handle_true_for_event_field(self):
        assert (
            CrushAdapter.can_handle({"event": "PreToolUse", "tool_input": {}}) is True
        )

    def test_can_handle_false_event_only(self):
        assert CrushAdapter.can_handle({"event": "PreToolUse"}) is False

    def test_can_handle_false_tool_input_only(self):
        assert CrushAdapter.can_handle({"tool_input": {}}) is False

    def test_can_handle_false_unknown_event_name(self):
        assert (
            CrushAdapter.can_handle({"event": "CustomEvent", "tool_input": {}}) is False
        )

    def test_can_handle_false_when_hook_event_name_present(self):
        assert (
            CrushAdapter.can_handle(
                {
                    "event": "PreToolUse",
                    "tool_input": {},
                    "hook_event_name": "PreToolUse",
                }
            )
            is False
        )

    def test_can_handle_false_non_string_event(self):
        assert CrushAdapter.can_handle({"event": 123, "tool_input": {}}) is False


class TestCrushNormalization:
    """Test Crush event normalization."""

    @pytest.fixture(autouse=True)
    def _clear_env(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            yield

    def test_pretooluse_event(self):
        data = {
            "event": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "rm -rf /"},
            "session_id": "313909e",
            "cwd": "/home/user/project",
        }
        n = CrushAdapter().normalize_input(data)
        assert n.event == HookEvent.PRE_TOOL_USE
        assert n.tool_name == "bash"
        assert n.tool_input == {"command": "rm -rf /"}
        assert n.working_dir == "/home/user/project"
        assert n.session_id == "313909e"

    def test_file_path_extraction(self):
        data = {
            "event": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/secret.py"},
        }
        n = CrushAdapter().normalize_input(data)
        assert n.file_path == "/tmp/secret.py"

    def test_event_field_bridging(self):
        data = {
            "event": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "ls"},
        }
        n = CrushAdapter().normalize_input(data)
        assert n.event == HookEvent.PRE_TOOL_USE
        assert "event" in data
        assert "hook_event_name" not in data

    def test_original_hook_data_not_mutated(self):
        data = {
            "event": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "ls"},
        }
        CrushAdapter().normalize_input(data)
        assert "hook_event_name" not in data

    def test_hook_event_name_not_overwritten(self):
        data = {
            "event": "PreToolUse",
            "hook_event_name": "PostToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "ls"},
        }
        n = CrushAdapter().normalize_input(data)
        assert n.event == HookEvent.POST_TOOL_USE


class TestCrushResponseFormatting:
    """Test Crush response formatting (inherits BaseAgentAdapter format)."""

    def test_pretooluse_block(self):
        result = CrushAdapter().format_response(
            has_secrets=True,
            error_message="Secret found in file",
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        assert result["exit_code"] == 0
        data = json.loads(result["output"])
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert result["_blocked"] is True

    def test_pretooluse_allow(self):
        result = CrushAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        assert result["exit_code"] == 0
        data = json.loads(result["output"])
        assert data == {}

    def test_posttooluse_block(self):
        result = CrushAdapter().format_response(
            has_secrets=True,
            error_message="Secret in output",
            hook_event=HookEvent.POST_TOOL_USE,
        )
        data = json.loads(result["output"])
        assert data["decision"] == "block"
        assert result["_blocked"] is True

    def test_posttooluse_redaction(self):
        result = CrushAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.POST_TOOL_USE,
            modified_output="[REDACTED]",
        )
        data = json.loads(result["output"])
        assert data["hookSpecificOutput"]["updatedToolOutput"] == "[REDACTED]"

    def test_prompt_block(self):
        result = CrushAdapter().format_response(
            has_secrets=True,
            error_message="Prompt injection detected",
            hook_event=HookEvent.PROMPT,
        )
        data = json.loads(result["output"])
        assert data["decision"] == "block"

    def test_prompt_security_message(self):
        result = CrushAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PROMPT,
            security_message="SECURITY RULES",
        )
        data = json.loads(result["output"])
        assert "SECURITY RULES" in data["systemMessage"]

    def test_violation_type_metadata(self):
        result = CrushAdapter().format_response(
            has_secrets=True,
            error_message="Secret found",
            hook_event=HookEvent.PRE_TOOL_USE,
            violation_type="secret_detected",
        )
        assert result["_violation_type"] == "secret_detected"
