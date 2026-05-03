#!/usr/bin/env python3
"""
Tests for the Hook Simulator TUI panel.

Tests the hook data building, result parsing, and TUI integration
without running the full Textual app.
"""

import json
import os
import tempfile
from io import StringIO
from pathlib import Path
from unittest import mock
from unittest.mock import patch

import pytest

from ai_guardian.tui.hook_simulator import (
    HookSimulatorContent,
    build_hook_data,
    parse_simulation_result,
)
from ai_guardian.tui.app import NAV_GROUPS, HELP_DOCS


class TestHookSimulatorImport:
    """Verify the panel integrates with the TUI app."""

    def test_hook_simulator_content_can_be_imported(self):
        assert HookSimulatorContent is not None

    def test_hook_simulator_in_nav_groups(self):
        nav_dict = {name: [pid for _, pid in items] for name, items in NAV_GROUPS}
        assert "panel-hook-simulator" in nav_dict["Tools"]

    def test_hook_simulator_has_help_doc(self):
        assert "panel-hook-simulator" in HELP_DOCS
        assert len(HELP_DOCS["panel-hook-simulator"]) > 0

    def test_tools_category_help_mentions_hook_simulator(self):
        assert "Hook Simulator" in HELP_DOCS["Tools"]


class TestBuildHookData:
    """Test the build_hook_data() helper function."""

    def test_userpromptsubmit(self):
        result = build_hook_data("UserPromptSubmit", content="Hello world")
        assert result["hook_event_name"] == "UserPromptSubmit"
        assert result["prompt"] == "Hello world"
        assert "tool_use" not in result
        assert "tool_name" not in result

    def test_pretooluse_read(self):
        result = build_hook_data(
            "PreToolUse", tool_name="Read", file_path="/tmp/test.py", content=""
        )
        assert result["hook_event_name"] == "PreToolUse"
        assert result["tool_use"]["name"] == "Read"
        assert result["tool_use"]["parameters"]["file_path"] == "/tmp/test.py"

    def test_pretooluse_bash(self):
        result = build_hook_data(
            "PreToolUse", tool_name="Bash", content="ls -la"
        )
        assert result["hook_event_name"] == "PreToolUse"
        assert result["tool_use"]["name"] == "Bash"
        assert result["tool_use"]["parameters"]["command"] == "ls -la"

    def test_posttooluse(self):
        result = build_hook_data(
            "PostToolUse", tool_name="Bash", content="command output here"
        )
        assert result["hook_event_name"] == "PostToolUse"
        assert result["tool_name"] == "Bash"
        assert result["tool_response"]["output"] == "command output here"

    def test_pretooluse_defaults_tool_name(self):
        result = build_hook_data("PreToolUse", content="test")
        assert result["tool_use"]["name"] == "Read"

    def test_posttooluse_defaults_tool_name(self):
        result = build_hook_data("PostToolUse", content="test")
        assert result["tool_name"] == "Bash"

    def test_userpromptsubmit_empty_content(self):
        result = build_hook_data("UserPromptSubmit", content="")
        assert result["prompt"] == ""


class TestParseSimulationResult:
    """Test the parse_simulation_result() helper function."""

    def test_allowed_empty_response(self):
        result = {"output": json.dumps({}), "exit_code": 0}
        parsed = parse_simulation_result(result)
        assert parsed["decision"] == "ALLOWED"
        assert parsed["reason"] is None
        assert parsed["redacted_output"] is None

    def test_blocked_by_decision_field(self):
        response = {"decision": "block", "reason": "Secret detected"}
        result = {"output": json.dumps(response), "exit_code": 0}
        parsed = parse_simulation_result(result)
        assert parsed["decision"] == "BLOCKED"
        assert parsed["reason"] == "Secret detected"

    def test_blocked_by_permission_decision(self):
        response = {
            "hookSpecificOutput": {
                "permissionDecision": "deny",
                "hookEventName": "PreToolUse",
            },
            "systemMessage": "Tool denied",
        }
        result = {"output": json.dumps(response), "exit_code": 0}
        parsed = parse_simulation_result(result)
        assert parsed["decision"] == "BLOCKED"
        assert parsed["reason"] == "Tool denied"

    def test_allowed_with_warning(self):
        response = {"systemMessage": "Warning: potential issue detected"}
        result = {"output": json.dumps(response), "exit_code": 0}
        parsed = parse_simulation_result(result)
        assert parsed["decision"] == "ALLOWED WITH WARNING"
        assert "Warning" in parsed["reason"]

    def test_allowed_with_redacted_output(self):
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": "REDACTED content",
            }
        }
        result = {"output": json.dumps(response), "exit_code": 0}
        parsed = parse_simulation_result(result)
        assert parsed["decision"] == "ALLOWED WITH WARNING"
        assert parsed["redacted_output"] == "REDACTED content"

    def test_none_output_with_exit_code_2(self):
        result = {"output": None, "exit_code": 2}
        parsed = parse_simulation_result(result)
        assert parsed["decision"] == "BLOCKED"

    def test_none_output_with_exit_code_0(self):
        result = {"output": None, "exit_code": 0}
        parsed = parse_simulation_result(result)
        assert parsed["decision"] == "ALLOWED"

    def test_raw_json_is_pretty_printed(self):
        response = {"decision": "block", "reason": "test"}
        result = {"output": json.dumps(response), "exit_code": 0}
        parsed = parse_simulation_result(result)
        assert "\n" in parsed["raw_json"]

    def test_cursor_blocked_response(self):
        response = {"continue": False, "user_message": "Blocked by Cursor"}
        result = {"output": json.dumps(response), "exit_code": 0}
        parsed = parse_simulation_result(result)
        assert parsed["decision"] == "BLOCKED"
        assert parsed["reason"] == "Blocked by Cursor"

    def test_cursor_allowed_response(self):
        response = {"continue": True}
        result = {"output": json.dumps(response), "exit_code": 0}
        parsed = parse_simulation_result(result)
        assert parsed["decision"] == "ALLOWED"

    def test_copilot_blocked_response(self):
        response = {
            "permissionDecision": "deny",
            "permissionDecisionReason": "Secret found",
        }
        result = {"output": json.dumps(response), "exit_code": 0}
        parsed = parse_simulation_result(result)
        assert parsed["decision"] == "BLOCKED"
        assert parsed["reason"] == "Secret found"

    def test_invalid_json_output(self):
        result = {"output": "not-json{{{", "exit_code": 0}
        parsed = parse_simulation_result(result)
        assert parsed["decision"] == "ALLOWED"
        assert parsed["reason"] == "not-json{{{"


class TestSimulationIsolation:
    """Verify that simulations don't write to the real violations log."""

    def test_state_dir_isolation(self):
        real_state_dir = tempfile.mkdtemp()
        violations_path = Path(real_state_dir) / "violations.jsonl"

        hook_data = build_hook_data("UserPromptSubmit", content="clean text")

        with tempfile.TemporaryDirectory() as tmp_state:
            env_overrides = {
                "AI_GUARDIAN_STATE_DIR": tmp_state,
                "AI_GUARDIAN_IDE_TYPE": "claude",
                "AI_GUARDIAN_CONFIG_DIR": real_state_dir,
            }
            with mock.patch.dict(os.environ, env_overrides):
                with mock.patch("sys.stdin", StringIO(json.dumps(hook_data))):
                    import ai_guardian

                    try:
                        ai_guardian.process_hook_input()
                    except Exception:
                        pass
                    finally:
                        import logging

                        logging.disable(logging.NOTSET)

        assert not violations_path.exists(), (
            "Simulation should not write to real state directory"
        )

        import shutil

        shutil.rmtree(real_state_dir, ignore_errors=True)
