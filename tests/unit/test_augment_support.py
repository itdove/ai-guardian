"""Tests for Augment Code hook support (Issue #638)."""

import os
from unittest import mock


from ai_guardian.response_format import detect_ide_type, detect_hook_event, IDEType
from ai_guardian.constants import HookEvent
from ai_guardian.hook_processing import extract_tool_result, _AUGMENT_TOOL_MAP
from ai_guardian.tool_policy import ToolPolicyChecker


class TestAugmentIDEDetection:
    """Test IDE detection for Augment Code."""

    def test_detect_ide_type_augment_env_var(self):
        """AI_GUARDIAN_IDE_TYPE=augment maps to CLAUDE_CODE."""
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "augment"}):
            result = detect_ide_type({})
            assert result == IDEType.CLAUDE_CODE

    def test_detect_ide_type_augment_auto_detection(self):
        """Auto-detect Augment from is_mcp_tool + tool_name fields."""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "launch-process",
            "tool_input": {"command": "ls"},
            "is_mcp_tool": False,
        }
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AI_GUARDIAN_IDE_TYPE", None)
            result = detect_ide_type(hook_data)
            assert result == IDEType.CLAUDE_CODE

    def test_detect_ide_type_augment_mcp_tool(self):
        """Auto-detect Augment with MCP tool."""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp:server__tool",
            "tool_input": {},
            "is_mcp_tool": True,
        }
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AI_GUARDIAN_IDE_TYPE", None)
            result = detect_ide_type(hook_data)
            assert result == IDEType.CLAUDE_CODE


class TestAugmentHookEventDetection:
    """Test hook event detection for Augment Code."""

    def test_detect_pretooluse(self):
        """Augment PreToolUse event detected correctly."""
        hook_data = {"hook_event_name": "PreToolUse", "tool_name": "launch-process"}
        assert detect_hook_event(hook_data) == HookEvent.PRE_TOOL_USE

    def test_detect_posttooluse(self):
        """Augment PostToolUse event detected correctly."""
        hook_data = {"hook_event_name": "PostToolUse", "tool_name": "launch-process"}
        assert detect_hook_event(hook_data) == HookEvent.POST_TOOL_USE


class TestAugmentToolNameMapping:
    """Test Augment Code tool name mapping."""

    def test_augment_tool_map_contents(self):
        """Verify the mapping dict contains all expected Augment tool names."""
        assert _AUGMENT_TOOL_MAP["launch-process"] == "Bash"
        assert _AUGMENT_TOOL_MAP["str-replace-editor"] == "Edit"
        assert _AUGMENT_TOOL_MAP["save-file"] == "Write"
        assert _AUGMENT_TOOL_MAP["view"] == "Read"
        assert _AUGMENT_TOOL_MAP["remove-files"] == "Delete"

    def test_extract_tool_result_augment_launch_process(self):
        """launch-process maps to Bash in PostToolUse extraction."""
        hook_data = {
            "tool_name": "launch-process",
            "tool_response": {"output": "hello world"},
        }
        output, tool_name = extract_tool_result(hook_data)
        assert tool_name == "Bash"
        assert output == "hello world"

    def test_extract_tool_result_augment_save_file(self):
        """save-file maps to Write and is skipped (state-modify tool)."""
        hook_data = {
            "tool_name": "save-file",
            "tool_response": {"output": "file saved"},
        }
        output, tool_name = extract_tool_result(hook_data)
        assert tool_name == "Write"
        assert output is None

    def test_extract_tool_result_augment_view(self):
        """view maps to Read."""
        hook_data = {
            "tool_name": "view",
            "tool_response": {"content": "file contents here"},
        }
        output, tool_name = extract_tool_result(hook_data)
        assert tool_name == "Read"

    def test_tool_policy_augment_tool_mapping(self):
        """ToolPolicyChecker._extract_tool_info maps Augment tool names."""
        checker = ToolPolicyChecker.__new__(ToolPolicyChecker)
        hook_data = {
            "tool_name": "launch-process",
            "tool_input": {"command": "ls -la"},
        }
        tool_name, tool_input = checker._extract_tool_info(hook_data)
        assert tool_name == "Bash"
        assert tool_input["command"] == "ls -la"

    def test_tool_policy_augment_str_replace_editor(self):
        """str-replace-editor maps to Edit in policy checker."""
        checker = ToolPolicyChecker.__new__(ToolPolicyChecker)
        hook_data = {
            "tool_name": "str-replace-editor",
            "tool_input": {"file_path": "/tmp/test.py"},
        }
        tool_name, tool_input = checker._extract_tool_info(hook_data)
        assert tool_name == "Edit"

    def test_tool_policy_augment_mcp_prefix(self):
        """mcp: prefix converted to mcp__ format."""
        checker = ToolPolicyChecker.__new__(ToolPolicyChecker)
        hook_data = {
            "tool_name": "mcp:server__tool",
            "tool_input": {},
        }
        tool_name, tool_input = checker._extract_tool_info(hook_data)
        assert tool_name == "mcp__server__tool"

    def test_tool_policy_regular_tool_unchanged(self):
        """Regular tool names not in Augment map pass through unchanged."""
        checker = ToolPolicyChecker.__new__(ToolPolicyChecker)
        hook_data = {
            "tool_name": "Bash",
            "tool_input": {"command": "echo test"},
        }
        tool_name, tool_input = checker._extract_tool_info(hook_data)
        assert tool_name == "Bash"


class TestAugmentMCPConfig:
    """Test MCP configuration for Augment Code."""

    def test_augment_in_mcp_ide_configs(self):
        from ai_guardian.setup import _MCP_IDE_CONFIGS

        assert "augment" in _MCP_IDE_CONFIGS
        aug_mcp = _MCP_IDE_CONFIGS["augment"]
        assert aug_mcp["config_file"] == "~/.augment/settings.json"
        assert aug_mcp["config_key"] == "mcpServers"
