"""Tests for the multi-agent hook adapter architecture (Issue #633)."""

import json
import os
from unittest import mock

import pytest

from ai_guardian.constants import HookEvent
from ai_guardian.hook_adapters import (
    ADAPTER_CLASSES,
    detect_adapter,
    get_adapter_by_ide_type,
    ClaudeCodeAdapter,
    CursorAdapter,
    CopilotAdapter,
    CodexAdapter,
    WindsurfAdapter,
    GeminiCLIAdapter,
    ClineAdapter,
    KiroAdapter,
    AugmentAdapter,
    OpenCodeAdapter,
    JunieAdapter,
)
from ai_guardian.hook_adapters.base import HookAdapter, NormalizedHookInput
from ai_guardian.response_format import IDEType


# ── NormalizedHookInput ──────────────────────────────────────────────────


class TestNormalizedHookInput:
    """Test NormalizedHookInput dataclass."""

    def test_defaults(self):
        n = NormalizedHookInput(event=HookEvent.PROMPT)
        assert n.event == HookEvent.PROMPT
        assert n.tool_name is None
        assert n.tool_input == {}
        assert n.file_path is None
        assert n.working_dir is None
        assert n.session_id is None
        assert n.tool_use_id is None
        assert n.prompt_text is None
        assert n.tool_response is None
        assert n.transcript_path is None
        assert n.raw_data == {}

    def test_full_construction(self):
        n = NormalizedHookInput(
            event=HookEvent.PRE_TOOL_USE,
            tool_name="Bash",
            tool_input={"command": "ls"},
            file_path="/tmp/test.py",
            working_dir="/home/user",
            session_id="sess-123",
            tool_use_id="tu-456",
            prompt_text="run tests",
            tool_response={"output": "ok"},
            transcript_path="/tmp/transcript.jsonl",
            raw_data={"hook_event_name": "PreToolUse"},
        )
        assert n.tool_name == "Bash"
        assert n.tool_input == {"command": "ls"}
        assert n.file_path == "/tmp/test.py"
        assert n.session_id == "sess-123"


# ── Adapter Registry ────────────────────────────────────────────────────


class TestAdapterRegistry:
    """Test detect_adapter() and get_adapter_by_ide_type()."""

    @pytest.fixture(autouse=True)
    def _clear_env(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AI_GUARDIAN_IDE_TYPE", None)
            yield

    def test_default_fallback_is_claude_code(self):
        adapter = detect_adapter({})
        assert isinstance(adapter, ClaudeCodeAdapter)

    def test_env_var_override_claude(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "claude"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, ClaudeCodeAdapter)

    def test_env_var_override_cursor(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "cursor"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, CursorAdapter)

    def test_env_var_override_copilot(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "copilot"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, CopilotAdapter)

    def test_env_var_override_github_copilot(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "github_copilot"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, CopilotAdapter)

    def test_env_var_override_codex(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "codex"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, CodexAdapter)

    def test_env_var_override_windsurf(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "windsurf"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, WindsurfAdapter)

    def test_env_var_override_gemini(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "gemini"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, GeminiCLIAdapter)

    def test_env_var_override_cline(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "cline"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, ClineAdapter)

    def test_env_var_override_zoocode(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "zoocode"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, ClineAdapter)

    def test_env_var_override_kiro(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "kiro"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, KiroAdapter)

    def test_env_var_override_aiderdesk(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "aiderdesk"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, KiroAdapter)

    def test_env_var_override_openclaw(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "openclaw"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, KiroAdapter)

    def test_env_var_override_augment(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "augment"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, AugmentAdapter)

    def test_env_var_override_opencode(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "opencode"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, OpenCodeAdapter)

    def test_env_var_override_junie(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "junie"}):
            adapter = detect_adapter({})
            assert isinstance(adapter, JunieAdapter)

    # ── _ide_type field in hook_data (--ide CLI flag) ──

    def test_ide_type_field_selects_cursor(self):
        adapter = detect_adapter({"_ide_type": "cursor"})
        assert isinstance(adapter, CursorAdapter)

    def test_ide_type_field_selects_gemini(self):
        adapter = detect_adapter({"_ide_type": "gemini"})
        assert isinstance(adapter, GeminiCLIAdapter)

    def test_ide_type_field_selects_copilot(self):
        adapter = detect_adapter({"_ide_type": "copilot"})
        assert isinstance(adapter, CopilotAdapter)

    def test_ide_type_field_selects_cline(self):
        adapter = detect_adapter({"_ide_type": "cline"})
        assert isinstance(adapter, ClineAdapter)

    def test_ide_type_field_selects_windsurf(self):
        adapter = detect_adapter({"_ide_type": "windsurf"})
        assert isinstance(adapter, WindsurfAdapter)

    def test_ide_type_field_selects_augment(self):
        adapter = detect_adapter({"_ide_type": "augment"})
        assert isinstance(adapter, AugmentAdapter)

    def test_ide_type_field_selects_kiro(self):
        adapter = detect_adapter({"_ide_type": "kiro"})
        assert isinstance(adapter, KiroAdapter)

    def test_ide_type_field_selects_codex(self):
        adapter = detect_adapter({"_ide_type": "codex"})
        assert isinstance(adapter, CodexAdapter)

    def test_ide_type_field_selects_opencode(self):
        adapter = detect_adapter({"_ide_type": "opencode"})
        assert isinstance(adapter, OpenCodeAdapter)

    def test_ide_type_field_beats_env_var(self):
        """_ide_type field takes priority over AI_GUARDIAN_IDE_TYPE env var."""
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "claude"}):
            adapter = detect_adapter({"_ide_type": "cursor"})
            assert isinstance(adapter, CursorAdapter)

    def test_ide_type_field_beats_auto_detection(self):
        """_ide_type field takes priority over auto-detection from hook data."""
        adapter = detect_adapter({
            "_ide_type": "cursor",
            "clineVersion": "1.0.0",
        })
        assert isinstance(adapter, CursorAdapter)

    def test_ide_type_field_case_insensitive(self):
        adapter = detect_adapter({"_ide_type": "Cursor"})
        assert isinstance(adapter, CursorAdapter)

    def test_ide_type_field_unknown_value_falls_through(self):
        adapter = detect_adapter({"_ide_type": "unknown_ide"})
        assert isinstance(adapter, ClaudeCodeAdapter)

    def test_get_adapter_by_ide_type(self):
        assert isinstance(get_adapter_by_ide_type(IDEType.CLAUDE_CODE), ClaudeCodeAdapter)
        assert isinstance(get_adapter_by_ide_type(IDEType.CURSOR), CursorAdapter)
        assert isinstance(get_adapter_by_ide_type(IDEType.GITHUB_COPILOT), CopilotAdapter)
        assert isinstance(get_adapter_by_ide_type(IDEType.GEMINI_CLI), GeminiCLIAdapter)
        assert isinstance(get_adapter_by_ide_type(IDEType.CLINE), ClineAdapter)
        assert isinstance(get_adapter_by_ide_type(IDEType.KIRO), KiroAdapter)
        assert isinstance(get_adapter_by_ide_type(IDEType.UNKNOWN), ClaudeCodeAdapter)

    def test_adapter_classes_list_not_empty(self):
        assert len(ADAPTER_CLASSES) >= 8

    def test_all_adapters_are_hook_adapter_subclass(self):
        for cls in ADAPTER_CLASSES:
            assert issubclass(cls, HookAdapter)


# ── Auto-detection ───────────────────────────────────────────────────────


class TestAutoDetection:
    """Test auto-detection from hook data structure."""

    @pytest.fixture(autouse=True)
    def _clear_env(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AI_GUARDIAN_IDE_TYPE", None)
            yield

    def test_detect_cline_from_clineversion(self):
        adapter = detect_adapter({"clineVersion": "1.0.0"})
        assert isinstance(adapter, ClineAdapter)

    def test_detect_gemini_from_transcript_path(self):
        adapter = detect_adapter({"transcript_path": "/tmp/t.jsonl"})
        assert isinstance(adapter, GeminiCLIAdapter)

    def test_detect_windsurf_from_agent_action_name(self):
        adapter = detect_adapter({"agent_action_name": "pre_run_command"})
        assert isinstance(adapter, WindsurfAdapter)

    def test_detect_copilot_from_toolname(self):
        adapter = detect_adapter({"toolName": "read_file"})
        assert isinstance(adapter, CopilotAdapter)

    def test_detect_copilot_from_timestamp_cwd(self):
        adapter = detect_adapter({"hook_event_name": "preToolUse", "timestamp": "2026-01-01T00:00:00Z", "cwd": "/home"})
        assert isinstance(adapter, CopilotAdapter)

    def test_detect_cursor_from_cursor_version(self):
        adapter = detect_adapter({"cursor_version": "0.50.0"})
        assert isinstance(adapter, CursorAdapter)

    def test_detect_cursor_from_hook_name(self):
        adapter = detect_adapter({"hook_name": "beforeSubmitPrompt"})
        assert isinstance(adapter, CursorAdapter)

    def test_detect_kiro_from_kiro_hook_type(self):
        adapter = detect_adapter({"kiro_hook_type": "pre_tool_use"})
        assert isinstance(adapter, KiroAdapter)

    def test_detect_kiro_from_kiro_version(self):
        adapter = detect_adapter({"kiro_version": "1.0.0"})
        assert isinstance(adapter, KiroAdapter)

    def test_detect_gemini_not_claude_with_transcript_path(self):
        """Claude Code data with transcript_path should NOT be detected as Gemini."""
        adapter = detect_adapter({
            "hook_event_name": "PreToolUse",
            "transcript_path": "/home/user/.claude/sessions/transcript.jsonl",
            "tool_name": "Bash",
        })
        assert isinstance(adapter, ClaudeCodeAdapter)

    def test_detect_opencode_from_opencode_version(self):
        adapter = detect_adapter({"opencode_version": "1.0.0"})
        assert isinstance(adapter, OpenCodeAdapter)

    def test_detect_opencode_from_hook_source(self):
        adapter = detect_adapter({"hook_source": "opencode"})
        assert isinstance(adapter, OpenCodeAdapter)

    def test_detect_augment_from_is_mcp_tool(self):
        adapter = detect_adapter({"is_mcp_tool": False, "tool_name": "view"})
        assert isinstance(adapter, AugmentAdapter)

    def test_detect_claude_from_pretooluse(self):
        adapter = detect_adapter({"hook_event_name": "PreToolUse"})
        assert isinstance(adapter, ClaudeCodeAdapter)

    def test_detect_claude_from_userpromptsubmit(self):
        adapter = detect_adapter({"hook_event_name": "UserPromptSubmit"})
        assert isinstance(adapter, ClaudeCodeAdapter)


# ── Normalization ────────────────────────────────────────────────────────


class TestNormalization:
    """Test normalize_input() across all adapters."""

    def test_claude_code_pretooluse(self):
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use": {"input": {"command": "ls -la"}},
            "cwd": "/home/user",
            "session_id": "s1",
            "tool_use_id": "tu1",
        }
        n = ClaudeCodeAdapter().normalize_input(data)
        assert n.event == HookEvent.PRE_TOOL_USE
        assert n.tool_name == "Bash"
        assert n.tool_input == {"command": "ls -la"}
        assert n.working_dir == "/home/user"
        assert n.session_id == "s1"
        assert n.tool_use_id == "tu1"

    def test_claude_code_prompt(self):
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "help me fix the bug",
            "session_id": "s2",
        }
        n = ClaudeCodeAdapter().normalize_input(data)
        assert n.event == HookEvent.PROMPT
        assert n.prompt_text == "help me fix the bug"

    def test_claude_code_posttooluse(self):
        data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": {"output": "file contents"},
        }
        n = ClaudeCodeAdapter().normalize_input(data)
        assert n.event == HookEvent.POST_TOOL_USE
        assert n.tool_response == {"output": "file contents"}

    def test_cursor_beforesubmitprompt(self):
        data = {
            "cursor_version": "0.50.0",
            "hook_event_name": "beforeSubmitPrompt",
            "message": "run tests",
        }
        n = CursorAdapter().normalize_input(data)
        assert n.event == HookEvent.PROMPT
        assert n.prompt_text == "run tests"

    def test_cursor_beforereadfile(self):
        data = {
            "cursor_version": "0.50.0",
            "hook_event_name": "beforeReadFile",
            "file_path": "/tmp/test.py",
        }
        n = CursorAdapter().normalize_input(data)
        assert n.event == HookEvent.BEFORE_READ_FILE
        assert n.file_path == "/tmp/test.py"
        assert n.tool_name == "Read"

    def test_cursor_beforeshellexecution(self):
        data = {
            "cursor_version": "0.50.0",
            "hook_event_name": "beforeShellExecution",
        }
        n = CursorAdapter().normalize_input(data)
        assert n.event == HookEvent.PRE_TOOL_USE
        assert n.tool_name == "Bash"

    def test_cursor_tool_name_synthesis_beforereadfile(self):
        data = {"hook_event_name": "beforeReadFile", "file_path": "/tmp/f.py"}
        assert CursorAdapter._extract_tool_name(data) == "Read"

    def test_cursor_tool_name_synthesis_beforeshellexecution(self):
        data = {"hook_event_name": "beforeShellExecution"}
        assert CursorAdapter._extract_tool_name(data) == "Bash"

    def test_cursor_tool_name_passthrough(self):
        """When tool_name is present, use it directly."""
        data = {"tool_name": "CustomTool", "hook_event_name": "preToolUse"}
        assert CursorAdapter._extract_tool_name(data) == "CustomTool"

    def test_copilot_toolname(self):
        data = {
            "toolName": "read_file",
            "toolArgs": '{"file_path": "/tmp/f.py"}',
            "cwd": "/home/user",
            "sessionId": "sid-123",
        }
        n = CopilotAdapter().normalize_input(data)
        assert n.event == HookEvent.PRE_TOOL_USE
        assert n.tool_name == "read_file"
        assert n.tool_input == {"file_path": "/tmp/f.py"}
        assert n.file_path == "/tmp/f.py"
        assert n.session_id == "sid-123"

    def test_windsurf_pre_run_command(self):
        data = {"agent_action_name": "pre_run_command", "tool_name": "shell"}
        n = WindsurfAdapter().normalize_input(data)
        assert n.event == HookEvent.PRE_TOOL_USE

    def test_windsurf_pre_user_prompt(self):
        data = {"agent_action_name": "pre_user_prompt"}
        n = WindsurfAdapter().normalize_input(data)
        assert n.event == HookEvent.PROMPT

    def test_windsurf_pre_read_code(self):
        data = {"agent_action_name": "pre_read_code"}
        n = WindsurfAdapter().normalize_input(data)
        assert n.event == HookEvent.BEFORE_READ_FILE

    def test_windsurf_post_events(self):
        for action in ("post_run_command", "post_read_code", "post_write_code", "post_mcp_tool_use"):
            data = {"agent_action_name": action}
            n = WindsurfAdapter().normalize_input(data)
            assert n.event == HookEvent.POST_TOOL_USE, f"{action} should map to POST_TOOL_USE"

    def test_gemini_beforetool(self):
        data = {
            "hook_event_name": "BeforeTool",
            "transcript_path": "/tmp/t.jsonl",
        }
        n = GeminiCLIAdapter().normalize_input(data)
        assert n.event == HookEvent.PRE_TOOL_USE
        assert n.transcript_path == "/tmp/t.jsonl"

    def test_gemini_aftertool(self):
        data = {"hook_event_name": "AfterTool", "transcript_path": "/tmp/t.jsonl"}
        n = GeminiCLIAdapter().normalize_input(data)
        assert n.event == HookEvent.POST_TOOL_USE

    def test_gemini_beforeagent(self):
        data = {"hook_event_name": "BeforeAgent", "transcript_path": "/tmp/t.jsonl"}
        n = GeminiCLIAdapter().normalize_input(data)
        assert n.event == HookEvent.PROMPT

    def test_cline_pretooluse(self):
        data = {
            "clineVersion": "1.0.0",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
        }
        n = ClineAdapter().normalize_input(data)
        assert n.event == HookEvent.PRE_TOOL_USE

    def test_kiro_pre_tool_use(self):
        data = {
            "kiro_hook_type": "pre_tool_use",
            "hook_event_name": "pre_tool_use",
            "tool_name": "read_file",
        }
        n = KiroAdapter().normalize_input(data)
        assert n.event == HookEvent.PRE_TOOL_USE

    def test_kiro_prompt_submit(self):
        data = {"kiro_hook_type": "prompt", "hook_event_name": "prompt_submit"}
        n = KiroAdapter().normalize_input(data)
        assert n.event == HookEvent.PROMPT

    def test_kiro_agent_stop(self):
        data = {"kiro_hook_type": "stop", "hook_event_name": "agent_stop"}
        n = KiroAdapter().normalize_input(data)
        assert n.event == HookEvent.POST_TOOL_USE

    def test_augment_tool_name_mapping(self):
        data = {
            "is_mcp_tool": False,
            "tool_name": "launch-process",
            "hook_event_name": "PreToolUse",
        }
        n = AugmentAdapter().normalize_input(data)
        assert n.tool_name == "Bash"

    def test_augment_all_tool_mappings(self):
        adapter = AugmentAdapter()
        tool_map = adapter.get_tool_name_map()
        assert tool_map["launch-process"] == "Bash"
        assert tool_map["str-replace-editor"] == "Edit"
        assert tool_map["save-file"] == "Write"
        assert tool_map["view"] == "Read"
        assert tool_map["remove-files"] == "Delete"

    def test_codex_shares_claude_format(self):
        adapter = CodexAdapter()
        assert adapter.name == "OpenAI Codex"
        assert adapter.ide_type == IDEType.CLAUDE_CODE


# ── Response Formatting ─────────────────────────────────────────────────


class TestResponseFormatting:
    """Test format_response() across all adapters."""

    def test_claude_code_pretooluse_block(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=True,
            error_message="Secret found",
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        assert result["exit_code"] == 0
        data = json.loads(result["output"])
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert result["_blocked"] is True

    def test_claude_code_pretooluse_allow(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        assert result["exit_code"] == 0
        data = json.loads(result["output"])
        assert data == {}

    def test_claude_code_prompt_block(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=True,
            error_message="Injection detected",
            hook_event=HookEvent.PROMPT,
        )
        data = json.loads(result["output"])
        assert data["decision"] == "block"
        assert "Injection detected" in data["reason"]

    def test_claude_code_prompt_security_message(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PROMPT,
            security_message="SECURITY RULES",
        )
        data = json.loads(result["output"])
        assert "SECURITY RULES" in data["systemMessage"]

    def test_claude_code_posttooluse_redaction(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.POST_TOOL_USE,
            modified_output="redacted content",
        )
        data = json.loads(result["output"])
        assert data["hookSpecificOutput"]["updatedToolOutput"] == "redacted content"

    def test_cursor_pretooluse_block(self):
        result = CursorAdapter().format_response(
            has_secrets=True,
            error_message="Secret found",
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        data = json.loads(result["output"])
        assert data["permission"] == "deny"
        assert "Secret found" in data["user_message"]
        assert data["agent_message"] == "Operation blocked by ai-guardian security policy"

    def test_cursor_pretooluse_allow(self):
        result = CursorAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        data = json.loads(result["output"])
        assert data["permission"] == "allow"
        assert "agent_message" not in data

    def test_cursor_beforereadfile_block(self):
        result = CursorAdapter().format_response(
            has_secrets=True,
            error_message="Denied",
            hook_event=HookEvent.BEFORE_READ_FILE,
        )
        data = json.loads(result["output"])
        assert data["continue"] is False
        assert "Denied" in data["user_message"]

    def test_cursor_beforereadfile_allow(self):
        result = CursorAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.BEFORE_READ_FILE,
        )
        data = json.loads(result["output"])
        assert data["continue"] is True
        assert "user_message" not in data

    def test_cursor_prompt_block(self):
        result = CursorAdapter().format_response(
            has_secrets=True,
            error_message="Blocked",
            hook_event=HookEvent.PROMPT,
        )
        data = json.loads(result["output"])
        assert data["continue"] is False
        assert "Blocked" in data["user_message"]

    def test_copilot_pretooluse_block(self):
        result = CopilotAdapter().format_response(
            has_secrets=True,
            error_message="Secret",
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        data = json.loads(result["output"])
        assert data["permissionDecision"] == "deny"

    def test_copilot_prompt_block(self, capsys):
        result = CopilotAdapter().format_response(
            has_secrets=True,
            error_message="Blocked",
            hook_event=HookEvent.PROMPT,
        )
        assert result["exit_code"] == 2
        captured = capsys.readouterr()
        assert "Blocked" in captured.err

    def test_gemini_block(self):
        result = GeminiCLIAdapter().format_response(
            has_secrets=True,
            error_message="Secret found",
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        data = json.loads(result["output"])
        assert data["decision"] == "deny"

    def test_gemini_allow_with_system_message(self):
        result = GeminiCLIAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PROMPT,
            security_message="SECURITY RULES",
        )
        data = json.loads(result["output"])
        assert "SECURITY RULES" in data["systemMessage"]

    def test_cline_block(self):
        result = ClineAdapter().format_response(
            has_secrets=True,
            error_message="Secret found",
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        data = json.loads(result["output"])
        assert data["cancel"] is True
        assert "Secret found" in data["reason"]

    def test_cline_allow_with_message(self):
        result = ClineAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PROMPT,
            security_message="SECURITY RULES",
        )
        data = json.loads(result["output"])
        assert "SECURITY RULES" in data["message"]

    def test_kiro_block(self, capsys):
        result = KiroAdapter().format_response(
            has_secrets=True,
            error_message="Secret found",
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        assert result["exit_code"] == 1
        assert result["output"] is None
        captured = capsys.readouterr()
        assert "Secret found" in captured.err

    def test_kiro_allow(self):
        result = KiroAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        assert result["exit_code"] == 0

    def test_kiro_allow_with_security_message(self):
        result = KiroAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PROMPT,
            security_message="RULES",
        )
        assert result["exit_code"] == 0
        assert "RULES" in result["output"]

    def test_kiro_modified_output(self):
        result = KiroAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.POST_TOOL_USE,
            modified_output="redacted",
        )
        assert "redacted" in result["output"]


# ── Agent-Facing Message Delivery (#1334) ──────────────────────────────


class TestAgentFacingMessages:
    """Test that warn/security messages reach the AI agent via agent-facing fields."""

    # -- Claude Code: additionalContext --

    def test_claude_code_prompt_security_has_additional_context(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PROMPT,
            security_message="SECURITY RULES",
        )
        data = json.loads(result["output"])
        assert "SECURITY RULES" in data["systemMessage"]
        assert data["hookSpecificOutput"]["additionalContext"] == "SECURITY RULES"
        assert data["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"

    def test_claude_code_prompt_security_and_warning_has_additional_context(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PROMPT,
            security_message="SECURITY RULES",
            warning_message="Config warning",
        )
        data = json.loads(result["output"])
        assert "SECURITY RULES" in data["hookSpecificOutput"]["additionalContext"]
        assert "Config warning" in data["hookSpecificOutput"]["additionalContext"]

    def test_claude_code_pretooluse_warn_has_additional_context(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
            warning_message="Log mode: tool policy violation",
        )
        data = json.loads(result["output"])
        assert data["systemMessage"] == "Log mode: tool policy violation"
        assert data["hookSpecificOutput"]["additionalContext"] == "Log mode: tool policy violation"
        assert data["hookSpecificOutput"]["hookEventName"] == "PreToolUse"

    def test_claude_code_posttooluse_warn_has_additional_context(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.POST_TOOL_USE,
            warning_message="Log mode: secret detected in output",
        )
        data = json.loads(result["output"])
        assert data["systemMessage"] == "Log mode: secret detected in output"
        assert data["hookSpecificOutput"]["additionalContext"] == "Log mode: secret detected in output"

    def test_claude_code_pretooluse_allow_no_additional_context(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        data = json.loads(result["output"])
        assert data == {}

    def test_claude_code_pretooluse_block_unchanged(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=True,
            error_message="Secret found",
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        data = json.loads(result["output"])
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "additionalContext" not in data.get("hookSpecificOutput", {})

    # -- Cursor: agent_message --

    def test_cursor_prompt_security_has_agent_message(self):
        result = CursorAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PROMPT,
            security_message="SECURITY RULES",
        )
        data = json.loads(result["output"])
        assert data["continue"] is True
        assert "SECURITY RULES" in data["agent_message"]

    def test_cursor_pretooluse_warn_has_agent_message(self):
        result = CursorAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
            warning_message="Log mode: violation detected",
        )
        data = json.loads(result["output"])
        assert data["permission"] == "allow"
        assert "Log mode: violation detected" in data["agent_message"]

    def test_cursor_pretooluse_allow_no_agent_message(self):
        result = CursorAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        data = json.loads(result["output"])
        assert data["permission"] == "allow"
        assert "agent_message" not in data

    # -- Gemini CLI: additionalContext --

    def test_gemini_prompt_security_has_additional_context(self):
        result = GeminiCLIAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PROMPT,
            security_message="SECURITY RULES",
        )
        data = json.loads(result["output"])
        assert "SECURITY RULES" in data["systemMessage"]
        assert "SECURITY RULES" in data["additionalContext"]

    # -- Cline: agent_context --

    def test_cline_prompt_security_has_agent_context(self):
        result = ClineAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PROMPT,
            security_message="SECURITY RULES",
        )
        data = json.loads(result["output"])
        assert "SECURITY RULES" in data["message"]
        assert "SECURITY RULES" in data["agent_context"]


# ── Warning + Error Combination ─────────────────────────────────────────


class TestWarningCombination:
    """Test that warning_message is prepended to error_message."""

    def test_claude_code_warning_prepended(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=True,
            error_message="Secret found",
            warning_message="Log mode active",
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        data = json.loads(result["output"])
        assert "Log mode active" in data["systemMessage"]
        assert "Secret found" in data["systemMessage"]

    def test_cursor_warning_prepended(self):
        result = CursorAdapter().format_response(
            has_secrets=True,
            error_message="Secret found",
            warning_message="Log mode active",
            hook_event=HookEvent.PROMPT,
        )
        data = json.loads(result["output"])
        assert "Log mode active" in data["user_message"]
        assert "Secret found" in data["user_message"]


# ── Metadata ─────────────────────────────────────────────────────────────


class TestMetadata:
    """Test daemon metadata attachment."""

    def test_blocked_metadata(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=True,
            error_message="Blocked",
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        assert result["_blocked"] is True

    def test_violation_type_metadata(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=True,
            error_message="Blocked",
            hook_event=HookEvent.PRE_TOOL_USE,
            violation_type="secret_detected",
        )
        assert result["_violation_type"] == "secret_detected"

    def test_no_blocked_when_allowed(self):
        result = ClaudeCodeAdapter().format_response(
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        assert "_blocked" not in result


# ── IDE Type Properties ──────────────────────────────────────────────────


class TestIDETypeProperties:
    """Test that each adapter reports the correct IDEType."""

    def test_claude_code_ide_type(self):
        assert ClaudeCodeAdapter().ide_type == IDEType.CLAUDE_CODE

    def test_cursor_ide_type(self):
        assert CursorAdapter().ide_type == IDEType.CURSOR

    def test_copilot_ide_type(self):
        assert CopilotAdapter().ide_type == IDEType.GITHUB_COPILOT

    def test_codex_ide_type(self):
        assert CodexAdapter().ide_type == IDEType.CLAUDE_CODE

    def test_windsurf_ide_type(self):
        assert WindsurfAdapter().ide_type == IDEType.CLAUDE_CODE

    def test_gemini_ide_type(self):
        assert GeminiCLIAdapter().ide_type == IDEType.GEMINI_CLI

    def test_cline_ide_type(self):
        assert ClineAdapter().ide_type == IDEType.CLINE

    def test_kiro_ide_type(self):
        assert KiroAdapter().ide_type == IDEType.KIRO

    def test_augment_ide_type(self):
        assert AugmentAdapter().ide_type == IDEType.CLAUDE_CODE

    def test_junie_ide_type(self):
        assert JunieAdapter().ide_type == IDEType.UNKNOWN


# ── Adapter Names ────────────────────────────────────────────────────────


class TestAdapterNames:
    """Test human-readable names."""

    def test_all_adapters_have_names(self):
        adapters = [
            ClaudeCodeAdapter(), CursorAdapter(), CopilotAdapter(),
            CodexAdapter(), WindsurfAdapter(), GeminiCLIAdapter(),
            ClineAdapter(), KiroAdapter(), AugmentAdapter(), JunieAdapter(),
        ]
        for adapter in adapters:
            assert adapter.name
            assert isinstance(adapter.name, str)
            assert len(adapter.name) > 2


# ── Backward Compatibility ──────────────────────────────────────────────


class TestBackwardCompatibility:
    """Test that response_format.py wrapper functions still work."""

    @pytest.fixture(autouse=True)
    def _clear_env(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AI_GUARDIAN_IDE_TYPE", None)
            yield

    def test_detect_ide_type_claude(self):
        from ai_guardian.response_format import detect_ide_type
        result = detect_ide_type({"hook_event_name": "PreToolUse"})
        assert result == IDEType.CLAUDE_CODE

    def test_detect_ide_type_cursor(self):
        from ai_guardian.response_format import detect_ide_type
        result = detect_ide_type({"cursor_version": "0.50"})
        assert result == IDEType.CURSOR

    def test_detect_hook_event_prompt(self):
        from ai_guardian.response_format import detect_hook_event
        result = detect_hook_event({"hook_event_name": "UserPromptSubmit"})
        assert result == HookEvent.PROMPT

    def test_detect_hook_event_pretooluse(self):
        from ai_guardian.response_format import detect_hook_event
        result = detect_hook_event({"hook_event_name": "PreToolUse"})
        assert result == HookEvent.PRE_TOOL_USE

    def test_detect_hook_event_kiro(self):
        from ai_guardian.response_format import detect_hook_event
        result = detect_hook_event({"hook_event_name": "pre_tool_use"})
        assert result == HookEvent.PRE_TOOL_USE

    def test_format_response_wrapper(self):
        from ai_guardian.response_format import format_response
        result = format_response(
            IDEType.CLAUDE_CODE,
            has_secrets=False,
            hook_event=HookEvent.PRE_TOOL_USE,
        )
        assert result["exit_code"] == 0
        assert json.loads(result["output"]) == {}


# ── Helper Methods ───────────────────────────────────────────────────────


class TestHelperMethods:
    """Test HookAdapter static helper methods."""

    def test_extract_file_path_tool_use_input(self):
        data = {"tool_use": {"input": {"file_path": "/tmp/test.py"}}}
        assert HookAdapter._extract_file_path_from_tool_input(data) == "/tmp/test.py"

    def test_extract_file_path_tool_use_parameters(self):
        data = {"tool_use": {"parameters": {"path": "/tmp/test.py"}}}
        assert HookAdapter._extract_file_path_from_tool_input(data) == "/tmp/test.py"

    def test_extract_file_path_direct_parameters(self):
        data = {"parameters": {"file_path": "/tmp/test.py"}}
        assert HookAdapter._extract_file_path_from_tool_input(data) == "/tmp/test.py"

    def test_extract_file_path_tool_input(self):
        data = {"tool_input": {"path": "/tmp/test.py"}}
        assert HookAdapter._extract_file_path_from_tool_input(data) == "/tmp/test.py"

    def test_extract_file_path_none(self):
        assert HookAdapter._extract_file_path_from_tool_input({}) is None

    def test_extract_tool_name_direct(self):
        assert HookAdapter._extract_tool_name({"tool_name": "Bash"}) == "Bash"

    def test_extract_tool_name_tool_use(self):
        assert HookAdapter._extract_tool_name({"tool_use": {"name": "Read"}}) == "Read"

    def test_extract_tool_name_none(self):
        assert HookAdapter._extract_tool_name({}) is None

    def test_extract_prompt_text(self):
        assert HookAdapter._extract_prompt_text({"prompt": "hello"}) == "hello"
        assert HookAdapter._extract_prompt_text({"message": "world"}) == "world"
        assert HookAdapter._extract_prompt_text({"userMessage": "test"}) == "test"
        assert HookAdapter._extract_prompt_text({}) is None

    def test_extract_transcript_path(self):
        assert HookAdapter._extract_transcript_path({"transcript_path": "/a"}) == "/a"
        assert HookAdapter._extract_transcript_path({"transcriptPath": "/b"}) == "/b"
        assert HookAdapter._extract_transcript_path({}) is None

    def test_combine_error_messages(self):
        assert HookAdapter._combine_error_messages("error", "warn") == "warn\n\nerror"
        assert HookAdapter._combine_error_messages("error", None) == "error"
        assert HookAdapter._combine_error_messages(None, "warn") is None


# ── Default Transcript Paths (Issue #935) ────────────────────────────────


class TestDefaultTranscriptPaths:
    """Test adapter-specific default transcript path resolution."""

    def test_base_adapter_returns_empty(self):
        """Base adapter returns empty list (no defaults)."""
        adapter = ClaudeCodeAdapter()
        assert adapter.get_default_transcript_paths() == []

    def test_copilot_returns_path_when_file_exists(self, tmp_path):
        """CopilotAdapter returns transcript path when file exists."""
        transcript = tmp_path / "events.jsonl"
        transcript.touch()

        adapter = CopilotAdapter()
        with mock.patch.object(CopilotAdapter, "TRANSCRIPT_PATH", str(transcript)):
            paths = adapter.get_default_transcript_paths()
            assert paths == [str(transcript)]

    def test_copilot_returns_empty_when_no_file(self, tmp_path):
        """CopilotAdapter returns empty list when transcript doesn't exist."""
        adapter = CopilotAdapter()
        with mock.patch.object(
            CopilotAdapter, "TRANSCRIPT_PATH",
            str(tmp_path / "nonexistent.jsonl"),
        ):
            assert adapter.get_default_transcript_paths() == []

    def test_codex_returns_paths_sorted_by_mtime(self, tmp_path):
        """CodexAdapter returns JSONL files sorted by modification time."""
        import time

        sessions = tmp_path / "sessions" / "2026" / "06" / "04"
        sessions.mkdir(parents=True)

        old = sessions / "old-session.jsonl"
        old.write_text('{"text":"old"}\n')
        time.sleep(0.05)
        new = sessions / "new-session.jsonl"
        new.write_text('{"text":"new"}\n')

        adapter = CodexAdapter()
        with mock.patch.object(CodexAdapter, "SESSIONS_DIR", str(tmp_path / "sessions")):
            paths = adapter.get_default_transcript_paths()
            assert len(paths) == 2
            # Most recent first
            assert paths[0] == str(new)
            assert paths[1] == str(old)

    def test_codex_returns_empty_when_no_dir(self, tmp_path):
        """CodexAdapter returns empty list when sessions dir doesn't exist."""
        adapter = CodexAdapter()
        with mock.patch.object(
            CodexAdapter, "SESSIONS_DIR",
            str(tmp_path / "nonexistent"),
        ):
            assert adapter.get_default_transcript_paths() == []

    def test_codex_returns_empty_when_no_jsonl_files(self, tmp_path):
        """CodexAdapter returns empty list when dir exists but has no JSONL files."""
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        (sessions / "readme.txt").write_text("not a transcript")

        adapter = CodexAdapter()
        with mock.patch.object(CodexAdapter, "SESSIONS_DIR", str(sessions)):
            assert adapter.get_default_transcript_paths() == []

    def test_codex_finds_nested_jsonl(self, tmp_path):
        """CodexAdapter finds JSONL files in nested date directories."""
        day1 = tmp_path / "sessions" / "2026" / "06" / "03"
        day2 = tmp_path / "sessions" / "2026" / "06" / "04"
        day1.mkdir(parents=True)
        day2.mkdir(parents=True)

        f1 = day1 / "session-a.jsonl"
        f1.write_text('{"text":"day1"}\n')
        f2 = day2 / "session-b.jsonl"
        f2.write_text('{"text":"day2"}\n')

        adapter = CodexAdapter()
        with mock.patch.object(CodexAdapter, "SESSIONS_DIR", str(tmp_path / "sessions")):
            paths = adapter.get_default_transcript_paths()
            assert len(paths) == 2
            # Both files found, most recent modification first
            assert str(f2) in paths
            assert str(f1) in paths

    def test_other_adapters_return_empty(self):
        """Adapters without transcript defaults return empty list."""
        for adapter_cls in [
            CursorAdapter, WindsurfAdapter, GeminiCLIAdapter,
            ClineAdapter, KiroAdapter, AugmentAdapter, OpenCodeAdapter,
        ]:
            adapter = adapter_cls()
            assert adapter.get_default_transcript_paths() == [], (
                f"{adapter.name} should return empty transcript paths"
            )


# ── Cursor Event-Based Hook Fixes (Issue #1220) ─────────────────────────


class TestCursorToolNameExtraction:
    """Tool name synthesis and tool_policy fallback for Cursor event-based hooks."""

    def test_tool_policy_extract_cursor_beforereadfile(self):
        from ai_guardian.tool_policy import ToolPolicyChecker
        checker = ToolPolicyChecker(config={})
        hook_data = {
            "cursor_version": "0.50.0",
            "hook_event_name": "beforeReadFile",
            "file_path": "/tmp/secret.txt",
        }
        tool_name, tool_input = checker._extract_tool_info(hook_data)
        assert tool_name == "Read"
        assert tool_input.get("file_path") == "/tmp/secret.txt"

    def test_tool_policy_extract_cursor_beforeshellexecution(self):
        from ai_guardian.tool_policy import ToolPolicyChecker
        checker = ToolPolicyChecker(config={})
        hook_data = {
            "cursor_version": "0.50.0",
            "hook_event_name": "beforeShellExecution",
        }
        tool_name, tool_input = checker._extract_tool_info(hook_data)
        assert tool_name == "Bash"

    def test_tool_policy_no_block_on_cursor_beforereadfile(self):
        """check_tool_allowed should not fail with 'unable to determine tool name'."""
        from ai_guardian.tool_policy import ToolPolicyChecker
        checker = ToolPolicyChecker(config={"rules": []})
        hook_data = {
            "cursor_version": "0.50.0",
            "hook_event_name": "beforeReadFile",
            "file_path": "/tmp/test.py",
        }
        is_allowed, error_msg, tool_name = checker.check_tool_allowed(hook_data)
        assert "unable to determine tool name" not in (error_msg or "")
        assert tool_name == "Read"
