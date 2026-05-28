"""
Tests for Issue #807: Content-aware hook protection for mixed settings files.

Mixed settings files (Claude, Gemini, Augment) contain both hooks and user
preferences. Only hook modifications should be blocked; non-hook edits
(permissions, theme, model, MCP) should be allowed.

Hooks-only files (Cursor, Copilot, etc.) remain fully blocked.
Bash/PowerShell commands remain fully blocked for all settings files.
"""

import json
import os
import tempfile
import pytest

from ai_guardian.tool_policy import ToolPolicyChecker


def _make_hook_data(tool_name, tool_input):
    return {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": tool_name,
            "input": tool_input,
        },
    }


@pytest.fixture
def checker():
    return ToolPolicyChecker(config={"permissions": []})


# ============================================================================
# Parametrized: Edit allows non-hook changes in mixed settings files
# ============================================================================

EDIT_ALLOWS_NON_HOOK = [
    pytest.param(
        "/home/user/.claude/settings.json",
        '"model": "claude-sonnet-4-5-20250514"',
        '"model": "claude-opus-4-20250514"',
        id="claude-model-change",
    ),
    pytest.param(
        "/home/user/.claude/settings.json",
        '"allow": []',
        '"allow": ["npm test"]',
        id="claude-permission-change",
    ),
    pytest.param(
        "/home/user/.claude/settings.json",
        '"mcpServers": {}',
        '"mcpServers": {"my-server": {"command": "npx"}}',
        id="claude-mcp-change",
    ),
    pytest.param(
        "/home/user/.gemini/settings.json",
        '"theme": "dark"',
        '"theme": "light"',
        id="gemini-non-hook-change",
    ),
    pytest.param(
        "/home/user/.augment/settings.json",
        '"model": "gpt-4"',
        '"model": "claude-sonnet"',
        id="augment-non-hook-change",
    ),
    pytest.param(
        "C:/Users/user/AppData/Roaming/Claude/settings.json",
        '"model": "old"',
        '"model": "new"',
        id="windows-claude-non-hook-change",
    ),
]


@pytest.mark.parametrize("file_path,old_string,new_string", EDIT_ALLOWS_NON_HOOK)
def test_edit_allows_non_hook_change(checker, file_path, old_string, new_string):
    """Edit tool allows non-hook modifications to mixed settings files."""
    hook_data = _make_hook_data("Edit", {
        "file_path": file_path,
        "old_string": old_string,
        "new_string": new_string,
    })
    allowed, msg, _ = checker.check_tool_allowed(hook_data)
    assert allowed, f"Non-hook change should be allowed: {file_path}"


# ============================================================================
# Parametrized: Edit blocks hook changes in mixed settings files
# ============================================================================

EDIT_BLOCKS_HOOK_CHANGES = [
    pytest.param(
        "/home/user/.claude/settings.json",
        '"hooks": {}',
        '"hooks": {"PreToolUse": []}',
        id="claude-hooks-key",
    ),
    pytest.param(
        "/home/user/.claude/settings.json",
        '"PreToolUse": [{"matcher": "*"}]',
        '"PreToolUse": []',
        id="claude-pretooluse-key",
    ),
    pytest.param(
        "/home/user/.claude/settings.json",
        'old content',
        '"PostToolUse": [{"matcher": "*"}]',
        id="claude-posttooluse-key",
    ),
    pytest.param(
        "/home/user/.claude/settings.json",
        '"UserPromptSubmit": [{"matcher": "*"}]',
        '"UserPromptSubmit": []',
        id="claude-userpromptsubmit-key",
    ),
    pytest.param(
        "/home/user/.gemini/settings.json",
        '"hooks": [{"event": "BeforeTool"}]',
        '"hooks": []',
        id="gemini-hooks-key",
    ),
    pytest.param(
        "/home/user/.gemini/settings.json",
        '"BeforeAgent": "ai-guardian"',
        '"BeforeAgent": "echo ok"',
        id="gemini-beforeagent",
    ),
    pytest.param(
        "/home/user/.augment/settings.json",
        '"hooks": {"hooks": {"PreToolUse": []}}',
        '"hooks": {}',
        id="augment-hooks-key",
    ),
    pytest.param(
        "C:/Users/user/AppData/Roaming/Claude/settings.json",
        '"hooks": {}',
        '"hooks": {"PreToolUse": []}',
        id="windows-claude-hooks",
    ),
    pytest.param(
        "/home/user/.claude/settings.json",
        '"command": "ai-guardian"',
        '"command": "echo bypass"',
        id="ai-guardian-command-modification",
    ),
]


@pytest.mark.parametrize("file_path,old_string,new_string", EDIT_BLOCKS_HOOK_CHANGES)
def test_edit_blocks_hook_change(checker, file_path, old_string, new_string):
    """Edit tool blocks hook modifications in mixed settings files."""
    hook_data = _make_hook_data("Edit", {
        "file_path": file_path,
        "old_string": old_string,
        "new_string": new_string,
    })
    allowed, msg, _ = checker.check_tool_allowed(hook_data)
    assert not allowed, f"Hook change should be blocked: {file_path}"


# ============================================================================
# Write content-aware tests (unchanged - complex setup with tempfiles)
# ============================================================================

class TestWriteContentAware:
    """Write tool does content-aware checking for mixed settings files."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.checker = ToolPolicyChecker(config={"permissions": []})

    def test_write_allows_unchanged_hooks(self):
        hooks_config = {"PreToolUse": [{"matcher": "*", "hooks": []}]}
        original = {"hooks": hooks_config, "model": "old-model"}
        updated = {"hooks": hooks_config, "model": "new-model"}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir="/tmp",
            prefix=".claude_settings_"
        ) as f:
            json.dump(original, f)
            tmp_path = f.name

        try:
            hook_data = _make_hook_data("Write", {
                "file_path": tmp_path,
                "content": json.dumps(updated),
            })

            import ai_guardian.tool_policy as tp
            orig_patterns = tp.MIXED_SETTINGS_PATTERNS
            tp.MIXED_SETTINGS_PATTERNS = ["*"]
            try:
                allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
                assert allowed, "Write with unchanged hooks should be allowed"
                assert msg is None
            finally:
                tp.MIXED_SETTINGS_PATTERNS = orig_patterns
        finally:
            os.unlink(tmp_path)

    def test_write_blocks_modified_hooks(self):
        original = {"hooks": {"PreToolUse": [{"matcher": "*"}]}, "model": "old"}
        updated = {"hooks": {"PreToolUse": []}, "model": "new"}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir="/tmp",
            prefix=".claude_settings_"
        ) as f:
            json.dump(original, f)
            tmp_path = f.name

        try:
            hook_data = _make_hook_data("Write", {
                "file_path": tmp_path,
                "content": json.dumps(updated),
            })

            import ai_guardian.tool_policy as tp
            orig_patterns = tp.MIXED_SETTINGS_PATTERNS
            tp.MIXED_SETTINGS_PATTERNS = ["*"]
            try:
                allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
                assert not allowed, "Write with modified hooks should be blocked"
                assert "Hook Protection" in msg
            finally:
                tp.MIXED_SETTINGS_PATTERNS = orig_patterns
        finally:
            os.unlink(tmp_path)

    def test_write_blocks_removed_hooks(self):
        original = {"hooks": {"PreToolUse": [{"matcher": "*"}]}, "model": "old"}
        updated = {"model": "new"}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir="/tmp",
            prefix=".claude_settings_"
        ) as f:
            json.dump(original, f)
            tmp_path = f.name

        try:
            hook_data = _make_hook_data("Write", {
                "file_path": tmp_path,
                "content": json.dumps(updated),
            })

            import ai_guardian.tool_policy as tp
            orig_patterns = tp.MIXED_SETTINGS_PATTERNS
            tp.MIXED_SETTINGS_PATTERNS = ["*"]
            try:
                allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
                assert not allowed, "Write removing hooks should be blocked"
            finally:
                tp.MIXED_SETTINGS_PATTERNS = orig_patterns
        finally:
            os.unlink(tmp_path)

    def test_write_blocks_new_file_with_hooks(self):
        non_existent = "/tmp/_test_nonexistent_settings_807.json"
        if os.path.exists(non_existent):
            os.unlink(non_existent)

        hook_data = _make_hook_data("Write", {
            "file_path": non_existent,
            "content": json.dumps({"hooks": {"PreToolUse": []}, "model": "test"}),
        })

        import ai_guardian.tool_policy as tp
        orig_patterns = tp.MIXED_SETTINGS_PATTERNS
        tp.MIXED_SETTINGS_PATTERNS = ["*"]
        try:
            allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
            assert not allowed, "New file with hooks should be blocked"
        finally:
            tp.MIXED_SETTINGS_PATTERNS = orig_patterns

    def test_write_allows_new_file_without_hooks(self):
        non_existent = "/tmp/_test_nonexistent_settings_807.json"
        if os.path.exists(non_existent):
            os.unlink(non_existent)

        hook_data = _make_hook_data("Write", {
            "file_path": non_existent,
            "content": json.dumps({"model": "test", "theme": "dark"}),
        })

        import ai_guardian.tool_policy as tp
        orig_patterns = tp.MIXED_SETTINGS_PATTERNS
        tp.MIXED_SETTINGS_PATTERNS = ["*"]
        try:
            allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
            assert allowed, "New file without hooks should be allowed"
        finally:
            tp.MIXED_SETTINGS_PATTERNS = orig_patterns

    def test_write_blocks_invalid_json(self):
        hook_data = _make_hook_data("Write", {
            "file_path": "/home/user/.claude/settings.json",
            "content": "not valid json {{{",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        assert not allowed, "Invalid JSON should fail-closed"
        assert "Hook Protection" in msg
        assert "cannot parse" in msg

    def test_write_blocks_empty_content(self):
        hook_data = _make_hook_data("Write", {
            "file_path": "/home/user/.claude/settings.json",
            "content": "",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        assert not allowed, "Empty content should fail-closed"

    def test_write_blocks_no_content_key(self):
        hook_data = _make_hook_data("Write", {
            "file_path": "/home/user/.claude/settings.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        assert not allowed, "Missing content should fail-closed"


# ============================================================================
# Parametrized: Hooks-only files remain fully blocked
# ============================================================================

HOOKS_ONLY_BLOCKED = [
    pytest.param("Write", "/home/user/.cursor/hooks.json", id="write-cursor-hooks"),
    pytest.param("Edit", "/home/user/.cursor/hooks.json", id="edit-cursor-hooks"),
    pytest.param("Write", "/home/user/.claude/hooks.json", id="write-claude-hooks"),
    pytest.param("Edit", "/home/user/.claude/hooks.json", id="edit-claude-hooks"),
]


@pytest.mark.parametrize("tool_name,file_path", HOOKS_ONLY_BLOCKED)
def test_hooks_only_files_still_blocked(checker, tool_name, file_path):
    """Hooks-only files remain fully blocked (regression tests)."""
    tool_input = {"file_path": file_path}
    if tool_name == "Edit":
        tool_input.update({"old_string": "old", "new_string": "new"})

    hook_data = _make_hook_data(tool_name, tool_input)
    allowed, msg, _ = checker.check_tool_allowed(hook_data)
    assert not allowed, f"{tool_name} on {file_path} should still be fully blocked"


# ============================================================================
# Parametrized: Bash blocks on IDE settings files
# ============================================================================

BASH_BLOCKED_IDE_SETTINGS = [
    pytest.param(
        "sed -i 's/ai-guardian//' ~/.claude/settings.json",
        id="sed-claude-settings",
    ),
    pytest.param(
        "sed -i 's/old/new/' ~/.gemini/settings.json",
        id="sed-gemini-settings",
    ),
    pytest.param(
        "sed -i 's/old/new/' ~/.augment/settings.json",
        id="sed-augment-settings",
    ),
    pytest.param(
        "rm ~/.gemini/settings.json",
        id="rm-gemini-settings",
    ),
    pytest.param(
        "rm ~/.augment/settings.json",
        id="rm-augment-settings",
    ),
    pytest.param(
        "echo '{}' > ~/.gemini/settings.json",
        id="redirect-gemini-settings",
    ),
    pytest.param(
        "vim ~/.augment/settings.json",
        id="vim-augment-settings",
    ),
]


@pytest.mark.parametrize("command", BASH_BLOCKED_IDE_SETTINGS)
def test_bash_blocks_ide_settings(checker, command):
    """Bash commands on settings files remain fully blocked."""
    hook_data = _make_hook_data("Bash", {"command": command})
    allowed, msg, _ = checker.check_tool_allowed(hook_data)
    assert not allowed, f"Bash command should be blocked: {command}"


# ============================================================================
# PowerShell still blocked (unchanged - only 2 tests)
# ============================================================================

POWERSHELL_BLOCKED = [
    pytest.param(
        "Remove-Item ~/.gemini/settings.json",
        id="remove-item-gemini",
    ),
    pytest.param(
        "Set-Content ~/.augment/settings.json '{}'",
        id="set-content-augment",
    ),
]


@pytest.mark.parametrize("command", POWERSHELL_BLOCKED)
def test_powershell_blocks_settings(checker, command):
    """PowerShell commands on settings files remain fully blocked."""
    hook_data = _make_hook_data("PowerShell", {"command": command})
    allowed, msg, _ = checker.check_tool_allowed(hook_data)
    assert not allowed, f"PowerShell command should be blocked: {command}"


# ============================================================================
# Hook protection error messages
# ============================================================================

def test_message_mentions_non_hook_settings_allowed(checker):
    hook_data = _make_hook_data("Edit", {
        "file_path": "/home/user/.claude/settings.json",
        "old_string": '"hooks": {}',
        "new_string": '"hooks": {"PreToolUse": []}',
    })
    allowed, msg, _ = checker.check_tool_allowed(hook_data)
    assert not allowed
    assert "Non-hook settings" in msg
    assert "CAN be modified" in msg


def test_message_mentions_hooks_key(checker):
    hook_data = _make_hook_data("Edit", {
        "file_path": "/home/user/.claude/settings.json",
        "old_string": '"hooks": {}',
        "new_string": '"hooks": {"PreToolUse": []}',
    })
    allowed, msg, _ = checker.check_tool_allowed(hook_data)
    assert "hook" in msg.lower()
    assert "Hook Protection" in msg


def test_message_file_path_shown(checker):
    hook_data = _make_hook_data("Edit", {
        "file_path": "/home/user/.claude/settings.json",
        "old_string": '"hooks": {}',
        "new_string": '"hooks": {"PreToolUse": []}',
    })
    allowed, msg, _ = checker.check_tool_allowed(hook_data)
    assert "/home/user/.claude/settings.json" in msg


def test_message_immutable_warning(checker):
    hook_data = _make_hook_data("Edit", {
        "file_path": "/home/user/.claude/settings.json",
        "old_string": '"hooks": {}',
        "new_string": '"hooks": {"PreToolUse": []}',
    })
    allowed, msg, _ = checker.check_tool_allowed(hook_data)
    assert "cannot be disabled via configuration" in msg


if __name__ == "__main__":
    pytest.main([__file__])
