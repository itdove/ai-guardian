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
from unittest import TestCase

from ai_guardian.tool_policy import ToolPolicyChecker


def _make_hook_data(tool_name, tool_input):
    return {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": tool_name,
            "input": tool_input,
        },
    }


class TestEditAllowsNonHookChanges(TestCase):
    """Edit tool allows non-hook modifications to mixed settings files."""

    def setUp(self):
        self.checker = ToolPolicyChecker(config={"permissions": []})

    def test_edit_allows_claude_model_change(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": '"model": "claude-sonnet-4-5-20250514"',
            "new_string": '"model": "claude-opus-4-20250514"',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertTrue(allowed, "Non-hook model change should be allowed")
        self.assertIsNone(msg)

    def test_edit_allows_claude_permission_change(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": '"allow": []',
            "new_string": '"allow": ["npm test"]',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertTrue(allowed, "Permission changes should be allowed")

    def test_edit_allows_claude_mcp_change(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": '"mcpServers": {}',
            "new_string": '"mcpServers": {"my-server": {"command": "npx"}}',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertTrue(allowed, "MCP server changes should be allowed")

    def test_edit_allows_gemini_non_hook_change(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.gemini/settings.json",
            "old_string": '"theme": "dark"',
            "new_string": '"theme": "light"',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertTrue(allowed, "Gemini non-hook change should be allowed")

    def test_edit_allows_augment_non_hook_change(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.augment/settings.json",
            "old_string": '"model": "gpt-4"',
            "new_string": '"model": "claude-sonnet"',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertTrue(allowed, "Augment non-hook change should be allowed")

    def test_edit_allows_windows_claude_non_hook_change(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "C:/Users/user/AppData/Roaming/Claude/settings.json",
            "old_string": '"model": "old"',
            "new_string": '"model": "new"',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertTrue(allowed, "Windows Claude non-hook change should be allowed")


class TestEditBlocksHookChanges(TestCase):
    """Edit tool blocks hook modifications in mixed settings files."""

    def setUp(self):
        self.checker = ToolPolicyChecker(config={"permissions": []})

    def test_edit_blocks_hooks_key(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": '"hooks": {}',
            "new_string": '"hooks": {"PreToolUse": []}',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Edit with hooks key should be blocked")
        self.assertIn("Hook Protection", msg)

    def test_edit_blocks_pretooluse_key(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": '"PreToolUse": [{"matcher": "*"}]',
            "new_string": '"PreToolUse": []',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Edit with PreToolUse key should be blocked")

    def test_edit_blocks_posttooluse_key(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": 'old content',
            "new_string": '"PostToolUse": [{"matcher": "*"}]',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Edit with PostToolUse key should be blocked")

    def test_edit_blocks_userpromptsubmit_key(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": '"UserPromptSubmit": [{"matcher": "*"}]',
            "new_string": '"UserPromptSubmit": []',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Edit with UserPromptSubmit key should be blocked")

    def test_edit_blocks_gemini_hooks_key(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.gemini/settings.json",
            "old_string": '"hooks": [{"event": "BeforeTool"}]',
            "new_string": '"hooks": []',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Gemini hooks edit should be blocked")

    def test_edit_blocks_gemini_beforeagent(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.gemini/settings.json",
            "old_string": '"BeforeAgent": "ai-guardian"',
            "new_string": '"BeforeAgent": "echo ok"',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Gemini BeforeAgent edit should be blocked")

    def test_edit_blocks_augment_hooks_key(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.augment/settings.json",
            "old_string": '"hooks": {"hooks": {"PreToolUse": []}}',
            "new_string": '"hooks": {}',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Augment hooks edit should be blocked")

    def test_edit_blocks_windows_claude_hooks(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "C:/Users/user/AppData/Roaming/Claude/settings.json",
            "old_string": '"hooks": {}',
            "new_string": '"hooks": {"PreToolUse": []}',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Windows Claude hooks edit should be blocked")

    def test_edit_blocks_ai_guardian_command_modification(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": '"command": "ai-guardian"',
            "new_string": '"command": "echo bypass"',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Modifying ai-guardian command should be blocked")


class TestWriteContentAware(TestCase):
    """Write tool does content-aware checking for mixed settings files."""

    def setUp(self):
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

            # Patch MIXED_SETTINGS_PATTERNS to match our temp file
            import ai_guardian.tool_policy as tp
            orig_patterns = tp.MIXED_SETTINGS_PATTERNS
            tp.MIXED_SETTINGS_PATTERNS = ["*"]
            try:
                allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
                self.assertTrue(allowed, "Write with unchanged hooks should be allowed")
                self.assertIsNone(msg)
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
                self.assertFalse(allowed, "Write with modified hooks should be blocked")
                self.assertIn("Hook Protection", msg)
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
                self.assertFalse(allowed, "Write removing hooks should be blocked")
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
            self.assertFalse(allowed, "New file with hooks should be blocked")
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
            self.assertTrue(allowed, "New file without hooks should be allowed")
        finally:
            tp.MIXED_SETTINGS_PATTERNS = orig_patterns

    def test_write_blocks_invalid_json(self):
        hook_data = _make_hook_data("Write", {
            "file_path": "/home/user/.claude/settings.json",
            "content": "not valid json {{{",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Invalid JSON should fail-closed")
        self.assertIn("Hook Protection", msg)
        self.assertIn("cannot parse", msg)

    def test_write_blocks_empty_content(self):
        hook_data = _make_hook_data("Write", {
            "file_path": "/home/user/.claude/settings.json",
            "content": "",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Empty content should fail-closed")

    def test_write_blocks_no_content_key(self):
        hook_data = _make_hook_data("Write", {
            "file_path": "/home/user/.claude/settings.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Missing content should fail-closed")


class TestHooksOnlyFilesStillBlocked(TestCase):
    """Hooks-only files remain fully blocked (regression tests)."""

    def setUp(self):
        self.checker = ToolPolicyChecker(config={"permissions": []})

    def test_write_blocks_cursor_hooks(self):
        hook_data = _make_hook_data("Write", {
            "file_path": "/home/user/.cursor/hooks.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Cursor hooks.json should still be fully blocked")

    def test_edit_blocks_cursor_hooks(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.cursor/hooks.json",
            "old_string": "old",
            "new_string": "new",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Cursor hooks.json edit should still be blocked")

    def test_write_blocks_claude_hooks_json(self):
        hook_data = _make_hook_data("Write", {
            "file_path": "/home/user/.claude/hooks.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Claude hooks.json should still be fully blocked")

    def test_edit_blocks_claude_hooks_json(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/hooks.json",
            "old_string": "old",
            "new_string": "new",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Claude hooks.json edit should still be blocked")


class TestBashStillBlocked(TestCase):
    """Bash commands on settings files remain fully blocked."""

    def setUp(self):
        self.checker = ToolPolicyChecker(config={"permissions": []})

    def test_bash_blocks_sed_claude_settings(self):
        hook_data = _make_hook_data("Bash", {
            "command": "sed -i 's/ai-guardian//' ~/.claude/settings.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Bash sed on Claude settings should be blocked")

    def test_bash_blocks_sed_gemini_settings(self):
        hook_data = _make_hook_data("Bash", {
            "command": "sed -i 's/old/new/' ~/.gemini/settings.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Bash sed on Gemini settings should be blocked")

    def test_bash_blocks_sed_augment_settings(self):
        hook_data = _make_hook_data("Bash", {
            "command": "sed -i 's/old/new/' ~/.augment/settings.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Bash sed on Augment settings should be blocked")

    def test_bash_blocks_rm_gemini_settings(self):
        hook_data = _make_hook_data("Bash", {
            "command": "rm ~/.gemini/settings.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Bash rm on Gemini settings should be blocked")

    def test_bash_blocks_rm_augment_settings(self):
        hook_data = _make_hook_data("Bash", {
            "command": "rm ~/.augment/settings.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Bash rm on Augment settings should be blocked")

    def test_bash_blocks_redirect_gemini_settings(self):
        hook_data = _make_hook_data("Bash", {
            "command": "echo '{}' > ~/.gemini/settings.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Bash redirect on Gemini settings should be blocked")

    def test_bash_blocks_vim_augment_settings(self):
        hook_data = _make_hook_data("Bash", {
            "command": "vim ~/.augment/settings.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "Bash vim on Augment settings should be blocked")


class TestPowerShellStillBlocked(TestCase):
    """PowerShell commands on settings files remain fully blocked."""

    def setUp(self):
        self.checker = ToolPolicyChecker(config={"permissions": []})

    def test_powershell_blocks_gemini_settings(self):
        hook_data = _make_hook_data("PowerShell", {
            "command": "Remove-Item ~/.gemini/settings.json",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "PowerShell Remove-Item on Gemini settings should be blocked")

    def test_powershell_blocks_augment_settings(self):
        hook_data = _make_hook_data("PowerShell", {
            "command": "Set-Content ~/.augment/settings.json '{}'",
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed, "PowerShell Set-Content on Augment settings should be blocked")


class TestHookProtectionErrorMessage(TestCase):
    """Hook protection error messages are helpful."""

    def setUp(self):
        self.checker = ToolPolicyChecker(config={"permissions": []})

    def test_message_mentions_non_hook_settings_allowed(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": '"hooks": {}',
            "new_string": '"hooks": {"PreToolUse": []}',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertFalse(allowed)
        self.assertIn("Non-hook settings", msg)
        self.assertIn("CAN be modified", msg)

    def test_message_mentions_hooks_key(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": '"hooks": {}',
            "new_string": '"hooks": {"PreToolUse": []}',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertIn("hook", msg.lower())
        self.assertIn("Hook Protection", msg)

    def test_message_file_path_shown(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": '"hooks": {}',
            "new_string": '"hooks": {"PreToolUse": []}',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertIn("/home/user/.claude/settings.json", msg)

    def test_message_immutable_warning(self):
        hook_data = _make_hook_data("Edit", {
            "file_path": "/home/user/.claude/settings.json",
            "old_string": '"hooks": {}',
            "new_string": '"hooks": {"PreToolUse": []}',
        })
        allowed, msg, _ = self.checker.check_tool_allowed(hook_data)
        self.assertIn("cannot be disabled via configuration", msg)


if __name__ == "__main__":
    import unittest
    unittest.main()
