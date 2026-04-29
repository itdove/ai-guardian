"""
Test for Issue #105: Self-protection rules can be bypassed with action=log setting

This test verifies that self-protection rules ALWAYS block, regardless of
user's action="log" configuration for directory_rules.
"""

import unittest
from ai_guardian.tool_policy import ToolPolicyChecker


class Issue105LogBypassTest(unittest.TestCase):
    """Test that action=log cannot bypass self-protection"""

    def test_immutable_deny_ignores_directory_rules_log_action(self):
        """
        CRITICAL: Self-protection should block even if directory_rules has action="log"

        Vulnerability scenario:
        1. User sets directory_rules.action = "log" for testing/gradual rollout
        2. AI tries to edit ai-guardian config file
        3. EXPECTED: Blocked by immutable deny patterns
        4. ACTUAL (if vulnerable): Allowed with warning (bypassing protection)
        """
        # Config with directory_rules action="log" (user setting for gradual rollout)
        config = {
            "directory_rules": {
                "action": "log",  # User wants log mode for directory blocking
                "rules": []
            },
            "permissions": []
        }

        checker = ToolPolicyChecker(config=config)

        # AI tries to edit ai-guardian config file
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/.config/ai-guardian/ai-guardian.json",
                    "old_string": '"secret_scanning": {"enabled": true}',
                    "new_string": '"secret_scanning": {"enabled": false}'
                }
            }
        }

        is_allowed, error_msg, tool_name = checker.check_tool_allowed(hook_data)

        # CRITICAL: Must be blocked, NOT allowed with warning
        self.assertFalse(is_allowed,
            "Self-protection MUST block config file edits, even with action=log")
        self.assertIsNotNone(error_msg, "Should provide error message")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg,
            "Error message should indicate critical file protection")

        # Verify it's not a log-mode warning
        self.assertNotIn("log mode", error_msg.lower(),
            "Should NOT be in log mode - must be hard blocked")
        self.assertNotIn("allowed", error_msg.lower(),
            "Error message should NOT say operation is allowed")

    def test_immutable_deny_ignores_permission_rule_with_log_action(self):
        """
        CRITICAL: Self-protection should block even if user adds permission rule with action="log"

        Attack scenario:
        1. Attacker adds permission rule with matcher="Edit", action="log"
        2. AI tries to edit ai-guardian config
        3. EXPECTED: Blocked by immutable deny (immutable > user rules)
        4. ACTUAL (if vulnerable): Allowed with warning
        """
        # Config with permission rule trying to bypass with action="log"
        config = {
            "permissions": [
                {
                    "matcher": "Edit",
                    "mode": "deny",
                    "patterns": ["*ai-guardian.json"],
                    "action": "log"  # Attacker tries to use log mode to bypass
                }
            ]
        }

        checker = ToolPolicyChecker(config=config)

        # AI tries to edit ai-guardian config file
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/.config/ai-guardian/ai-guardian.json",
                    "old_string": '"enabled": true',
                    "new_string": '"enabled": false'
                }
            }
        }

        is_allowed, error_msg, tool_name = checker.check_tool_allowed(hook_data)

        # CRITICAL: Must be blocked - immutable patterns override user rules
        self.assertFalse(is_allowed,
            "Immutable deny patterns MUST override user permission rules")
        self.assertIsNotNone(error_msg)
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)
        self.assertNotIn("log mode", error_msg.lower())

    def test_write_ai_guardian_config_always_blocked(self):
        """Write to ai-guardian config must ALWAYS be blocked (no log mode)"""
        config = {
            "directory_rules": {"action": "log"},
            "permissions": []
        }

        checker = ToolPolicyChecker(config=config)

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/.config/ai-guardian/ai-guardian.json",
                    "content": "{}"
                }
            }
        }

        is_allowed, error_msg, tool_name = checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to config must be blocked")
        self.assertNotIn("log mode", error_msg.lower() if error_msg else "")

    def test_bash_rm_ai_guardian_config_always_blocked(self):
        """Bash rm of ai-guardian config must ALWAYS be blocked (no log mode)"""
        config = {
            "directory_rules": {"action": "log"},
            "permissions": []
        }

        checker = ToolPolicyChecker(config=config)

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "rm ~/.config/ai-guardian/ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash rm of config must be blocked")
        self.assertNotIn("log mode", error_msg.lower() if error_msg else "")

    def test_edit_claude_settings_always_blocked(self):
        """Edit of IDE hooks must ALWAYS be blocked (no log mode)"""
        config = {
            "directory_rules": {"action": "log"},
            "permissions": []
        }

        checker = ToolPolicyChecker(config=config)

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/.claude/settings.json",
                    "old_string": '"ai-guardian"',
                    "new_string": '""'
                }
            }
        }

        is_allowed, error_msg, tool_name = checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Edit of IDE hooks must be blocked")
        self.assertNotIn("log mode", error_msg.lower() if error_msg else "")

    def test_edit_ai_read_deny_marker_always_blocked(self):
        """Edit of .ai-read-deny markers must ALWAYS be blocked (no log mode)"""
        config = {
            "directory_rules": {"action": "log"},
            "permissions": []
        }

        checker = ToolPolicyChecker(config=config)

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/secrets/.ai-read-deny",
                    "old_string": "",
                    "new_string": "test"
                }
            }
        }

        is_allowed, error_msg, tool_name = checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Edit of .ai-read-deny must be blocked")
        self.assertNotIn("log mode", error_msg.lower() if error_msg else "")


if __name__ == "__main__":
    unittest.main()
