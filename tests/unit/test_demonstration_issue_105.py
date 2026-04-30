"""
Demonstration: Issue #105 - Self-protection cannot be bypassed with action=log

This test demonstrates that even with action="log" configured at various levels,
self-protection rules ALWAYS block attempts to modify critical files.
"""

import unittest
from ai_guardian.tool_policy import ToolPolicyChecker


class DemonstrationIssue105(unittest.TestCase):
    """Demonstrate that action=log cannot bypass self-protection"""

    def test_scenario_1_directory_rules_action_log(self):
        """
        Scenario 1: User sets directory_rules.action = "log"

        Expected: Self-protection STILL blocks config file edits
        """
        print("\n" + "="*70)
        print("SCENARIO 1: User configured directory_rules with action='log'")
        print("="*70)

        config = {
            "directory_rules": {
                "action": "log",  # User wants log mode for directory blocking
                "rules": []
            },
            "permissions": []
        }

        checker = ToolPolicyChecker(config=config)

        # AI tries to disable secret scanning
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

        print(f"\nAttempt: Edit ai-guardian.json to disable secret scanning")
        print(f"Result: is_allowed = {is_allowed}")
        print(f"Message preview: {error_msg[:100] if error_msg else 'None'}...")

        # CRITICAL: Must be blocked!
        self.assertFalse(is_allowed, "❌ VULNERABILITY: Config file was allowed to be edited!")
        self.assertIn("Protection:", error_msg)
        self.assertNotIn("log mode", error_msg.lower(), "Must be hard blocked, not log mode")

        print("\n✅ SECURE: Edit was BLOCKED (not allowed with warning)")
        print("="*70)

    def test_scenario_2_permission_rule_with_action_log(self):
        """
        Scenario 2: Attacker adds permission rule with action="log"

        Expected: Immutable patterns override user rules - STILL blocked
        """
        print("\n" + "="*70)
        print("SCENARIO 2: Attacker adds permission rule with action='log'")
        print("="*70)

        config = {
            "permissions": [
                {
                    "matcher": "Edit",
                    "mode": "deny",
                    "patterns": ["*ai-guardian.json"],
                    "action": "log"  # Attacker tries to bypass with log mode
                }
            ]
        }

        checker = ToolPolicyChecker(config=config)

        # AI tries to remove IDE hooks
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

        print(f"\nAttempt: Edit .claude/settings.json to remove ai-guardian hook")
        print(f"Result: is_allowed = {is_allowed}")
        print(f"Message preview: {error_msg[:100] if error_msg else 'None'}...")

        # CRITICAL: Must be blocked!
        self.assertFalse(is_allowed, "❌ VULNERABILITY: IDE hooks were allowed to be edited!")
        self.assertIn("Protection:", error_msg)
        self.assertNotIn("log mode", error_msg.lower(), "Must be hard blocked, not log mode")

        print("\n✅ SECURE: Edit was BLOCKED (immutable patterns override user rules)")
        print("="*70)

    def test_scenario_3_bash_rm_with_action_log(self):
        """
        Scenario 3: User has action="log" and AI tries to delete config with Bash

        Expected: Immutable Bash patterns STILL block
        """
        print("\n" + "="*70)
        print("SCENARIO 3: User has action='log', AI tries 'rm' on config file")
        print("="*70)

        config = {
            "directory_rules": {"action": "log"},
            "permissions": []
        }

        checker = ToolPolicyChecker(config=config)

        # AI tries to delete config file via Bash
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

        print(f"\nAttempt: Bash command 'rm ~/.config/ai-guardian/ai-guardian.json'")
        print(f"Result: is_allowed = {is_allowed}")
        print(f"Message preview: {error_msg[:100] if error_msg else 'None'}...")

        # CRITICAL: Must be blocked!
        self.assertFalse(is_allowed, "❌ VULNERABILITY: Bash rm was allowed!")
        self.assertIn("CRITICAL", error_msg.upper())
        self.assertNotIn("log mode", error_msg.lower(), "Must be hard blocked, not log mode")

        print("\n✅ SECURE: Bash rm was BLOCKED (self-protection active)")
        print("="*70)

    def test_scenario_4_write_marker_file_with_action_log(self):
        """
        Scenario 4: User has action="log" and AI tries to write .ai-read-deny marker

        Expected: Directory protection markers ALWAYS blocked
        """
        print("\n" + "="*70)
        print("SCENARIO 4: User has action='log', AI tries to create .ai-read-deny")
        print("="*70)

        config = {
            "directory_rules": {"action": "log"},
            "permissions": []
        }

        checker = ToolPolicyChecker(config=config)

        # AI tries to create .ai-read-deny marker
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/secrets/.ai-read-deny",
                    "content": ""
                }
            }
        }

        is_allowed, error_msg, tool_name = checker.check_tool_allowed(hook_data)

        print(f"\nAttempt: Write to .ai-read-deny marker file")
        print(f"Result: is_allowed = {is_allowed}")
        print(f"Message preview: {error_msg[:100] if error_msg else 'None'}...")

        # CRITICAL: Must be blocked!
        self.assertFalse(is_allowed, "❌ VULNERABILITY: .ai-read-deny marker was allowed!")
        self.assertIn("Protection:", error_msg)
        self.assertIn("Directory protection marker", error_msg)
        self.assertNotIn("log mode", error_msg.lower(), "Must be hard blocked, not log mode")

        print("\n✅ SECURE: Write was BLOCKED (directory markers protected)")
        print("="*70)

    def test_scenario_5_comparison_with_normal_file(self):
        """
        Scenario 5: For comparison - normal files ARE allowed

        Shows that self-protection is selective, not breaking all edits
        """
        print("\n" + "="*70)
        print("SCENARIO 5: For comparison - editing normal user files")
        print("="*70)

        config = {
            "directory_rules": {"action": "log"},
            "permissions": []
        }

        checker = ToolPolicyChecker(config=config)

        # AI tries to edit a normal project file
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/my-project/src/main.py",
                    "old_string": "DEBUG = False",
                    "new_string": "DEBUG = True"
                }
            }
        }

        is_allowed, error_msg, tool_name = checker.check_tool_allowed(hook_data)

        print(f"\nAttempt: Edit normal project file /home/user/my-project/src/main.py")
        print(f"Result: is_allowed = {is_allowed}")
        print(f"Message: {error_msg if error_msg else 'None (allowed)'}")

        # Normal files ARE allowed
        self.assertTrue(is_allowed, "Normal files should be editable")
        self.assertIsNone(error_msg, "No error for normal files")

        print("\n✅ ALLOWED: Normal project files can still be edited")
        print("   (Self-protection is selective - only protects critical files)")
        print("="*70)


if __name__ == "__main__":
    # Run with verbose output to see the demonstration
    unittest.main(verbosity=2)
