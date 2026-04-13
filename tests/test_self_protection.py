"""
Unit tests for ai-guardian self-protection feature (Issue #32)

Tests the IMMUTABLE_DENY_PATTERNS that protect:
- ai-guardian configuration files
- IDE hook configuration files (Claude, Cursor)
- ai-guardian package source code
"""

import json
from unittest import TestCase
from ai_guardian.tool_policy import ToolPolicyChecker


class SelfProtectionTest(TestCase):
    """Test suite for self-protection feature"""

    def setUp(self):
        """Set up test fixtures"""
        # Create policy checker with empty config (no user-configured permissions)
        # This ensures we're only testing the immutable deny patterns
        self.policy_checker = ToolPolicyChecker(config={"permissions": []})

    # ========================================================================
    # Test: AI cannot modify ai-guardian config files (Write tool)
    # ========================================================================

    def test_write_blocks_user_config_file(self):
        """AI cannot write to ~/.config/ai-guardian/ai-guardian.json"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/.config/ai-guardian/ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to ai-guardian config should be blocked")
        self.assertIsNotNone(error_msg, "Error message should be provided")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)
        self.assertIn("ai-guardian configuration", error_msg)

    def test_write_blocks_project_config_file(self):
        """AI cannot write to project .ai-guardian.json"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/my-project/.ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to project config should be blocked")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    def test_write_blocks_any_ai_guardian_json(self):
        """AI cannot write to any *ai-guardian.json file"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/tmp/test-ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to any ai-guardian.json should be blocked")

    # ========================================================================
    # Test: AI cannot modify IDE hook files (Write tool)
    # ========================================================================

    def test_write_blocks_claude_settings(self):
        """AI cannot write to ~/.claude/settings.json"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/.claude/settings.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to Claude settings should be blocked")
        self.assertIn("IDE hook configuration", error_msg)

    def test_write_blocks_cursor_hooks(self):
        """AI cannot write to ~/.cursor/hooks.json"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/.cursor/hooks.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to Cursor hooks should be blocked")

    def test_write_blocks_windows_claude_settings(self):
        """AI cannot write to Windows Claude settings"""
        # Python normalizes Windows paths to forward slashes on most operations
        # So we test with the normalized form
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "C:/Users/user/AppData/Roaming/Claude/settings.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to Windows Claude settings should be blocked")

    # ========================================================================
    # Test: AI cannot modify package source code (Write tool)
    # ========================================================================

    def test_write_blocks_package_source_site_packages(self):
        """AI cannot write to site-packages/ai_guardian/"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to package source should be blocked")
        self.assertIn("package source code", error_msg)

    def test_write_blocks_package_source_src(self):
        """AI cannot write to src/ai_guardian/"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/ai-guardian/src/ai_guardian/__main__.py"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to source code should be blocked")

    # ========================================================================
    # Test: AI cannot modify config files (Edit tool)
    # ========================================================================

    def test_edit_blocks_user_config_file(self):
        """AI cannot edit ~/.config/ai-guardian/ai-guardian.json"""
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

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Edit of ai-guardian config should be blocked")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    def test_edit_blocks_claude_settings(self):
        """AI cannot edit ~/.claude/settings.json"""
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

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Edit of Claude settings should be blocked")

    def test_edit_blocks_package_source(self):
        """AI cannot edit package source code"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py",
                    "old_string": "IMMUTABLE_DENY_PATTERNS",
                    "new_string": "DISABLED"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Edit of package source should be blocked")

    # ========================================================================
    # Test: AI cannot bypass via Bash sed/awk
    # ========================================================================

    def test_bash_blocks_sed_on_config(self):
        """AI cannot use sed to modify ai-guardian config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "sed -i 's/enabled\":true/enabled\":false/' ~/.config/ai-guardian/ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash sed on config should be blocked")

    def test_bash_blocks_awk_on_config(self):
        """AI cannot use awk to modify ai-guardian config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "awk '{gsub(/enabled\":true/, \"enabled\":false\")}1' ai-guardian.json > tmp && mv tmp ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash awk on config should be blocked")

    def test_bash_blocks_sed_on_claude_settings(self):
        """AI cannot use sed to modify Claude settings"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "sed -i 's/ai-guardian//' ~/.claude/settings.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash sed on Claude settings should be blocked")

    def test_bash_blocks_sed_on_package_source(self):
        """AI cannot use sed to modify package source"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "sed -i 's/IMMUTABLE/DISABLED/' /usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash sed on package source should be blocked")

    # ========================================================================
    # Test: AI cannot bypass via Bash vim/nano
    # ========================================================================

    def test_bash_blocks_vim_on_claude_settings(self):
        """AI cannot use vim to edit Claude settings"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "vim ~/.claude/settings.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash vim on Claude settings should be blocked")

    def test_bash_blocks_nano_on_cursor_hooks(self):
        """AI cannot use nano to edit Cursor hooks"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "nano ~/.cursor/hooks.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash nano on Cursor hooks should be blocked")

    # ========================================================================
    # Test: AI cannot bypass via Bash echo/cat redirect
    # ========================================================================

    def test_bash_blocks_echo_redirect_to_config(self):
        """AI cannot use echo redirect to overwrite config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "echo '{}' > ~/.config/ai-guardian/ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash echo redirect to config should be blocked")

    def test_bash_blocks_redirect_to_claude_settings(self):
        """AI cannot use redirect to overwrite Claude settings"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "cat /dev/null > ~/.claude/settings.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash redirect to Claude settings should be blocked")

    # ========================================================================
    # Test: AI cannot bypass via Bash rm/mv
    # ========================================================================

    def test_bash_blocks_rm_config(self):
        """AI cannot use rm to delete config files"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "rm ~/.config/ai-guardian/ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash rm of config should be blocked")

    def test_bash_blocks_rm_claude_settings(self):
        """AI cannot use rm to delete Claude settings"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "rm -f ~/.claude/settings.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash rm of Claude settings should be blocked")

    def test_bash_blocks_mv_config(self):
        """AI cannot use mv to move/rename config files"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "mv ~/.config/ai-guardian/ai-guardian.json /tmp/backup.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash mv of config should be blocked")

    # ========================================================================
    # Test: AI cannot bypass via Bash chmod/chattr
    # ========================================================================

    def test_bash_blocks_chmod_on_config(self):
        """AI cannot use chmod on config files"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "chmod 777 ~/.config/ai-guardian/ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash chmod on config should be blocked")

    def test_bash_blocks_chattr_on_claude_settings(self):
        """AI cannot use chattr on Claude settings"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "chattr -i ~/.claude/settings.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash chattr on Claude settings should be blocked")

    # ========================================================================
    # Test: Non-protected files are allowed
    # ========================================================================

    def test_write_allows_normal_files(self):
        """AI can write to normal files"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/my-project/src/main.py"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Write to normal files should be allowed")
        self.assertIsNone(error_msg, "No error message for allowed operation")

    def test_edit_allows_normal_files(self):
        """AI can edit normal files"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/my-project/README.md",
                    "old_string": "old",
                    "new_string": "new"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Edit of normal files should be allowed")

    def test_bash_allows_normal_commands(self):
        """AI can use Bash for normal commands"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "ls -la /home/user/my-project"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Normal Bash commands should be allowed")

    # ========================================================================
    # Test: Error messages are clear
    # ========================================================================

    def test_error_message_format(self):
        """Error messages should be clear and helpful"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/.claude/settings.json",
                    "old_string": "test",
                    "new_string": "test2"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        # Check error message contains all required elements
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)
        self.assertIn("/home/user/.claude/settings.json", error_msg)
        self.assertIn("Edit", error_msg)
        self.assertIn("ai-guardian configuration", error_msg)
        self.assertIn("IDE hook configuration", error_msg)
        self.assertIn("package source code", error_msg)
        self.assertIn("cannot be disabled via configuration", error_msg)
        self.assertIn("use your text editor manually", error_msg)


if __name__ == '__main__':
    import unittest
    unittest.main()
