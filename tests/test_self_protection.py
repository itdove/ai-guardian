"""
Unit tests for ai-guardian self-protection feature (Issue #32)

Tests the IMMUTABLE_DENY_PATTERNS that protect:
- ai-guardian configuration files
- IDE hook configuration files (Claude, Cursor)
- ai-guardian package source code
"""

import json
from unittest import TestCase
from unittest.mock import patch
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

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_write_allows_development_source_for_contributors(self, mock_is_maintainer):
        """Contributors can write to development src/ai_guardian/ (fork + PR workflow)"""
        mock_is_maintainer.return_value = False

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/ai-guardian/src/ai_guardian/__main__.py",
                    "content": "# Modified source"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be able to write development source code")
        self.assertIsNone(error_msg, "No error for allowed operations")

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
    # Test: Edge cases - User directories with 'ai_guardian' in path (Issue #47)
    # ========================================================================

    def test_write_allows_user_project_with_ai_guardian_in_name(self):
        """AI can write to user project that has 'ai_guardian' in directory name"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/my_ai_guardian_project/src/main.py"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Write to user project with 'ai_guardian' in name should be allowed")
        self.assertIsNone(error_msg, "No error message for allowed operation")

    def test_write_allows_backup_directory_with_ai_guardian(self):
        """AI can write to backup directory with 'ai_guardian' in name"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/backup_ai_guardian_configs/settings.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Write to backup directory with 'ai_guardian' should be allowed")
        self.assertIsNone(error_msg)

    def test_write_allows_tutorial_directory_with_ai_guardian(self):
        """AI can write to tutorial directory with 'ai_guardian' in name"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/projects/ai_guardian_tutorial/example.py"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Write to tutorial directory with 'ai_guardian' should be allowed")

    def test_write_still_blocks_site_packages(self):
        """AI cannot write to site-packages/ai_guardian/ (verify protection still works)"""
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

        self.assertFalse(is_allowed, "Write to site-packages/ai_guardian should still be blocked")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_write_allows_development_source_for_contributors_init(self, mock_is_maintainer):
        """Contributors can write to ai-guardian/src/ai_guardian/ (fork + PR workflow)"""
        mock_is_maintainer.return_value = False

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/ai-guardian/src/ai_guardian/__init__.py",
                    "content": "# Modified source"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be able to write development source")
        self.assertIsNone(error_msg, "No error for allowed operations")

    def test_edit_allows_user_project_with_ai_guardian_in_name(self):
        """AI can edit files in user project with 'ai_guardian' in directory name"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/my_ai_guardian_project/config.py",
                    "old_string": "DEBUG = False",
                    "new_string": "DEBUG = True"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Edit of user project with 'ai_guardian' in name should be allowed")

    def test_bash_allows_sed_on_user_project_with_ai_guardian(self):
        """AI can use sed on user project with 'ai_guardian' in directory name"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "sed -i 's/old/new/' /home/user/my_ai_guardian_project/config.py"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Bash sed on user project with 'ai_guardian' should be allowed")

    def test_bash_still_blocks_sed_on_site_packages(self):
        """AI cannot use sed on site-packages/ai_guardian/"""
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

        self.assertFalse(is_allowed, "Bash sed on site-packages/ai_guardian should still be blocked")

    # ========================================================================
    # Test: AI cannot modify .ai-read-deny marker files (Write tool)
    # ========================================================================

    def test_write_blocks_ai_read_deny_marker(self):
        """AI cannot write to .ai-read-deny marker file"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/secrets/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to .ai-read-deny should be blocked")
        self.assertIsNotNone(error_msg, "Error message should be provided")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)
        self.assertIn(".ai-read-deny", error_msg)
        self.assertIn("Directory protection marker", error_msg)

    def test_write_blocks_ai_read_deny_absolute_path(self):
        """AI cannot write to .ai-read-deny with absolute path"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/var/lib/sensitive/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to .ai-read-deny (absolute) should be blocked")
        self.assertIn("Directory protection marker", error_msg)

    def test_write_blocks_ai_read_deny_nested_path(self):
        """AI cannot write to .ai-read-deny in nested directories"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/project/a/b/c/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Write to .ai-read-deny (nested) should be blocked")

    # ========================================================================
    # Test: AI cannot modify .ai-read-deny marker files (Edit tool)
    # ========================================================================

    def test_edit_blocks_ai_read_deny_marker(self):
        """AI cannot edit .ai-read-deny marker file"""
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

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Edit of .ai-read-deny should be blocked")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)
        self.assertIn("Directory protection marker", error_msg)

    # ========================================================================
    # Test: AI cannot bypass via Bash rm
    # ========================================================================

    def test_bash_blocks_rm_ai_read_deny(self):
        """AI cannot use rm to delete .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "rm /home/user/secrets/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash rm of .ai-read-deny should be blocked")

    def test_bash_blocks_rm_ai_read_deny_relative(self):
        """AI cannot use rm to delete .ai-read-deny (relative path)"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "rm secrets/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash rm of .ai-read-deny (relative) should be blocked")

    def test_bash_blocks_rm_rf_ai_read_deny(self):
        """AI cannot use rm -rf to delete .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "rm -rf /home/user/project/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash rm -rf of .ai-read-deny should be blocked")

    # ========================================================================
    # Test: AI cannot bypass via Bash mv
    # ========================================================================

    def test_bash_blocks_mv_ai_read_deny(self):
        """AI cannot use mv to move/rename .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "mv /home/user/secrets/.ai-read-deny /tmp/backup"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash mv of .ai-read-deny should be blocked")

    def test_bash_blocks_mv_ai_read_deny_rename(self):
        """AI cannot use mv to rename .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "mv .ai-read-deny .ai-read-deny.bak"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash mv rename of .ai-read-deny should be blocked")

    # ========================================================================
    # Test: AI cannot bypass via Bash sed/awk
    # ========================================================================

    def test_bash_blocks_sed_ai_read_deny(self):
        """AI cannot use sed on .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "sed -i 's/test/new/' /home/user/secrets/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash sed on .ai-read-deny should be blocked")

    def test_bash_blocks_awk_ai_read_deny(self):
        """AI cannot use awk on .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "awk '{print}' .ai-read-deny > /tmp/out"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash awk on .ai-read-deny should be blocked")

    # ========================================================================
    # Test: AI cannot bypass via Bash echo redirect
    # ========================================================================

    def test_bash_blocks_echo_redirect_ai_read_deny(self):
        """AI cannot use echo redirect to overwrite .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "echo '' > /home/user/secrets/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash echo redirect to .ai-read-deny should be blocked")

    def test_bash_blocks_cat_redirect_ai_read_deny(self):
        """AI cannot use cat redirect to overwrite .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "cat /dev/null > .ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash cat redirect to .ai-read-deny should be blocked")

    # ========================================================================
    # Test: AI cannot bypass via Bash chmod/chattr
    # ========================================================================

    def test_bash_blocks_chmod_ai_read_deny(self):
        """AI cannot use chmod on .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "chmod 777 /home/user/secrets/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash chmod on .ai-read-deny should be blocked")

    def test_bash_blocks_chattr_ai_read_deny(self):
        """AI cannot use chattr on .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "chattr +i /home/user/secrets/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash chattr on .ai-read-deny should be blocked")

    # ========================================================================
    # Test: AI cannot bypass via Bash vim/nano
    # ========================================================================

    def test_bash_blocks_vim_ai_read_deny(self):
        """AI cannot use vim to edit .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "vim /home/user/secrets/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash vim on .ai-read-deny should be blocked")

    def test_bash_blocks_nano_ai_read_deny(self):
        """AI cannot use nano to edit .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": "nano .ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash nano on .ai-read-deny should be blocked")

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
        self.assertIn(".ai-read-deny marker files", error_msg)
        self.assertIn("cannot be disabled via configuration", error_msg)
        self.assertIn("use your text editor manually", error_msg)

    def test_error_message_marker_file_format(self):
        """Error message for .ai-read-deny should mention directory protection"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/secrets/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        # Check error message contains marker-file-specific elements
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)
        self.assertIn("/home/user/secrets/.ai-read-deny", error_msg)
        self.assertIn("Write", error_msg)
        self.assertIn("Directory protection marker", error_msg)
        self.assertIn(".ai-read-deny marker files (directory protection)", error_msg)
        self.assertIn("directory protection cannot be bypassed", error_msg)
        self.assertIn("delete .ai-read-deny manually", error_msg)

    # ========================================================================
    # Test: Workaround tip for documentation files (Issue #65)
    # ========================================================================

    def test_error_message_includes_workaround_tip_for_write_protected_md_file(self):
        """Error message includes tip when writing to protected .md file with ai-guardian in name"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/project/.config/ai-guardian/docs/setup.md"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed)
        self.assertIn("💡 TIP", error_msg)
        self.assertIn("ai - guardian", error_msg)
        self.assertIn("with spaces", error_msg)
        self.assertIn("trying to write ABOUT the tool", error_msg)

    def test_error_message_for_pip_installed_readme(self):
        """Error message for pip-installed README explains it's production code"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/usr/lib/python3.12/site-packages/ai_guardian/README.md",
                    "old_string": "old",
                    "new_string": "new"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed)
        # Should explain this is pip-installed production code
        self.assertIn("Pip-installed", error_msg)
        self.assertIn("production deployment", error_msg)
        # Should provide guidance on how to develop
        self.assertIn("git clone", error_msg)
        self.assertIn("Development source files CAN be edited", error_msg)

    def test_error_message_includes_workaround_tip_for_protected_txt_in_docs(self):
        """Error message includes tip for protected .txt file with ai-guardian in path"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/.config/ai-guardian/README.txt"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed)
        self.assertIn("💡 TIP", error_msg)

    def test_error_message_no_tip_for_protected_config_file(self):
        """Error message should NOT include tip for actual protected config files"""
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

        self.assertFalse(is_allowed)
        self.assertNotIn("💡 TIP", error_msg)
        self.assertNotIn("ai - guardian", error_msg)

    def test_error_message_no_tip_for_protected_python_source(self):
        """Error message should NOT include tip for protected Python source files"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py",
                    "old_string": "old",
                    "new_string": "new"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed)
        self.assertNotIn("💡 TIP", error_msg)

    def test_error_message_no_tip_for_ide_settings_without_ai_guardian(self):
        """Error message should NOT include tip for IDE settings (no ai-guardian in path)"""
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

        self.assertFalse(is_allowed)
        self.assertNotIn("💡 TIP", error_msg)


if __name__ == '__main__':
    import unittest
    unittest.main()
