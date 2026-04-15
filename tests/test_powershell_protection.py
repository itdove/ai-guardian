"""
Unit tests for PowerShell tool self-protection (Issue #45)

Tests the IMMUTABLE_DENY_PATTERNS for PowerShell tool that protect:
- ai-guardian configuration files
- IDE hook configuration files (Claude, Cursor)
- ai-guardian package source code
- .ai-read-deny marker files
"""

import json
from unittest import TestCase
from unittest.mock import patch
from ai_guardian.tool_policy import ToolPolicyChecker


class PowerShellProtectionTest(TestCase):
    """Test suite for PowerShell self-protection feature"""

    def setUp(self):
        """Set up test fixtures"""
        # Create policy checker with empty config (no user-configured permissions)
        # This ensures we're only testing the immutable deny patterns
        self.policy_checker = ToolPolicyChecker(config={"permissions": []})

    # ========================================================================
    # Test: PowerShell cannot modify ai-guardian config files
    # ========================================================================

    def test_powershell_blocks_remove_item_config(self):
        """PowerShell Remove-Item blocked for ai-guardian.json"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Remove-Item ~/.config/ai-guardian/ai-guardian.json -Force"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Remove-Item on config should be blocked")
        self.assertIsNotNone(error_msg, "Error message should be provided")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    def test_powershell_blocks_set_content_config(self):
        """PowerShell Set-Content blocked for ai-guardian config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Set-Content -Path ~/.config/ai-guardian/ai-guardian.json -Value '{}'"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Set-Content on config should be blocked")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    def test_powershell_blocks_clear_content_config(self):
        """PowerShell Clear-Content blocked for ai-guardian config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Clear-Content -Path C:\\Users\\user\\.config\\ai-guardian\\ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Clear-Content on config should be blocked")

    def test_powershell_blocks_move_item_config(self):
        """PowerShell Move-Item blocked for ai-guardian config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Move-Item ai-guardian.json ai-guardian.json.bak"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Move-Item on config should be blocked")

    def test_powershell_blocks_rename_item_config(self):
        """PowerShell Rename-Item blocked for ai-guardian config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Rename-Item ai-guardian.json old-config.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Rename-Item on config should be blocked")

    def test_powershell_blocks_out_file_config(self):
        """PowerShell Out-File blocked for ai-guardian config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Get-Content empty.json | Out-File -FilePath ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Out-File on config should be blocked")

    def test_powershell_blocks_copy_item_config(self):
        """PowerShell Copy-Item blocked for ai-guardian config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Copy-Item empty.json ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Copy-Item on config should be blocked")

    # ========================================================================
    # Test: PowerShell cannot modify IDE hook files
    # ========================================================================

    def test_powershell_blocks_remove_item_claude_settings(self):
        """PowerShell Remove-Item blocked for Claude settings"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Remove-Item ~/.claude/settings.json -Force"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Remove-Item on Claude settings should be blocked")
        self.assertIn("IDE hook configuration", error_msg)

    def test_powershell_blocks_set_content_cursor_hooks(self):
        """PowerShell Set-Content blocked for Cursor hooks"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Set-Content -Path ~/.cursor/hooks.json -Value '{}'"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Set-Content on Cursor hooks should be blocked")

    def test_powershell_blocks_clear_content_windows_claude(self):
        """PowerShell Clear-Content blocked for Windows Claude settings"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Clear-Content C:\\Users\\user\\AppData\\Roaming\\Claude\\settings.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Clear-Content on Windows Claude settings should be blocked")

    def test_powershell_blocks_move_item_cursor_hooks(self):
        """PowerShell Move-Item blocked for Cursor hooks"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Move-Item ~/.cursor/hooks.json ~/.cursor/hooks.json.bak"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Move-Item on Cursor hooks should be blocked")

    # ========================================================================
    # Test: PowerShell cannot modify package source
    # ========================================================================

    def test_powershell_blocks_remove_item_package_source(self):
        """PowerShell Remove-Item blocked for package source"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Remove-Item C:\\Python\\Lib\\site-packages\\ai_guardian\\tool_policy.py"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Remove-Item on package source should be blocked")
        self.assertIn("package source code", error_msg)

    def test_powershell_blocks_set_content_package_source(self):
        """PowerShell Set-Content blocked for package source"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Set-Content -Path /usr/lib/python3.12/site-packages/ai_guardian/__main__.py -Value ''"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Set-Content on package source should be blocked")

    # ========================================================================
    # Test: PowerShell redirections blocked
    # ========================================================================

    def test_powershell_blocks_redirect_config(self):
        """PowerShell redirect (>) blocked for ai-guardian config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "echo '{}' > ~/.config/ai-guardian/ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell redirect to config should be blocked")

    def test_powershell_blocks_append_redirect_claude_settings(self):
        """PowerShell append redirect (>>) blocked for Claude settings"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "echo 'data' >> ~/.claude/settings.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell append redirect to Claude settings should be blocked")

    # ========================================================================
    # Test: PowerShell aliases blocked
    # ========================================================================

    def test_powershell_blocks_del_alias_config(self):
        """PowerShell del alias blocked for ai-guardian config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "del ai-guardian.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell del alias on config should be blocked")

    def test_powershell_blocks_rm_alias_claude_settings(self):
        """PowerShell rm alias blocked for Claude settings"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "rm ~/.claude/settings.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell rm alias on Claude settings should be blocked")

    def test_powershell_blocks_move_alias_config(self):
        """PowerShell move alias blocked for ai-guardian config"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "move ai-guardian.json backup.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell move alias on config should be blocked")

    # ========================================================================
    # Test: Edge cases - User directories with 'ai_guardian' in path (Issue #47)
    # ========================================================================

    def test_powershell_allows_user_project_with_ai_guardian_in_name(self):
        """PowerShell can modify user project with 'ai_guardian' in directory name"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Set-Content -Path C:\\Users\\user\\my_ai_guardian_project\\config.py -Value 'test'"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "PowerShell on user project with 'ai_guardian' should be allowed")
        self.assertIsNone(error_msg)

    def test_powershell_allows_remove_item_user_project(self):
        """PowerShell Remove-Item allowed for user project with 'ai_guardian' in name"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Remove-Item /home/user/backup_ai_guardian_configs/old_file.txt"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "PowerShell Remove-Item on user directory with 'ai_guardian' should be allowed")

    def test_powershell_still_blocks_site_packages(self):
        """PowerShell cannot modify site-packages/ai_guardian/ (verify protection)"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Set-Content -Path C:\\Python\\Lib\\site-packages\\ai_guardian\\tool_policy.py -Value ''"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Set-Content on site-packages/ai_guardian should still be blocked")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_powershell_still_blocks_source_repo(self, mock_is_maintainer):
        """PowerShell cannot modify ai-guardian/src/ai_guardian/ (verify protection for non-maintainers)"""
        mock_is_maintainer.return_value = False

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Remove-Item /home/user/ai-guardian/src/ai_guardian/__init__.py"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Remove-Item on ai-guardian/src/ai_guardian should still be blocked")

    # ========================================================================
    # Test: PowerShell cannot modify .ai-read-deny marker files
    # ========================================================================

    def test_powershell_blocks_remove_item_ai_read_deny(self):
        """PowerShell Remove-Item blocked for .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Remove-Item C:\\secrets\\.ai-read-deny -Force"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Remove-Item on .ai-read-deny should be blocked")
        self.assertIn("Directory protection marker", error_msg)

    def test_powershell_blocks_move_item_ai_read_deny(self):
        """PowerShell Move-Item blocked for .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Move-Item /home/user/secrets/.ai-read-deny /tmp/backup"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Move-Item on .ai-read-deny should be blocked")

    def test_powershell_blocks_set_content_ai_read_deny(self):
        """PowerShell Set-Content blocked for .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Set-Content -Path .ai-read-deny -Value 'test'"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Set-Content on .ai-read-deny should be blocked")

    def test_powershell_blocks_clear_content_ai_read_deny(self):
        """PowerShell Clear-Content blocked for .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Clear-Content /var/sensitive/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell Clear-Content on .ai-read-deny should be blocked")

    def test_powershell_blocks_redirect_ai_read_deny(self):
        """PowerShell redirect blocked for .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "echo '' > /home/user/secrets/.ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell redirect to .ai-read-deny should be blocked")

    def test_powershell_blocks_rm_alias_ai_read_deny(self):
        """PowerShell rm alias blocked for .ai-read-deny"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "rm .ai-read-deny"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "PowerShell rm alias on .ai-read-deny should be blocked")

    # ========================================================================
    # Test: Legitimate PowerShell commands allowed
    # ========================================================================

    def test_powershell_allows_normal_commands(self):
        """Legitimate PowerShell commands should be allowed"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Get-ChildItem C:\\Users\\user\\Documents"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Normal PowerShell commands should be allowed")
        self.assertIsNone(error_msg, "No error message for allowed operation")

    def test_powershell_allows_remove_normal_files(self):
        """PowerShell Remove-Item allowed for normal files"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Remove-Item C:\\Users\\user\\Documents\\temp.txt"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "PowerShell Remove-Item on normal files should be allowed")

    def test_powershell_allows_set_content_normal_files(self):
        """PowerShell Set-Content allowed for normal files"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "PowerShell",
                "input": {
                    "command": "Set-Content -Path C:\\project\\README.md -Value 'Hello World'"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "PowerShell Set-Content on normal files should be allowed")


if __name__ == '__main__':
    import unittest
    unittest.main()
