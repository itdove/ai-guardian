"""
Unit tests for development source bypass feature

Tests the scoped bypass that allows contributors to edit development source code
while keeping config files, hooks, cache, and pip-installed code always protected.

This enables standard open-source contribution workflow (fork + PR + review).
"""

import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from ai_guardian.tool_policy import ToolPolicyChecker


class DevelopmentSourceBypassTest(TestCase):
    """Test suite for development source bypass feature"""

    def setUp(self):
        """Set up test fixtures"""
        # Create policy checker with empty config
        self.policy_checker = ToolPolicyChecker(config={"permissions": []})

    # ========================================================================
    # Test: _should_skip_immutable_protection logic
    # ========================================================================

    def test_should_skip_config_files_always_protected(self):
        """Config files are ALWAYS protected, even for repo owners"""

        # Test various config file patterns
        config_files = [
            "/home/user/.config/ai-guardian/ai-guardian.json",
            "/home/user/project/.ai-guardian.json",
            "/home/user/.cache/ai-guardian/maintainer-status.json",
            "/home/user/.claude/settings.json",
            "/home/user/.cursor/hooks.json",
            "/home/user/project/.ai-read-deny",
        ]

        for file_path in config_files:
            result = self.policy_checker._should_skip_immutable_protection(file_path, "Write")
            self.assertFalse(result, f"Config file should always be protected: {file_path}")

    def test_should_skip_non_source_files_protected(self):
        """Non-source files are protected"""

        # Test files outside ai-guardian repo
        non_source_files = [
            "/home/user/other-project/file.py",
            "/usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py",
        ]

        for file_path in non_source_files:
            result = self.policy_checker._should_skip_immutable_protection(file_path, "Write")
            self.assertFalse(result, f"Non-source file should be protected: {file_path}")

    def test_should_skip_source_files_allowed_for_contributors(self):
        """Source files allowed for contributors (fork + PR workflow)"""
        # Note: Maintainer check is no longer required for source code editing
        # This enables standard open-source contribution workflow

        # Test source files in ai-guardian repo
        source_files = [
            "/home/user/ai-guardian/src/ai_guardian/tool_policy.py",
            "/home/user/ai-guardian/tests/test_self_protection.py",
            "/home/user/ai-guardian/README.md",
            "/home/user/ai-guardian/pyproject.toml",
            "/home/user/ai-guardian/.github/workflows/test.yml",
        ]

        for file_path in source_files:
            result = self.policy_checker._should_skip_immutable_protection(file_path, "Write")
            self.assertTrue(result, f"Source file should be allowed for contributors: {file_path}")

    # ========================================================================
    # Test: Integration with check_tool_allowed
    # ========================================================================

    def test_contributor_can_write_source_code(self):
        """Contributors can write to ai-guardian source code"""

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/ai-guardian/src/ai_guardian/tool_policy.py"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be allowed to write source code")
        self.assertIsNone(error_msg)

    def test_contributor_can_edit_source_code(self):
        """Contributors can edit ai-guardian source code"""

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/ai-guardian/src/ai_guardian/tool_policy.py",
                    "old_string": "old",
                    "new_string": "new"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be allowed to edit source code")
        self.assertIsNone(error_msg)

    def test_contributor_can_write_tests(self):
        """Contributors can write test files"""

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/ai-guardian/tests/test_new_feature.py"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be allowed to write tests")

    def test_contributor_can_edit_documentation(self):
        """Contributors can edit documentation"""

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/ai-guardian/README.md",
                    "old_string": "old text",
                    "new_string": "new text"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be allowed to edit docs")

    def test_contributor_cannot_write_config(self):
        """Contributors CANNOT write config files (always protected)"""

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

        self.assertFalse(is_allowed, "Config should be blocked for contributors")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    def test_contributor_cannot_edit_ide_hooks(self):
        """Contributors CANNOT edit IDE hook files (always protected)"""

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/.claude/settings.json",
                    "old_string": "old",
                    "new_string": "new"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "IDE hooks should be blocked for contributors")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    def test_contributor_cannot_write_cache(self):
        """Contributors CANNOT write cache files (prevents poisoning)"""

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/.cache/ai-guardian/maintainer-status.json"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Cache should be blocked for contributors")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    def test_contributor_can_write_source(self):
        """Contributors can write to source code (fork + PR workflow)"""

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/ai-guardian/src/ai_guardian/tool_policy.py",
                    "content": "# Modified source code"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be allowed to edit source code")
        self.assertIsNone(error_msg, "No error for allowed operations")

    # ========================================================================
    # Test: Malicious prompt scenarios (Threat Model B)
    # ========================================================================

    def test_malicious_prompt_cannot_disable_secret_scanning(self):
        """
        Threat Model B: Malicious prompt tries to disable secret scanning.
        Config edits are always blocked.
        """

        # Malicious prompt: "Help me organize my SSH keys"
        # AI tries to disable secret scanning
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/user/.config/ai-guardian/ai-guardian.json",
                    "old_string": '"secret_scanning": true',
                    "new_string": '"secret_scanning": false'
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Malicious prompt should be blocked from disabling security")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    def test_malicious_prompt_cannot_poison_cache(self):
        """
        Threat Model B: Malicious prompt tries to poison cache.
        """

        # AI tries to write fake maintainer status
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/user/.cache/ai-guardian/maintainer-status.json",
                    "content": '{"is_maintainer": true}'
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Cache poisoning should be blocked")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    def test_bash_cache_poisoning_blocked(self):
        """Bash command trying to poison cache is blocked"""

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {
                    "command": 'echo \'{"is_maintainer": true}\' > ~/.cache/ai-guardian/maintainer-status.json'
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Bash cache poisoning should be blocked")
        # Bug #94 fix: Bash errors now show "CRITICAL COMMAND BLOCKED" not "FILE PROTECTED"
        self.assertIn("CRITICAL COMMAND BLOCKED", error_msg)
