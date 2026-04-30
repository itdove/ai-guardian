"""
Test contributor workflow - Issue #105 Resolution

Tests that contributors (non-maintainers) can use AI assistance to edit
ai-guardian source code in development repos while critical files remain protected.

Security model:
- Config/hooks/cache: ALWAYS protected (even for repo owners)
- Pip-installed code: ALWAYS protected (production deployment)
- Development source: ALLOWED for contributors (fork + PR workflow)
"""

import unittest
from unittest.mock import patch
from ai_guardian.tool_policy import ToolPolicyChecker


class ContributorWorkflowTest(unittest.TestCase):
    """Test that contributors can edit source code but not critical files"""

    def setUp(self):
        """Set up test fixtures"""
        self.policy_checker = ToolPolicyChecker(config={"permissions": []})

    # ========================================================================
    # Test: Contributors CAN edit development source code
    # ========================================================================

    def test_contributor_can_edit_source_file(self):
        """Contributors can edit source files in development repo"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/alice/ai-guardian/src/ai_guardian/tool_policy.py",
                    "old_string": "old code",
                    "new_string": "new code"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be able to edit development source code")
        self.assertIsNone(error_msg, "No error message for allowed operation")

    def test_contributor_can_edit_test_file(self):
        """Contributors can edit test files in development repo"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/alice/ai-guardian/tests/test_self_protection.py",
                    "old_string": "def test_old()",
                    "new_string": "def test_new()"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be able to edit test files")
        self.assertIsNone(error_msg)

    def test_contributor_can_edit_documentation(self):
        """Contributors can edit documentation in development repo"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/alice/ai-guardian/README.md",
                    "old_string": "## Old Heading",
                    "new_string": "## New Heading"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be able to edit documentation")
        self.assertIsNone(error_msg)

    def test_contributor_can_write_new_test_file(self):
        """Contributors can create new test files"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/alice/ai-guardian/tests/test_new_feature.py",
                    "content": "import unittest\n\nclass NewFeatureTest(unittest.TestCase):\n    pass"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be able to create new test files")

    def test_contributor_can_edit_pyproject_toml(self):
        """Contributors can edit project configuration like pyproject.toml"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/alice/ai-guardian/pyproject.toml",
                    "old_string": 'version = "1.0.0"',
                    "new_string": 'version = "1.1.0"'
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be able to edit pyproject.toml")

    def test_contributor_can_edit_github_workflows(self):
        """Contributors can edit GitHub Actions workflows"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/alice/ai-guardian/.github/workflows/test.yml",
                    "old_string": "python-version: 3.11",
                    "new_string": "python-version: 3.12"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Contributors should be able to edit GitHub workflows")

    # ========================================================================
    # Test: Contributors CANNOT edit config/hooks/cache (security critical)
    # ========================================================================

    def test_contributor_cannot_edit_config_file(self):
        """Contributors CANNOT edit ai-guardian.json (always protected)"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/alice/.config/ai-guardian/ai-guardian.json",
                    "old_string": '"enabled": true',
                    "new_string": '"enabled": false'
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Config files must be protected from contributors")
        self.assertIsNotNone(error_msg)
        self.assertIn("Protection:", error_msg)

    def test_contributor_cannot_edit_claude_settings(self):
        """Contributors CANNOT edit IDE hooks (always protected)"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/home/alice/.claude/settings.json",
                    "old_string": '"ai-guardian"',
                    "new_string": '""'
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "IDE hooks must be protected from contributors")
        self.assertIn("Protection:", error_msg)

    def test_contributor_cannot_edit_cache_file(self):
        """Contributors CANNOT edit cache files (prevents cache poisoning)"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/alice/.cache/ai-guardian/maintainer-status.json",
                    "content": '{"repositories": {}}'
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Cache files must be protected from contributors")
        self.assertIn("Protection:", error_msg)

    def test_contributor_cannot_edit_ai_read_deny_marker(self):
        """Contributors CANNOT edit .ai-read-deny markers"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Write",
                "input": {
                    "file_path": "/home/alice/secrets/.ai-read-deny",
                    "content": ""
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Directory markers must be protected from contributors")
        self.assertIn("Protection:", error_msg)

    # ========================================================================
    # Test: Pip-installed code is ALWAYS protected (production deployment)
    # ========================================================================

    def test_contributor_cannot_edit_site_packages(self):
        """Contributors CANNOT edit pip-installed package code"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    "file_path": "/usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py",
                    "old_string": "IMMUTABLE",
                    "new_string": "DISABLED"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(is_allowed, "Pip-installed code must be protected from contributors")
        self.assertIsNotNone(error_msg)
        self.assertIn("Protection:", error_msg)
        # Should provide helpful error message about pip-installed code
        self.assertIn("Pip-installed", error_msg)

    def test_contributor_cannot_bash_modify_site_packages(self):
        """Contributors CANNOT use Bash to modify pip-installed code"""
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

        self.assertFalse(is_allowed, "Bash modifications of pip-installed code must be blocked")

    # ========================================================================
    # Test: Fork workflow (alice/ai-guardian)
    # ========================================================================

    def test_fork_owner_can_edit_source_in_fork(self):
        """Fork owners can edit source code in their own fork"""
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Edit",
                "input": {
                    # Alice's fork at ~/forks/ai-guardian
                    "file_path": "/home/alice/forks/ai-guardian/src/ai_guardian/__init__.py",
                    "old_string": "version = '1.0.0'",
                    "new_string": "version = '1.1.0'"
                }
            }
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(hook_data)

        self.assertTrue(is_allowed, "Fork owners should be able to edit source in their fork")
        self.assertIsNone(error_msg)

    # ========================================================================
    # Test: Error messages provide helpful guidance
    # ========================================================================

    def test_pip_installed_error_message_helpful(self):
        """Error message for pip-installed code provides helpful guidance"""
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
        # Should explain this is pip-installed code
        self.assertIn("Pip-installed", error_msg)
        # Should explain how to develop properly
        self.assertIn("git clone", error_msg)
        self.assertIn("pip install -e", error_msg)
        # Should clarify development source CAN be edited
        self.assertIn("Development source files CAN be edited", error_msg)


if __name__ == "__main__":
    unittest.main()
