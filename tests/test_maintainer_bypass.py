"""
Unit tests for maintainer bypass feature (Issue #60)

Tests the scoped bypass that allows GitHub maintainers to edit source code
while keeping config files always protected.
"""

import json
import os
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest import TestCase
from unittest.mock import patch, MagicMock
from ai_guardian.tool_policy import ToolPolicyChecker


class MaintainerBypassTest(TestCase):
    """Test suite for maintainer bypass feature"""

    def setUp(self):
        """Set up test fixtures"""
        # Create policy checker with empty config
        self.policy_checker = ToolPolicyChecker(config={"permissions": []})

    # ========================================================================
    # Test: GitHub maintainer check methods
    # ========================================================================

    @patch('subprocess.run')
    def test_get_git_repo_info_https_url(self, mock_run):
        """Extract owner/repo from HTTPS git URL"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="https://github.com/itdove/ai-guardian.git\n"
        )

        result = self.policy_checker._get_git_repo_info()

        self.assertEqual(result, ("itdove", "ai-guardian"))

    @patch('subprocess.run')
    def test_get_git_repo_info_ssh_url(self, mock_run):
        """Extract owner/repo from SSH git URL"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="git@github.com:itdove/ai-guardian.git\n"
        )

        result = self.policy_checker._get_git_repo_info()

        self.assertEqual(result, ("itdove", "ai-guardian"))

    @patch('subprocess.run')
    def test_get_git_repo_info_no_dotgit(self, mock_run):
        """Extract owner/repo from URL without .git suffix"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="https://github.com/itdove/ai-guardian\n"
        )

        result = self.policy_checker._get_git_repo_info()

        self.assertEqual(result, ("itdove", "ai-guardian"))

    @patch('subprocess.run')
    def test_get_git_repo_info_not_github(self, mock_run):
        """Return None for non-GitHub repos"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="https://gitlab.com/user/repo.git\n"
        )

        result = self.policy_checker._get_git_repo_info()

        self.assertIsNone(result)

    @patch('subprocess.run')
    def test_get_git_repo_info_not_git_repo(self, mock_run):
        """Return None if not a git repository"""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        result = self.policy_checker._get_git_repo_info()

        self.assertIsNone(result)

    @patch('subprocess.run')
    def test_get_authenticated_github_user(self, mock_run):
        """Get GitHub username from gh CLI"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="itdove\n"
        )

        result = self.policy_checker._get_authenticated_github_user()

        self.assertEqual(result, "itdove")

    @patch('subprocess.run')
    def test_get_authenticated_github_user_not_authenticated(self, mock_run):
        """Return None if gh CLI not authenticated"""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        result = self.policy_checker._get_authenticated_github_user()

        self.assertIsNone(result)

    @patch('subprocess.run')
    def test_check_github_collaborator_is_maintainer(self, mock_run):
        """Return True if user is a collaborator"""
        mock_run.return_value = MagicMock(returncode=0)

        result = self.policy_checker._check_github_collaborator("itdove", "ai-guardian", "itdove")

        self.assertTrue(result)

    @patch('subprocess.run')
    def test_check_github_collaborator_not_maintainer(self, mock_run):
        """Return False if user is not a collaborator"""
        mock_run.return_value = MagicMock(returncode=1)

        result = self.policy_checker._check_github_collaborator("itdove", "ai-guardian", "random-user")

        self.assertFalse(result)

    # ========================================================================
    # Test: Maintainer cache
    # ========================================================================

    @patch.object(Path, 'exists')
    @patch('builtins.open')
    @patch.object(ToolPolicyChecker, '_get_git_repo_info')
    def test_get_maintainer_cache_valid(self, mock_repo_info, mock_open, mock_exists):
        """Return cached status if not expired"""
        mock_repo_info.return_value = ("itdove", "ai-guardian")
        mock_exists.return_value = True

        # Create cache data that's 1 hour old
        cache_time = datetime.now(timezone.utc) - timedelta(hours=1)
        cache_data = {
            "version": 1,
            "ttl_hours": 24,
            "repositories": {
                "itdove/ai-guardian": {
                    "username": "itdove",
                    "is_maintainer": True,
                    "checked_at": cache_time.isoformat()
                }
            }
        }

        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(cache_data)

        result = self.policy_checker._get_maintainer_cache()

        self.assertTrue(result)

    @patch.object(Path, 'exists')
    @patch('builtins.open')
    @patch.object(ToolPolicyChecker, '_get_git_repo_info')
    def test_get_maintainer_cache_expired(self, mock_repo_info, mock_open, mock_exists):
        """Return None if cache expired"""
        mock_repo_info.return_value = ("itdove", "ai-guardian")
        mock_exists.return_value = True

        # Create cache data that's 25 hours old (expired)
        cache_time = datetime.now(timezone.utc) - timedelta(hours=25)
        cache_data = {
            "version": 1,
            "ttl_hours": 24,
            "repositories": {
                "itdove/ai-guardian": {
                    "username": "itdove",
                    "is_maintainer": True,
                    "checked_at": cache_time.isoformat()
                }
            }
        }

        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(cache_data)

        result = self.policy_checker._get_maintainer_cache()

        self.assertIsNone(result)

    @patch.object(Path, 'exists')
    def test_get_maintainer_cache_not_exists(self, mock_exists):
        """Return None if cache file doesn't exist"""
        mock_exists.return_value = False

        result = self.policy_checker._get_maintainer_cache()

        self.assertIsNone(result)

    # ========================================================================
    # Test: _should_skip_immutable_protection logic
    # ========================================================================

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_should_skip_config_files_always_protected(self, mock_is_maintainer):
        """Config files are ALWAYS protected, even for maintainers"""
        mock_is_maintainer.return_value = True

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

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_should_skip_non_source_files_protected(self, mock_is_maintainer):
        """Non-source files are protected even for maintainers"""
        mock_is_maintainer.return_value = True

        # Test files outside ai-guardian repo
        non_source_files = [
            "/home/user/other-project/file.py",
            "/usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py",
        ]

        for file_path in non_source_files:
            result = self.policy_checker._should_skip_immutable_protection(file_path, "Write")
            self.assertFalse(result, f"Non-source file should be protected: {file_path}")

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_should_skip_source_files_allowed_for_maintainers(self, mock_is_maintainer):
        """Source files allowed for maintainers"""
        mock_is_maintainer.return_value = True

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
            self.assertTrue(result, f"Source file should be allowed for maintainers: {file_path}")

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_should_skip_source_files_blocked_for_non_maintainers(self, mock_is_maintainer):
        """Source files blocked for non-maintainers"""
        mock_is_maintainer.return_value = False

        # Test source files in ai-guardian repo
        source_files = [
            "/home/user/ai-guardian/src/ai_guardian/tool_policy.py",
            "/home/user/ai-guardian/tests/test_self_protection.py",
        ]

        for file_path in source_files:
            result = self.policy_checker._should_skip_immutable_protection(file_path, "Write")
            self.assertFalse(result, f"Source file should be blocked for non-maintainers: {file_path}")

    # ========================================================================
    # Test: Integration with check_tool_allowed
    # ========================================================================

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_maintainer_can_write_source_code(self, mock_is_maintainer):
        """Maintainer can write to ai-guardian source code"""
        mock_is_maintainer.return_value = True

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

        self.assertTrue(is_allowed, "Maintainer should be allowed to write source code")
        self.assertIsNone(error_msg)

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_maintainer_can_edit_source_code(self, mock_is_maintainer):
        """Maintainer can edit ai-guardian source code"""
        mock_is_maintainer.return_value = True

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

        self.assertTrue(is_allowed, "Maintainer should be allowed to edit source code")
        self.assertIsNone(error_msg)

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_maintainer_can_write_tests(self, mock_is_maintainer):
        """Maintainer can write test files"""
        mock_is_maintainer.return_value = True

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

        self.assertTrue(is_allowed, "Maintainer should be allowed to write tests")

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_maintainer_can_edit_documentation(self, mock_is_maintainer):
        """Maintainer can edit documentation"""
        mock_is_maintainer.return_value = True

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

        self.assertTrue(is_allowed, "Maintainer should be allowed to edit docs")

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_maintainer_cannot_write_config(self, mock_is_maintainer):
        """Maintainer CANNOT write config files (always protected)"""
        mock_is_maintainer.return_value = True

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

        self.assertFalse(is_allowed, "Config should be blocked even for maintainers")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_maintainer_cannot_edit_ide_hooks(self, mock_is_maintainer):
        """Maintainer CANNOT edit IDE hook files (always protected)"""
        mock_is_maintainer.return_value = True

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

        self.assertFalse(is_allowed, "IDE hooks should be blocked even for maintainers")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_maintainer_cannot_write_cache(self, mock_is_maintainer):
        """Maintainer CANNOT write cache files (prevents poisoning)"""
        mock_is_maintainer.return_value = True

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

        self.assertFalse(is_allowed, "Cache should be blocked even for maintainers")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_non_maintainer_cannot_write_source(self, mock_is_maintainer):
        """Non-maintainer cannot write to source code"""
        mock_is_maintainer.return_value = False

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

        self.assertFalse(is_allowed, "Non-maintainer should be blocked from source code")
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    # ========================================================================
    # Test: Malicious prompt scenarios (Threat Model B)
    # ========================================================================

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_malicious_prompt_cannot_disable_secret_scanning(self, mock_is_maintainer):
        """
        Threat Model B: Malicious prompt tries to disable secret scanning.
        Even if user is maintainer, config edits are blocked.
        """
        mock_is_maintainer.return_value = True

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

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_malicious_prompt_cannot_poison_cache(self, mock_is_maintainer):
        """
        Threat Model B: Malicious prompt tries to poison maintainer cache.
        """
        mock_is_maintainer.return_value = False

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

    @patch.object(ToolPolicyChecker, '_is_github_maintainer_cached')
    def test_bash_cache_poisoning_blocked(self, mock_is_maintainer):
        """Bash command trying to poison cache is blocked"""
        mock_is_maintainer.return_value = False

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
        self.assertIn("CRITICAL FILE PROTECTED", error_msg)

    # ========================================================================
    # Test: Retry logic and improved error handling (Issue #68)
    # ========================================================================

    @patch('subprocess.run')
    def test_github_collaborator_check_retries_on_timeout(self, mock_run):
        """GitHub API check should retry on timeout"""
        # First attempt times out, second succeeds
        mock_run.side_effect = [
            subprocess.TimeoutExpired(cmd=['gh', 'api'], timeout=10),
            MagicMock(returncode=0)  # Success on retry
        ]

        with patch('time.sleep'):  # Don't actually sleep in tests
            result = self.policy_checker._check_github_collaborator("owner", "repo", "user")

        self.assertTrue(result)
        self.assertEqual(mock_run.call_count, 2, "Should retry once after timeout")

    @patch('subprocess.run')
    def test_github_collaborator_check_retries_on_error(self, mock_run):
        """GitHub API check should retry on general errors"""
        # First attempt fails, second succeeds
        mock_run.side_effect = [
            Exception("Network error"),
            MagicMock(returncode=0)  # Success on retry
        ]

        with patch('time.sleep'):  # Don't actually sleep in tests
            result = self.policy_checker._check_github_collaborator("owner", "repo", "user")

        self.assertTrue(result)
        self.assertEqual(mock_run.call_count, 2, "Should retry once after error")

    @patch('subprocess.run')
    def test_github_collaborator_check_fails_after_max_retries(self, mock_run):
        """GitHub API check should fail after max retries"""
        # Both attempts time out
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=['gh', 'api'], timeout=10)

        with patch('time.sleep'):  # Don't actually sleep in tests
            result = self.policy_checker._check_github_collaborator("owner", "repo", "user")

        self.assertFalse(result)
        self.assertEqual(mock_run.call_count, 2, "Should try twice then give up")

    @patch.object(Path, 'exists')
    @patch('builtins.open')
    @patch.object(ToolPolicyChecker, '_get_git_repo_info')
    def test_get_maintainer_cache_handles_corrupt_json(self, mock_repo_info, mock_open, mock_exists):
        """Cache reading should handle corrupt JSON gracefully"""
        mock_repo_info.return_value = ("itdove", "ai-guardian")
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = "not valid json {"

        result = self.policy_checker._get_maintainer_cache()

        self.assertIsNone(result, "Should return None for corrupt cache")

    @patch.object(Path, 'exists')
    @patch('builtins.open')
    @patch.object(ToolPolicyChecker, '_get_git_repo_info')
    def test_get_maintainer_cache_validates_structure(self, mock_repo_info, mock_open, mock_exists):
        """Cache reading should validate cache data structure"""
        mock_repo_info.return_value = ("itdove", "ai-guardian")
        mock_exists.return_value = True

        # Cache with missing checked_at field
        cache_data = {
            "version": 1,
            "ttl_hours": 24,
            "repositories": {
                "itdove/ai-guardian": {
                    "username": "itdove",
                    "is_maintainer": True
                    # missing "checked_at"!
                }
            }
        }

        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(cache_data)

        result = self.policy_checker._get_maintainer_cache()

        self.assertIsNone(result, "Should return None for invalid cache structure")

    @patch.object(Path, 'exists')
    @patch('builtins.open')
    @patch.object(ToolPolicyChecker, '_get_git_repo_info')
    def test_get_maintainer_cache_handles_invalid_timestamp(self, mock_repo_info, mock_open, mock_exists):
        """Cache reading should handle invalid timestamp formats"""
        mock_repo_info.return_value = ("itdove", "ai-guardian")
        mock_exists.return_value = True

        # Cache with invalid timestamp
        cache_data = {
            "version": 1,
            "ttl_hours": 24,
            "repositories": {
                "itdove/ai-guardian": {
                    "username": "itdove",
                    "is_maintainer": True,
                    "checked_at": "not a valid timestamp"
                }
            }
        }

        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(cache_data)

        result = self.policy_checker._get_maintainer_cache()

        self.assertIsNone(result, "Should return None for invalid timestamp")
