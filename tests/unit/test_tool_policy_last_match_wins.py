"""
Tests for last-match-wins permission rule evaluation (Issue #595).

Verifies that permission rules are evaluated in order with last match winning,
consistent with directory_rules evaluation in hook_processing.py.
"""

from unittest import TestCase
from unittest.mock import patch

from ai_guardian.tools.policy import ToolPolicyChecker
from tests.fixtures.mock_mcp_server import create_hook_data


class LastMatchWinsBasicTests(TestCase):
    """Test basic last-match-wins evaluation semantics."""

    def test_last_matching_rule_wins_allow_then_deny(self):
        """Last matching rule (deny) should win over earlier allow."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "mcp__*", "mode": "allow", "patterns": ["*"]},
                    {"matcher": "mcp__*", "mode": "deny", "patterns": ["*"]},
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(
            tool_name="mcp__notebooklm-mcp__notebook_list", tool_input={}
        )
        allowed, error_msg, _ = policy.check_tool_allowed(hook_data)
        assert not allowed, "Last rule (deny) should win"

    def test_last_matching_rule_wins_deny_then_allow(self):
        """Last matching rule (allow) should win over earlier deny."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "mcp__*", "mode": "deny", "patterns": ["*"]},
                    {"matcher": "mcp__*", "mode": "allow", "patterns": ["*"]},
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(
            tool_name="mcp__notebooklm-mcp__notebook_list", tool_input={}
        )
        allowed, error_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "Last rule (allow) should win"

    def test_no_rules_blocks_by_default(self):
        """No matching rules should block (secure by default)."""
        config = {"permissions": {"enabled": True, "rules": []}}
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(
            tool_name="mcp__notebooklm-mcp__notebook_list", tool_input={}
        )
        allowed, error_msg, _ = policy.check_tool_allowed(hook_data)
        assert not allowed, "No rules should block by default"

    def test_catch_all_allow_permits_everything(self):
        """A catch-all allow rule should permit all tools."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "*", "mode": "allow", "patterns": ["*"]},
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)

        test_cases = [
            ("Bash", {"command": "ls"}),
            ("Read", {"file_path": "/tmp/test.txt"}),
            ("Write", {"file_path": "/tmp/test.txt", "content": "hello"}),
            ("Skill", {"skill": "test-skill"}),
            ("mcp__test__tool", {}),
        ]
        for tool_name, tool_input in test_cases:
            hook_data = create_hook_data(tool_name=tool_name, tool_input=tool_input)
            allowed, _, _ = policy.check_tool_allowed(hook_data)
            assert allowed, f"Catch-all allow should permit {tool_name}"


class LastMatchWinsLayeredPolicyTests(TestCase):
    """Test layered policy patterns (the main use case from Issue #595)."""

    def _standard_profile_config(self):
        """Config matching the new @standard profile."""
        return {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "*", "mode": "allow", "patterns": ["*"]},
                    {
                        "matcher": "mcp__*",
                        "mode": "deny",
                        "patterns": ["*"],
                        "action": "warn",
                    },
                    {
                        "matcher": "mcp__ai-guardian__*",
                        "mode": "allow",
                        "patterns": ["*"],
                    },
                    {
                        "matcher": "Skill",
                        "mode": "deny",
                        "patterns": ["*"],
                        "action": "warn",
                    },
                ],
            }
        }

    def test_unlisted_mcp_server_warned_not_blocked(self):
        """Bug #595: unlisted MCP server should be warned, not blocked."""
        config = self._standard_profile_config()
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(
            tool_name="mcp__new-server__some_tool", tool_input={}
        )
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "Unlisted MCP server should be allowed (warn mode)"
        assert warn_msg is not None, "Should produce a warning message"
        assert "warn" in warn_msg.lower() or "⚠️" in warn_msg

    def test_known_mcp_server_allowed_no_warning(self):
        """Known MCP server (ai-guardian) should be allowed without warning."""
        config = self._standard_profile_config()
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(
            tool_name="mcp__ai-guardian__check_path", tool_input={}
        )
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "ai-guardian MCP should be allowed"
        assert warn_msg is None, "ai-guardian MCP should have no warning"

    def test_builtin_tools_allowed(self):
        """Built-in tools should be allowed by the catch-all rule."""
        config = self._standard_profile_config()
        policy = ToolPolicyChecker(config=config)

        for tool_name, tool_input in [
            ("Bash", {"command": "ls"}),
            ("Read", {"file_path": "/tmp/test.txt"}),
            ("Write", {"file_path": "/tmp/test.txt", "content": "hello"}),
        ]:
            hook_data = create_hook_data(tool_name=tool_name, tool_input=tool_input)
            allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
            assert allowed, f"{tool_name} should be allowed"
            assert warn_msg is None, f"{tool_name} should have no warning"

    def test_skill_warned(self):
        """Unknown skill should be warned (not blocked)."""
        config = self._standard_profile_config()
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(
            tool_name="Skill", tool_input={"skill": "unknown-skill"}
        )
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "Unknown skill should be allowed (warn mode)"
        assert warn_msg is not None, "Should produce a warning"

    def test_specific_allow_overrides_category_deny(self):
        """Specific allow rule should override broader deny rule."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "*", "mode": "allow", "patterns": ["*"]},
                    {"matcher": "mcp__*", "mode": "deny", "patterns": ["*"]},
                    {
                        "matcher": "mcp__mcp-atlassian__*",
                        "mode": "allow",
                        "patterns": ["*"],
                    },
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)

        hook_data = create_hook_data(
            tool_name="mcp__mcp-atlassian__jira_search", tool_input={}
        )
        allowed, _, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "Atlassian MCP should be allowed by specific rule"

        hook_data = create_hook_data(
            tool_name="mcp__unknown-server__some_tool", tool_input={}
        )
        allowed, _, _ = policy.check_tool_allowed(hook_data)
        assert not allowed, "Unknown MCP should be blocked by mcp__* deny"

    def test_issue_example_full_config(self):
        """Test the exact config from the issue description."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "*", "mode": "allow", "patterns": ["*"]},
                    {
                        "matcher": "mcp__*",
                        "mode": "deny",
                        "patterns": ["*"],
                        "action": "warn",
                    },
                    {
                        "matcher": "mcp__mcp-atlassian__*",
                        "mode": "allow",
                        "patterns": ["*"],
                    },
                    {
                        "matcher": "mcp__notebooklm-mcp__*",
                        "mode": "allow",
                        "patterns": ["*"],
                    },
                    {
                        "matcher": "Skill",
                        "mode": "deny",
                        "patterns": ["*"],
                        "action": "warn",
                    },
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["feedback", "daf-jira"],
                    },
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)

        hook_data = create_hook_data(
            tool_name="mcp__mcp-atlassian__jira_search", tool_input={}
        )
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed and warn_msg is None, "Atlassian MCP: allowed, no warning"

        hook_data = create_hook_data(
            tool_name="mcp__notebooklm-mcp__notebook_list", tool_input={}
        )
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed and warn_msg is None, "NotebookLM MCP: allowed, no warning"

        hook_data = create_hook_data(
            tool_name="mcp__new-sdlc-mcp__some_tool", tool_input={}
        )
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed and warn_msg is not None, "New MCP: allowed with warning"

        hook_data = create_hook_data(
            tool_name="Skill", tool_input={"skill": "feedback"}
        )
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed and warn_msg is None, "feedback skill: allowed, no warning"

        hook_data = create_hook_data(
            tool_name="Skill", tool_input={"skill": "daf-jira"}
        )
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed and warn_msg is None, "daf-jira skill: allowed, no warning"

        hook_data = create_hook_data(
            tool_name="Skill", tool_input={"skill": "unknown-skill"}
        )
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed and warn_msg is not None, "Unknown skill: allowed with warning"

        hook_data = create_hook_data(tool_name="Bash", tool_input={"command": "ls"})
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed and warn_msg is None, "Bash: allowed, no warning"


class DenyActionModesTests(TestCase):
    """Test deny rule action modes (block/warn/log-only)."""

    def test_deny_action_block(self):
        """Deny with action=block should block the tool."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "mcp__*",
                        "mode": "deny",
                        "patterns": ["*"],
                        "action": "block",
                    },
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="mcp__test__tool", tool_input={})
        allowed, error_msg, _ = policy.check_tool_allowed(hook_data)
        assert not allowed
        assert error_msg is not None

    def test_deny_action_warn(self):
        """Deny with action=warn should allow with warning."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "mcp__*",
                        "mode": "deny",
                        "patterns": ["*"],
                        "action": "warn",
                    },
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="mcp__test__tool", tool_input={})
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "warn mode should allow"
        assert warn_msg is not None, "warn mode should produce a message"

    def test_deny_action_log_only(self):
        """Deny with action=log-only should allow silently."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "mcp__*",
                        "mode": "deny",
                        "patterns": ["*"],
                        "action": "log-only",
                    },
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="mcp__test__tool", tool_input={})
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "log-only mode should allow"
        assert warn_msg is None, "log-only mode should be silent"

    def test_deny_default_action_is_block(self):
        """Deny without explicit action should default to block."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "mcp__*", "mode": "deny", "patterns": ["*"]},
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="mcp__test__tool", tool_input={})
        allowed, _, _ = policy.check_tool_allowed(hook_data)
        assert not allowed, "Default action should be block"


class BackwardCompatibilityTests(TestCase):
    """Test backward compatibility with old action-on-allow format."""

    def test_allow_with_action_warn_expands_correctly(self):
        """Old format: allow + action=warn should expand into allow + deny(warn)."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "mcp__notebooklm-mcp__*",
                        "mode": "allow",
                        "patterns": ["mcp__notebooklm-mcp__notebook_list"],
                        "action": "warn",
                    },
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)

        hook_data = create_hook_data(
            tool_name="mcp__notebooklm-mcp__notebook_list", tool_input={}
        )
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "Listed tool should be allowed"

        hook_data = create_hook_data(
            tool_name="mcp__notebooklm-mcp__notebook_create", tool_input={}
        )
        allowed, warn_msg, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "Unlisted tool should be allowed (warn mode from expanded deny)"
        assert warn_msg is not None, "Should have warning for unlisted tool"

    @patch("ai_guardian.tools.policy.logger")
    def test_legacy_expansion_logs_deprecation(self, mock_logger):
        """Legacy rule expansion should log a deprecation notice."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "mcp__*",
                        "mode": "allow",
                        "patterns": ["*"],
                        "action": "warn",
                    },
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="mcp__test__tool", tool_input={})
        policy.check_tool_allowed(hook_data)

        info_calls = [str(c) for c in mock_logger.info.call_args_list]
        deprecation_logged = any("deprecated" in c.lower() for c in info_calls)
        assert deprecation_logged, f"Should log deprecation. Info calls: {info_calls}"


class StrictProfileTests(TestCase):
    """Test strict profile behavior (empty rules = block everything)."""

    def test_strict_profile_blocks_mcp(self):
        """Empty rules should block MCP tools."""
        config = {"permissions": {"enabled": True, "rules": []}}
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="mcp__test__tool", tool_input={})
        allowed, _, _ = policy.check_tool_allowed(hook_data)
        assert not allowed

    def test_strict_profile_blocks_skills(self):
        """Empty rules should block Skills."""
        config = {"permissions": {"enabled": True, "rules": []}}
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="Skill", tool_input={"skill": "test"})
        allowed, _, _ = policy.check_tool_allowed(hook_data)
        assert not allowed

    def test_strict_profile_allows_builtin_tools_by_default(self):
        """Empty rules should still allow built-in tools (backward compat)."""
        config = {"permissions": {"enabled": True, "rules": []}}
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="Bash", tool_input={"command": "ls"})
        allowed, _, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "Built-in tools should be allowed when no rules target them"

    def test_strict_with_explicit_allow_works(self):
        """Strict profile with explicit allow should work."""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "Bash", "mode": "allow", "patterns": ["*"]},
                    {
                        "matcher": "mcp__ai-guardian__*",
                        "mode": "allow",
                        "patterns": ["*"],
                    },
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)

        hook_data = create_hook_data(tool_name="Bash", tool_input={"command": "ls"})
        allowed, _, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "Explicitly allowed Bash should work"

        hook_data = create_hook_data(
            tool_name="mcp__ai-guardian__check_path", tool_input={}
        )
        allowed, _, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "Explicitly allowed MCP should work"

        hook_data = create_hook_data(tool_name="mcp__other__tool", tool_input={})
        allowed, _, _ = policy.check_tool_allowed(hook_data)
        assert not allowed, "Non-allowed MCP should be blocked"


class PermissionsDisabledTests(TestCase):
    """Test behavior when permissions are disabled."""

    def test_disabled_permissions_allows_everything(self):
        """When permissions disabled, all tools should be allowed."""
        config = {
            "permissions": {
                "enabled": False,
                "rules": [
                    {"matcher": "*", "mode": "deny", "patterns": ["*"]},
                ],
            }
        }
        policy = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="mcp__test__tool", tool_input={})
        allowed, _, _ = policy.check_tool_allowed(hook_data)
        assert allowed, "Disabled permissions should allow everything"
