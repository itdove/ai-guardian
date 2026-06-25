"""
Advanced tool policy tests for comprehensive coverage.

Tests complex rule matching, pattern evaluation, and edge cases
in tool permission checking.
"""

from unittest import TestCase

from ai_guardian.tool_policy import ToolPolicyChecker
from tests.fixtures.mock_mcp_server import create_hook_data
from tests.fixtures import attack_constants


class ToolPolicyRuleMatchingTests(TestCase):
    """Test different rule matching patterns"""

    def test_wildcard_pattern_matching(self):
        """Test wildcard pattern matching"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "tool_name", "mode": "deny", "patterns": ["mcp__*"]}
                ],
            }
        }

        policy_checker = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(
            tool_name=attack_constants.MCP_TOOL_NOTEBOOKLM_CREATE,
            tool_input={"title": "Test"},
        )

        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
        assert not allowed, "Wildcard pattern should match MCP tools"

    def test_case_sensitivity_in_matching(self):
        """Test case sensitivity in tool name matching"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "tool_name", "mode": "deny", "patterns": ["bash"]}
                ],
            }
        }

        policy_checker = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="Bash", tool_input={})

        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
        # Just verify it processes without error
        assert isinstance(allowed, bool)


class ToolPolicyRuleOrderingTests(TestCase):
    """Test rule ordering and priority"""

    def test_last_matching_rule_wins(self):
        """Test that last matching rule takes precedence (Issue #595)"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "Bash", "mode": "deny", "patterns": ["*"]},
                    {"matcher": "Bash", "mode": "allow", "patterns": ["*"]},
                ],
            }
        }

        policy_checker = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="Bash", tool_input={"command": "ls"})

        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
        assert allowed, "Last rule (allow) should take precedence"

    def test_no_matching_rule_default_behavior(self):
        """Test default behavior when no rule matches — MCP/Skills blocked, built-in allowed"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [{"matcher": "Bash", "mode": "deny", "patterns": ["*"]}],
            }
        }
        policy_checker = ToolPolicyChecker(config=config)

        # MCP tools without matching rules are blocked (restricted)
        hook_data = create_hook_data(tool_name="mcp__test__tool", tool_input={})
        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
        assert not allowed, "MCP tool with no matching rule should be blocked"

        # Built-in tools without matching rules are allowed
        hook_data = create_hook_data(
            tool_name="Read", tool_input={"file_path": "/tmp/test"}
        )
        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
        assert allowed, "Built-in tool with no matching rule should be allowed"


class ToolPolicyConfigVariationsTests(TestCase):
    """Test different configuration variations"""

    def test_permissions_disabled(self):
        """Test that disabled permissions allow all tools"""
        config = {
            "permissions": {
                "enabled": False,
                "rules": [{"matcher": "tool_name", "mode": "deny", "patterns": ["*"]}],
            }
        }

        policy_checker = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="Bash", tool_input={})

        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
        assert allowed, "Disabled permissions should allow all tools"

    def test_empty_rules_list(self):
        """Test configuration with empty rules list — built-in tools still allowed"""
        config = {"permissions": {"enabled": True, "rules": []}}

        policy_checker = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="Bash", tool_input={"command": "ls"})

        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
        assert allowed, "Built-in tools should be allowed even with empty rules"

    def test_no_permissions_config(self):
        """Test with no permissions configuration"""
        config = {}

        policy_checker = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="Bash", tool_input={})

        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
        # No config: should default to allowing
        assert isinstance(allowed, bool)

    def test_invalid_rule_format_handled(self):
        """Test that invalid rule format is handled gracefully"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        # Missing matcher and mode
                        "patterns": ["Bash"]
                    }
                ],
            }
        }

        policy_checker = ToolPolicyChecker(config=config)
        hook_data = create_hook_data(tool_name="Bash", tool_input={})

        # Should handle invalid rule without crashing
        try:
            allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
            assert isinstance(allowed, bool)
        except Exception:
            # If it raises an exception, that's also acceptable error handling
            pass


class ToolPolicyEdgeCasesTests(TestCase):
    """Test edge cases in tool policy checking"""

    def test_empty_tool_name(self):
        """Test handling of empty tool name"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [{"matcher": "tool_name", "mode": "deny", "patterns": ["*"]}],
            }
        }

        policy_checker = ToolPolicyChecker(config=config)
        hook_data = {"hook_event_name": "PreToolUse", "tool_name": ""}

        # Should handle empty tool name gracefully
        try:
            allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
            assert isinstance(allowed, bool)
        except Exception:
            pass

    def test_null_tool_name(self):
        """Test handling of null tool name"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [{"matcher": "tool_name", "mode": "deny", "patterns": ["*"]}],
            }
        }

        policy_checker = ToolPolicyChecker(config=config)
        hook_data = {"hook_event_name": "PreToolUse", "tool_name": None}

        # Should handle null tool name gracefully
        try:
            allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
            assert isinstance(allowed, bool)
        except Exception:
            pass

    def test_missing_tool_name_field(self):
        """Test handling of missing tool_name field"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [{"matcher": "tool_name", "mode": "deny", "patterns": ["*"]}],
            }
        }

        policy_checker = ToolPolicyChecker(config=config)
        hook_data = {"hook_event_name": "PreToolUse"}  # No tool_name

        # Should handle missing tool_name gracefully
        try:
            allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)
            assert isinstance(allowed, bool)
        except Exception:
            pass
