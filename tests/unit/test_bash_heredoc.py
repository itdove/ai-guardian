"""
Unit tests for bash heredoc handling (Issue #151)

Tests that heredoc content is properly stripped from bash commands
before pattern matching, preventing false positives when heredoc
content mentions protected keywords.
"""

import unittest
from ai_guardian.tool_policy import ToolPolicyChecker, _strip_bash_heredoc_content


class BashHeredocTest(unittest.TestCase):
    """Test suite for bash heredoc handling"""

    def setUp(self):
        """Set up test fixtures"""
        # Create policy checker with empty config
        self.policy_checker = ToolPolicyChecker(config={"permissions": []})

    # ========================================================================
    # Test: _strip_bash_heredoc_content function
    # ========================================================================

    def test_strip_simple_heredoc(self):
        """Strip content from simple heredoc"""
        command = """cat <<EOF
This is content
with ai-guardian mentioned
EOF"""
        result = _strip_bash_heredoc_content(command)
        # Should keep delimiters but remove content
        self.assertIn("<<EOF", result)
        self.assertIn("EOF", result)
        self.assertNotIn("This is content", result)
        self.assertNotIn("ai-guardian", result)

    def test_strip_quoted_heredoc(self):
        """Strip content from quoted heredoc (single quotes)"""
        command = """cat <<'EOF'
rm ai-guardian.json
> /etc/passwd
EOF"""
        result = _strip_bash_heredoc_content(command)
        self.assertIn("<<'EOF'", result)
        self.assertNotIn("rm ai-guardian", result)
        self.assertNotIn("> /etc/passwd", result)

    def test_strip_double_quoted_heredoc(self):
        """Strip content from double-quoted heredoc"""
        command = """cat <<"EOF"
dangerous content > ai-guardian
EOF"""
        result = _strip_bash_heredoc_content(command)
        self.assertIn('<<"EOF"', result)
        self.assertNotIn("dangerous content", result)

    def test_strip_dash_heredoc(self):
        """Strip content from dash heredoc (<<-EOF)"""
        command = """cat <<-EOF
	indented content
	ai-guardian > file
	EOF"""
        result = _strip_bash_heredoc_content(command)
        self.assertIn("<<-EOF", result)
        self.assertNotIn("indented content", result)

    def test_multiple_heredocs(self):
        """Strip content from multiple heredocs in same command"""
        command = """cat <<EOF1
content1 > ai-guardian
EOF1
cat <<EOF2
content2 with ai-guardian
EOF2"""
        result = _strip_bash_heredoc_content(command)
        self.assertNotIn("content1", result)
        self.assertNotIn("content2", result)
        # Command structure should remain
        self.assertEqual(result.count("cat"), 2)

    def test_no_heredoc_unchanged(self):
        """Commands without heredocs are unchanged"""
        command = "echo 'hello world'"
        result = _strip_bash_heredoc_content(command)
        self.assertEqual(command, result)

    def test_empty_command(self):
        """Empty commands are handled gracefully"""
        self.assertEqual(_strip_bash_heredoc_content(""), "")
        self.assertEqual(_strip_bash_heredoc_content(None), None)

    def test_heredoc_with_pipe(self):
        """Heredoc with pipe operator is handled correctly"""
        command = """cat <<'EOF' | pbcopy
gh issue create --title "Doc" --body "ai-guardian > redirect"
EOF"""
        result = _strip_bash_heredoc_content(command)
        self.assertIn("cat <<'EOF' | pbcopy", result)
        self.assertNotIn("ai-guardian > redirect", result)

    # ========================================================================
    # Test: Actual command blocking behavior (integration tests)
    # ========================================================================

    def test_heredoc_mentioning_ai_guardian_is_allowed(self):
        """
        ISSUE #151: Heredoc content mentioning ai-guardian should be ALLOWED.

        This was previously blocked by pattern "*>*ai-guardian*" matching
        heredoc content instead of just command structure.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """cat <<'EOF' | pbcopy
gh issue create --title "Documentation: Configure ai-guardian" --body "$(cat <<'EOFBODY'
## Problem
Users are confused about ai-guardian configuration > setup process
EOFBODY
)"
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        # This should be ALLOWED - heredoc content should not trigger blocking
        self.assertTrue(
            is_allowed,
            f"Heredoc with ai-guardian mention should be allowed. Error: {error_msg}",
        )

    def test_actual_redirect_to_ai_guardian_is_blocked(self):
        """
        Real redirect to ai-guardian files should still be BLOCKED.

        This verifies the fix doesn't break legitimate blocking.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": "echo 'malicious' > /tmp/ai-guardian.json"},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        # This should be BLOCKED - actual redirect to ai-guardian file
        self.assertFalse(is_allowed, "Actual redirect to ai-guardian should be blocked")
        self.assertIn("Protection:", error_msg)

    def test_heredoc_with_redirect_operator_allowed(self):
        """
        Heredoc content containing '>' operator should be allowed.

        Pattern should only match actual shell redirects, not text content.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """cat <<EOF
Markdown example:
> This is a quote about ai-guardian
> It should not be blocked
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        self.assertTrue(
            is_allowed,
            f"Heredoc with '>' in content should be allowed. Error: {error_msg}",
        )

    def test_nested_heredoc_in_command_substitution(self):
        """
        Test the exact example from issue #151.
        """
        # This is the actual command from the issue
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """cat <<'EOF' | pbcopy
gh issue create --title "Doc update" --body "Discussion of ai-guardian > redirect patterns"
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        self.assertTrue(
            is_allowed,
            "The exact command from issue #151 should be allowed. "
            f"This is a false positive that was reported. Error: {error_msg}",
        )

    def test_heredoc_strip_preserves_actual_command_blocking(self):
        """
        Verify that stripping heredoc doesn't affect blocking of dangerous commands.
        """
        # Actual dangerous command with heredoc
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """rm /tmp/ai-guardian.json
cat <<EOF
This is just documentation
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        # The rm command should still be blocked
        self.assertFalse(
            is_allowed, "Dangerous commands should still be blocked even with heredocs"
        )


    # ========================================================================
    # Test: Heredoc bypass of immutable deny patterns (Issue #1350)
    # ========================================================================

    def test_heredoc_bypass_sed_on_config_blocked(self):
        """
        ISSUE #1350: sed on ai-guardian.json hidden inside heredoc must be blocked.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """bash <<'EOF'
sed -i 's/enabled/disabled/' ~/.config/ai-guardian/ai-guardian.json
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        self.assertFalse(
            is_allowed,
            "sed on ai-guardian.json inside heredoc should be blocked",
        )

    def test_heredoc_bypass_rm_on_hooks_blocked(self):
        """
        ISSUE #1350: rm on cursor hooks.json hidden inside heredoc must be blocked.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """bash <<EOF
rm ~/.cursor/hooks.json
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        self.assertFalse(
            is_allowed,
            "rm on cursor hooks.json inside heredoc should be blocked",
        )

    def test_heredoc_bypass_redirect_to_config_blocked(self):
        """
        ISSUE #1350: redirect to ai-guardian.json inside heredoc must be blocked.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """bash <<'EOF'
echo '{}' > /tmp/ai-guardian.json
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        self.assertFalse(
            is_allowed,
            "redirect to ai-guardian.json inside heredoc should be blocked",
        )

    def test_heredoc_bypass_chmod_on_config_blocked(self):
        """
        ISSUE #1350: chmod on ai-guardian.json inside heredoc must be blocked.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """bash <<'EOF'
chmod 777 ai-guardian.json
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        self.assertFalse(
            is_allowed,
            "chmod on ai-guardian.json inside heredoc should be blocked",
        )

    def test_heredoc_bypass_cat_config_read_blocked(self):
        """
        ISSUE #1350: cat on config dir inside heredoc must be blocked.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """bash <<'EOF'
cat ~/.config/ai-guardian/ai-guardian.json
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        self.assertFalse(
            is_allowed,
            "cat on ai-guardian config inside heredoc should be blocked",
        )

    def test_heredoc_bypass_mv_hooks_blocked(self):
        """
        ISSUE #1350: mv on settings.json inside heredoc must be blocked.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """bash <<'EOF'
mv ~/.claude/settings.json /tmp/backup
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        self.assertFalse(
            is_allowed,
            "mv on settings.json inside heredoc should be blocked",
        )

    def test_heredoc_bypass_with_dash_format_blocked(self):
        """
        ISSUE #1350: Dash heredoc (<<-EOF) bypass must also be blocked.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """bash <<-EOF
	sed -i '' 's/x/y/' ai-guardian.json
	EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        self.assertFalse(
            is_allowed,
            "sed on ai-guardian.json inside dash heredoc should be blocked",
        )

    def test_legitimate_heredoc_still_allowed_after_fix(self):
        """
        Regression guard: Issue #151 fix still works after #1350 fix.

        Heredoc content that merely mentions ai-guardian in safe context
        (docs, comments) should remain allowed.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """cat <<'EOF'
## How to configure ai-guardian

1. Install ai-guardian
2. Run the setup wizard
3. Review your ai-guardian configuration
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        self.assertTrue(
            is_allowed,
            f"Documentation heredoc mentioning ai-guardian should be allowed. Error: {error_msg}",
        )

    def test_heredoc_safe_content_with_quotes_allowed(self):
        """
        Heredoc with safe content that includes quotes around ai-guardian terms
        should still be allowed.
        """
        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": """cat <<'EOF'
The "ai-guardian" tool provides security scanning.
It can detect prompt injection and secrets.
EOF"""},
            },
        }

        is_allowed, error_msg, tool_name = self.policy_checker.check_tool_allowed(
            hook_data
        )

        self.assertTrue(
            is_allowed,
            f"Safe heredoc content should be allowed. Error: {error_msg}",
        )


if __name__ == "__main__":
    unittest.main()
