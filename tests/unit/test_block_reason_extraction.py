"""
Unit tests for policy blocking message improvements (Issue #88)

Tests that:
- _extract_block_reason() correctly extracts concise reasons from error messages
- Log messages include the specific reason for blocking
- Error messages include "🛡️ BLOCKED BY POLICY" header
- Anti-workaround language is present in denial messages
"""

import unittest
from ai_guardian import _extract_block_reason


class BlockReasonExtractionTest(unittest.TestCase):
    """Test suite for _extract_block_reason() function"""

    def test_extract_critical_file_ai_guardian_config(self):
        """Should extract 'Critical file protected: ai-guardian config' from immutable deny message"""
        error_message = """
======================================================================
🛡️ BLOCKED BY POLICY
🔒 Protection:
======================================================================

This file is protected by ai-guardian and cannot be modified.

File: ~/.config/ai-guardian/ai-guardian.json
Tool: Edit

Reason: Critical security configuration

Protected files:
  • ai-guardian configuration files
  • IDE hook configuration (Claude, Cursor)
  • ai-guardian package source code
  • .ai-read-deny marker files (directory protection)

This protection cannot be disabled via configuration.
It ensures ai-guardian cannot be bypassed by AI agents.

DO NOT attempt workarounds - the protection is intentional.

To edit these files, use your text editor manually.
======================================================================
"""
        reason = _extract_block_reason(error_message)
        self.assertEqual(reason, "Critical file protected: ai-guardian config")

    def test_extract_critical_file_source_code(self):
        """Should extract 'Critical file protected: source code' from source file deny"""
        error_message = """
======================================================================
🛡️ BLOCKED BY POLICY
🔒 Protection:
======================================================================

This file is protected by ai-guardian and cannot be modified.

File: ~/ai-guardian/src/ai_guardian/__init__.py
Tool: Edit

Reason: Repository source file (maintainer bypass not available)
"""
        reason = _extract_block_reason(error_message)
        self.assertEqual(reason, "Critical file protected: source code")

    def test_extract_critical_file_marker(self):
        """Should extract 'Critical file protected: .ai-read-deny marker' from marker file deny"""
        error_message = """
======================================================================
🛡️ BLOCKED BY POLICY
🔒 Protection:
======================================================================

This file is protected by ai-guardian and cannot be modified.

File: ~/secrets/.ai-read-deny
Tool: Edit

Reason: Directory protection marker
"""
        reason = _extract_block_reason(error_message)
        self.assertEqual(reason, "Critical file protected: .ai-read-deny marker")

    def test_extract_matched_deny_pattern(self):
        """Should extract pattern from 'matched deny pattern' message"""
        error_message = """
======================================================================
🛡️ BLOCKED BY POLICY
🚫 TOOL ACCESS DENIED
======================================================================

Tool: Read
File Path: ~/secrets/production.env
Blocked by: matched deny pattern: *.env
Matcher: Read
"""
        reason = _extract_block_reason(error_message)
        self.assertEqual(reason, "Matched deny pattern: *.env")

    def test_extract_no_permission_rule(self):
        """Should extract 'No permission rule configured' from no rule message"""
        error_message = """
======================================================================
🛡️ BLOCKED BY POLICY
🚫 TOOL ACCESS DENIED
======================================================================

Tool: Skill
Skill Name: unknown-skill
Blocked by: no permission rule
"""
        reason = _extract_block_reason(error_message)
        self.assertEqual(reason, "No permission rule configured")

    def test_extract_not_in_allow_list(self):
        """Should extract 'Not in allow list' from allow list denial"""
        error_message = """
======================================================================
🛡️ BLOCKED BY POLICY
🚫 TOOL ACCESS DENIED
======================================================================

Tool: Skill
Skill Name: daf-unknown
Blocked by: not in allow list
Matcher: Skill
"""
        reason = _extract_block_reason(error_message)
        self.assertEqual(reason, "Not in allow list")

    def test_extract_unknown_reason(self):
        """Should return 'Policy violation' for unknown error format"""
        error_message = "Some unknown error format"
        reason = _extract_block_reason(error_message)
        self.assertEqual(reason, "Policy violation")

    def test_extract_complex_deny_pattern(self):
        """Should extract complex patterns with special characters"""
        error_message = """
Blocked by: matched deny pattern: */.config/ai-guardian/*
"""
        reason = _extract_block_reason(error_message)
        self.assertEqual(reason, "Matched deny pattern: */.config/ai-guardian/*")


class PolicyBlockedHeaderTest(unittest.TestCase):
    """Test suite for 🛡️ BLOCKED BY POLICY header in error messages"""

    def test_deny_message_has_blocked_header(self):
        """Tool deny messages should include 🛡️ BLOCKED BY POLICY header"""
        from ai_guardian.tool_policy import ToolPolicyChecker

        config = {
            "permissions": [
                {
                    "matcher": "Skill",
                    "mode": "allow",
                    "patterns": ["daf-*"]
                }
            ]
        }

        policy_checker = ToolPolicyChecker(config=config)
        hook_data = {
            "tool_name": "Skill",
            "tool_input": {"skill": "blocked-skill"}
        }

        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(allowed)
        # Phase 3 format uses 🛡️ instead of 🛡️
        self.assertIn("🛡️", error_msg)
        self.assertIn("DO NOT attempt", error_msg)

    def test_immutable_deny_message_has_blocked_header(self):
        """Immutable file deny messages should include Phase 3 format"""
        from ai_guardian.tool_policy import ToolPolicyChecker

        policy_checker = ToolPolicyChecker()

        # Test with ai-guardian config file (immutable)
        hook_data = {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/home/user/.config/ai-guardian/ai-guardian.json"
            }
        }

        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)

        self.assertFalse(allowed)
        # Phase 3 format uses 🛡️ instead of 🛡️
        self.assertIn("🛡️", error_msg)
        self.assertIn("Protection:", error_msg)
        self.assertIn("DO NOT attempt", error_msg)


if __name__ == "__main__":
    unittest.main()
