"""
Unit tests for tool policy time-based expiration feature (Issue #34)

Tests the ability to set expiration timestamps on permission patterns.
"""

import json
from datetime import datetime, timezone
from unittest import TestCase
from ai_guardian.tool_policy import ToolPolicyChecker


class ToolPolicyExpirationTest(TestCase):
    """Test suite for tool policy time-based expiration"""

    # ========================================================================
    # Test: Simple pattern format (backward compatibility)
    # ========================================================================

    def test_simple_pattern_format_never_expires(self):
        """Simple string patterns never expire"""
        config = {
            "permissions": [
                {
                    "matcher": "Skill",
                    "mode": "allow",
                    "patterns": ["daf-*", "gh-cli"]
                }
            ]
        }

        policy_checker = ToolPolicyChecker(config=config)

        # Simple patterns should always be valid
        self.assertTrue(policy_checker._is_pattern_valid("daf-*"))
        self.assertTrue(policy_checker._is_pattern_valid("gh-cli"))

    def test_simple_patterns_allow_tool_access(self):
        """Tools matching simple patterns are allowed"""
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
            "tool_use": {
                "name": "Skill",
                "input": {"skill": "daf-jira"}
            }
        }

        is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)
        self.assertTrue(is_allowed)
        self.assertIsNone(error_msg)

    # ========================================================================
    # Test: Extended pattern format with valid_until
    # ========================================================================

    def test_extended_pattern_format_not_yet_expired(self):
        """Extended pattern with future valid_until is valid"""
        pattern_entry = {
            "pattern": "debug-*",
            "valid_until": "2099-12-31T23:59:59Z"
        }

        policy_checker = ToolPolicyChecker(config={"permissions": []})
        self.assertTrue(policy_checker._is_pattern_valid(pattern_entry))

    def test_extended_pattern_format_expired(self):
        """Extended pattern with past valid_until is expired"""
        pattern_entry = {
            "pattern": "temp-*",
            "valid_until": "2020-01-01T00:00:00Z"
        }

        policy_checker = ToolPolicyChecker(config={"permissions": []})
        self.assertFalse(policy_checker._is_pattern_valid(pattern_entry))

    def test_extended_pattern_format_no_valid_until(self):
        """Extended pattern without valid_until never expires"""
        pattern_entry = {
            "pattern": "permanent-*"
        }

        policy_checker = ToolPolicyChecker(config={"permissions": []})
        self.assertTrue(policy_checker._is_pattern_valid(pattern_entry))

    def test_extended_pattern_format_empty_valid_until(self):
        """Extended pattern with empty valid_until never expires"""
        pattern_entry = {
            "pattern": "test-*",
            "valid_until": ""
        }

        policy_checker = ToolPolicyChecker(config={"permissions": []})
        self.assertTrue(policy_checker._is_pattern_valid(pattern_entry))

    # ========================================================================
    # Test: Pattern filtering
    # ========================================================================

    def test_filter_valid_patterns_removes_expired(self):
        """Expired patterns are filtered out from pattern lists"""
        current_time = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)

        patterns = [
            "permanent-*",  # Simple format - never expires
            {
                "pattern": "active-*",
                "valid_until": "2026-04-14T00:00:00Z"  # Future - valid
            },
            {
                "pattern": "expired-*",
                "valid_until": "2026-04-12T00:00:00Z"  # Past - expired
            }
        ]

        policy_checker = ToolPolicyChecker(config={"permissions": []})
        filtered = policy_checker._filter_valid_patterns(patterns, current_time)

        # Should keep first two, remove expired one
        self.assertEqual(len(filtered), 2)
        self.assertIn("permanent-*", filtered)
        self.assertIn(patterns[1], filtered)  # The active-* pattern
        self.assertNotIn(patterns[2], filtered)  # The expired-* pattern

    # ========================================================================
    # Test: Tool access with time-based expiration
    # ========================================================================

    def test_tool_allowed_before_expiration(self):
        """Tool is allowed when pattern has not expired"""
        current_time = datetime(2026, 4, 13, 11, 0, 0, tzinfo=timezone.utc)

        config = {
            "permissions": [
                {
                    "matcher": "Skill",
                    "mode": "allow",
                    "patterns": [
                        {
                            "pattern": "debug-*",
                            "valid_until": "2026-04-13T12:00:00Z"
                        }
                    ]
                }
            ]
        }

        policy_checker = ToolPolicyChecker(config=config)

        # Override current time for testing
        policy_checker._find_permission_rules = lambda tool_name: [
            {
                "matcher": "Skill",
                "mode": "allow",
                "patterns": policy_checker._filter_valid_patterns(
                    config["permissions"][0]["patterns"],
                    current_time
                )
            }
        ] if tool_name == "Skill" else []

        hook_data = {
            "tool_use": {
                "name": "Skill",
                "input": {"skill": "debug-tool"}
            }
        }

        is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)
        self.assertTrue(is_allowed)

    def test_tool_denied_after_expiration(self):
        """Tool is denied when pattern has expired"""
        current_time = datetime(2026, 4, 13, 13, 0, 0, tzinfo=timezone.utc)

        config = {
            "permissions": [
                {
                    "matcher": "Skill",
                    "mode": "allow",
                    "patterns": [
                        {
                            "pattern": "debug-*",
                            "valid_until": "2026-04-13T12:00:00Z"
                        }
                    ]
                }
            ]
        }

        policy_checker = ToolPolicyChecker(config=config)

        # Override _find_permission_rules to use custom current_time
        original_find = policy_checker._find_permission_rules

        def custom_find(tool_name):
            rules = original_find(tool_name)
            # Filter patterns with custom current_time
            for rule in rules:
                if "patterns" in rule:
                    rule["patterns"] = policy_checker._filter_valid_patterns(
                        rule["patterns"],
                        current_time
                    )
            return rules

        policy_checker._find_permission_rules = custom_find

        hook_data = {
            "tool_use": {
                "name": "Skill",
                "input": {"skill": "debug-tool"}
            }
        }

        is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)
        self.assertFalse(is_allowed)
        self.assertIsNotNone(error_msg)

    # ========================================================================
    # Test: Mixed simple and extended patterns
    # ========================================================================

    def test_mixed_simple_and_extended_patterns(self):
        """Config can have both simple and extended patterns"""
        current_time = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)

        patterns = [
            "daf-*",  # Simple - permanent
            {
                "pattern": "debug-*",
                "valid_until": "2026-04-14T00:00:00Z"  # Extended - valid
            },
            {
                "pattern": "temp-*",
                "valid_until": "2026-04-12T00:00:00Z"  # Extended - expired
            }
        ]

        policy_checker = ToolPolicyChecker(config={"permissions": []})
        filtered = policy_checker._filter_valid_patterns(patterns, current_time)

        # Should keep first two (permanent and active), remove expired
        self.assertEqual(len(filtered), 2)

    # ========================================================================
    # Test: Pattern extraction
    # ========================================================================

    def test_extract_pattern_string_from_simple_format(self):
        """Extract pattern string from simple string format"""
        policy_checker = ToolPolicyChecker(config={"permissions": []})

        pattern_str = policy_checker._extract_pattern_string("daf-*")
        self.assertEqual(pattern_str, "daf-*")

    def test_extract_pattern_string_from_extended_format(self):
        """Extract pattern string from extended dict format"""
        policy_checker = ToolPolicyChecker(config={"permissions": []})

        pattern_entry = {
            "pattern": "debug-*",
            "valid_until": "2026-04-13T12:00:00Z"
        }

        pattern_str = policy_checker._extract_pattern_string(pattern_entry)
        self.assertEqual(pattern_str, "debug-*")

    # ========================================================================
    # Test: Boundary conditions
    # ========================================================================

    def test_pattern_expired_exactly_at_boundary(self):
        """Pattern is expired when current_time == valid_until"""
        current_time = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)

        pattern_entry = {
            "pattern": "temp-*",
            "valid_until": "2026-04-13T12:00:00Z"
        }

        policy_checker = ToolPolicyChecker(config={"permissions": []})

        # At exact expiration time, should be expired
        is_valid = policy_checker._is_pattern_valid(pattern_entry, current_time)
        self.assertFalse(is_valid)

    def test_pattern_valid_one_second_before_expiration(self):
        """Pattern is valid one second before expiration"""
        current_time = datetime(2026, 4, 13, 11, 59, 59, tzinfo=timezone.utc)

        pattern_entry = {
            "pattern": "temp-*",
            "valid_until": "2026-04-13T12:00:00Z"
        }

        policy_checker = ToolPolicyChecker(config={"permissions": []})

        is_valid = policy_checker._is_pattern_valid(pattern_entry, current_time)
        self.assertTrue(is_valid)

    # ========================================================================
    # Test: Invalid timestamp handling (fail-safe)
    # ========================================================================

    def test_invalid_timestamp_treated_as_valid(self):
        """Invalid timestamp is treated as non-expiring (fail-safe)"""
        pattern_entry = {
            "pattern": "test-*",
            "valid_until": "invalid-timestamp"
        }

        policy_checker = ToolPolicyChecker(config={"permissions": []})

        # Fail-safe: invalid timestamp should be treated as valid
        is_valid = policy_checker._is_pattern_valid(pattern_entry)
        self.assertTrue(is_valid)

    # ========================================================================
    # Test: Legacy format support
    # ========================================================================

    def test_legacy_allow_format_with_expiration(self):
        """Legacy allow format supports time-based expiration"""
        current_time = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)

        config = {
            "permissions": [
                {
                    "matcher": "Skill",
                    "allow": [
                        "daf-*",
                        {
                            "pattern": "debug-*",
                            "valid_until": "2026-04-14T00:00:00Z"
                        }
                    ]
                }
            ]
        }

        policy_checker = ToolPolicyChecker(config=config)
        rules = policy_checker._find_permission_rules("Skill")

        # Should have filtered patterns
        self.assertEqual(len(rules), 1)
        self.assertIn("allow", rules[0])

    # ========================================================================
    # Test: Real-world scenarios
    # ========================================================================

    def test_temporary_debug_access_scenario(self):
        """Real-world: Temporary debug access expires at noon"""
        morning_time = datetime(2026, 4, 13, 9, 30, 0, tzinfo=timezone.utc)
        afternoon_time = datetime(2026, 4, 13, 14, 30, 0, tzinfo=timezone.utc)

        config = {
            "permissions": [
                {
                    "matcher": "Skill",
                    "mode": "allow",
                    "patterns": [
                        "daf-*",  # Permanent
                        {
                            "pattern": "debug-*",
                            "valid_until": "2026-04-13T12:00:00Z",
                            "_comment": "Temporary debug access until noon"
                        }
                    ]
                }
            ]
        }

        policy_checker = ToolPolicyChecker(config=config)

        # Morning: debug access should be valid
        morning_patterns = policy_checker._filter_valid_patterns(
            config["permissions"][0]["patterns"],
            morning_time
        )
        self.assertEqual(len(morning_patterns), 2)

        # Afternoon: debug access should be expired
        afternoon_patterns = policy_checker._filter_valid_patterns(
            config["permissions"][0]["patterns"],
            afternoon_time
        )
        self.assertEqual(len(afternoon_patterns), 1)  # Only permanent pattern remains

    def test_temporary_bash_permission_scenario(self):
        """Real-world: Temporary Docker cleanup permission"""
        config = {
            "permissions": [
                {
                    "matcher": "Bash",
                    "mode": "allow",
                    "patterns": [
                        {
                            "pattern": "*docker rm*",
                            "valid_until": "2026-04-13T15:00:00Z",
                            "_comment": "Container cleanup until 15:00"
                        }
                    ]
                }
            ]
        }

        policy_checker = ToolPolicyChecker(config=config)

        # Before 15:00
        before_time = datetime(2026, 4, 13, 14, 30, 0, tzinfo=timezone.utc)
        before_patterns = policy_checker._filter_valid_patterns(
            config["permissions"][0]["patterns"],
            before_time
        )
        self.assertEqual(len(before_patterns), 1)

        # After 15:00
        after_time = datetime(2026, 4, 13, 15, 30, 0, tzinfo=timezone.utc)
        after_patterns = policy_checker._filter_valid_patterns(
            config["permissions"][0]["patterns"],
            after_time
        )
        self.assertEqual(len(after_patterns), 0)


if __name__ == '__main__':
    unittest.main()
