#!/usr/bin/env python3
"""
Tests for TUI Widgets

Test reusable TUI widgets including TimeBasedToggle.
"""

import unittest
from datetime import datetime, timedelta, timezone

from ai_guardian.tui.widgets import ISO8601Validator, TimeBasedToggle


class TestISO8601Validator(unittest.TestCase):
    """Test ISO 8601 validator."""

    def setUp(self):
        self.validator = ISO8601Validator()

    def test_valid_utc_timestamp(self):
        """Test valid UTC timestamp with Z suffix."""
        result = self.validator.validate("2026-04-13T18:00:00Z")
        self.assertTrue(result.is_valid)

    def test_valid_utc_timestamp_with_milliseconds(self):
        """Test valid UTC timestamp with milliseconds."""
        result = self.validator.validate("2026-04-13T18:00:00.123Z")
        self.assertTrue(result.is_valid)

    def test_invalid_without_z_suffix(self):
        """Test timestamp without Z suffix is invalid."""
        result = self.validator.validate("2026-04-13T18:00:00")
        self.assertFalse(result.is_valid)
        self.assertIn("UTC", str(result.failure_descriptions))

    def test_invalid_format(self):
        """Test completely invalid format."""
        result = self.validator.validate("not-a-timestamp")
        self.assertFalse(result.is_valid)

    def test_empty_string_allowed(self):
        """Test empty string is allowed (optional field)."""
        result = self.validator.validate("")
        self.assertTrue(result.is_valid)

    def test_whitespace_only_allowed(self):
        """Test whitespace-only is allowed (optional field)."""
        result = self.validator.validate("   ")
        self.assertTrue(result.is_valid)


class TestTimeBasedToggle(unittest.TestCase):
    """Test TimeBasedToggle widget."""

    def test_init_with_bool_true(self):
        """Test initialization with simple boolean True."""
        toggle = TimeBasedToggle(
            title="Test Feature",
            config_key="test_feature",
            current_value=True
        )

        self.assertTrue(toggle.is_enabled)
        self.assertEqual(toggle.disabled_until, "")
        self.assertEqual(toggle.reason, "")
        self.assertEqual(toggle.current_mode, "enabled")

    def test_init_with_bool_false(self):
        """Test initialization with simple boolean False."""
        toggle = TimeBasedToggle(
            title="Test Feature",
            config_key="test_feature",
            current_value=False
        )

        self.assertFalse(toggle.is_enabled)
        self.assertEqual(toggle.disabled_until, "")
        self.assertEqual(toggle.reason, "")
        self.assertEqual(toggle.current_mode, "disabled")

    def test_init_with_dict_enabled(self):
        """Test initialization with dict format (enabled)."""
        toggle = TimeBasedToggle(
            title="Test Feature",
            config_key="test_feature",
            current_value={"value": True}
        )

        self.assertTrue(toggle.is_enabled)
        self.assertEqual(toggle.current_mode, "enabled")

    def test_init_with_dict_temp_disabled(self):
        """Test initialization with dict format (temporarily disabled)."""
        future_time = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

        toggle = TimeBasedToggle(
            title="Test Feature",
            config_key="test_feature",
            current_value={
                "value": False,
                "disabled_until": future_time,
                "reason": "Testing"
            }
        )

        self.assertFalse(toggle.is_enabled)
        self.assertEqual(toggle.disabled_until, future_time)
        self.assertEqual(toggle.reason, "Testing")
        self.assertEqual(toggle.current_mode, "temp_disabled")

    def test_get_value_simple_enabled(self):
        """Test get_value returns True for simple enabled mode."""
        toggle = TimeBasedToggle(
            title="Test Feature",
            config_key="test_feature",
            current_value=True
        )

        # Simulate mode being set to enabled
        toggle.current_mode = "enabled"

        # Note: get_value tries to query widgets which won't exist in unit test
        # This tests the fallback behavior
        value = toggle.get_value()
        self.assertTrue(value)

    def test_get_value_simple_disabled(self):
        """Test get_value returns False for simple disabled mode."""
        toggle = TimeBasedToggle(
            title="Test Feature",
            config_key="test_feature",
            current_value=False
        )

        # Simulate mode being set to disabled
        toggle.current_mode = "disabled"

        value = toggle.get_value()
        self.assertFalse(value)


if __name__ == '__main__':
    unittest.main()
