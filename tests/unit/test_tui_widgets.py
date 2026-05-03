#!/usr/bin/env python3
"""
Tests for TUI Widgets

Test reusable TUI widgets including TimeBasedToggle.
"""

import unittest
from datetime import datetime, timedelta, timezone

from ai_guardian.tui.widgets import (
    ISO8601Validator, DurationValidator, TimeBasedToggle,
    parse_duration, duration_from_timestamp, sanitize_enabled_value,
    format_local_time,
)


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


class TestSanitizeEnabledValue(unittest.TestCase):
    """Test sanitize_enabled_value prevents corrupted config values."""

    def test_true_passthrough(self):
        self.assertIs(sanitize_enabled_value(True), True)

    def test_false_passthrough(self):
        self.assertIs(sanitize_enabled_value(False), False)

    def test_valid_temp_disabled_passthrough(self):
        val = {"value": False, "disabled_until": "2026-12-31T23:59:59Z", "reason": "test"}
        self.assertEqual(sanitize_enabled_value(val), val)

    def test_dict_without_disabled_until_collapses_to_false(self):
        self.assertIs(sanitize_enabled_value({"value": False}), False)

    def test_dict_without_disabled_until_collapses_to_true(self):
        self.assertIs(sanitize_enabled_value({"value": True}), True)

    def test_dict_with_empty_disabled_until_collapses(self):
        self.assertIs(sanitize_enabled_value({"value": False, "disabled_until": ""}), False)

    def test_dict_with_reason_only_collapses(self):
        self.assertIs(sanitize_enabled_value({"value": False, "reason": "test"}), False)

    def test_non_bool_non_dict_converts(self):
        self.assertIs(sanitize_enabled_value(1), True)
        self.assertIs(sanitize_enabled_value(0), False)


class TestParseDuration(unittest.TestCase):
    """Test duration parsing."""

    def test_minutes(self):
        self.assertEqual(parse_duration("30m"), timedelta(minutes=30))

    def test_hours(self):
        self.assertEqual(parse_duration("2h"), timedelta(hours=2))

    def test_days(self):
        self.assertEqual(parse_duration("1d"), timedelta(days=1))

    def test_combined_hours_minutes(self):
        self.assertEqual(parse_duration("1h30m"), timedelta(hours=1, minutes=30))

    def test_combined_days_hours(self):
        self.assertEqual(parse_duration("2d12h"), timedelta(days=2, hours=12))

    def test_combined_all(self):
        self.assertEqual(parse_duration("1d2h30m"), timedelta(days=1, hours=2, minutes=30))

    def test_uppercase(self):
        self.assertEqual(parse_duration("2H"), timedelta(hours=2))

    def test_empty(self):
        self.assertIsNone(parse_duration(""))

    def test_invalid(self):
        self.assertIsNone(parse_duration("abc"))

    def test_zero(self):
        self.assertIsNone(parse_duration("0m"))


class TestDurationFromTimestamp(unittest.TestCase):
    """Test timestamp to duration conversion."""

    def test_future_timestamp(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=2, minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = duration_from_timestamp(future)
        self.assertIn("h", result)

    def test_expired_timestamp(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(duration_from_timestamp(past), "expired")

    def test_invalid_timestamp(self):
        self.assertEqual(duration_from_timestamp("not-a-date"), "")


class TestDurationValidator(unittest.TestCase):
    """Test DurationValidator."""

    def setUp(self):
        self.validator = DurationValidator()

    def test_valid_30m(self):
        self.assertTrue(self.validator.validate("30m").is_valid)

    def test_valid_2h(self):
        self.assertTrue(self.validator.validate("2h").is_valid)

    def test_valid_1d(self):
        self.assertTrue(self.validator.validate("1d").is_valid)

    def test_valid_combined(self):
        self.assertTrue(self.validator.validate("1h30m").is_valid)

    def test_invalid(self):
        self.assertFalse(self.validator.validate("abc").is_valid)

    def test_empty_allowed(self):
        self.assertTrue(self.validator.validate("").is_valid)


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


class TestFormatLocalTime(unittest.TestCase):
    """Test format_local_time utility function."""

    def test_utc_timestamp_with_z_suffix(self):
        """Test converting UTC timestamp with Z suffix to local time."""
        result = format_local_time("2026-05-02T19:38:32Z")
        self.assertNotEqual(result, "2026-05-02T19:38:32Z")
        self.assertIn("2026", result)
        self.assertNotIn("Z", result)

    def test_utc_timestamp_with_microseconds(self):
        """Test converting UTC timestamp with microseconds."""
        result = format_local_time("2026-05-02T19:38:32.610852Z")
        self.assertNotEqual(result, "2026-05-02T19:38:32.610852Z")
        self.assertIn("2026", result)

    def test_utc_timestamp_with_offset(self):
        """Test converting UTC timestamp with +00:00 offset."""
        result = format_local_time("2026-05-02T19:38:32+00:00")
        self.assertIn("2026", result)
        self.assertNotIn("+00:00", result)

    def test_invalid_timestamp_returns_raw(self):
        """Test that invalid timestamp returns the raw string."""
        result = format_local_time("not-a-timestamp")
        self.assertEqual(result, "not-a-timestamp")

    def test_empty_string_returns_raw(self):
        """Test that empty string returns the raw string."""
        result = format_local_time("")
        self.assertEqual(result, "")

    def test_output_format(self):
        """Test that output matches expected format YYYY-MM-DD HH:MM TZ."""
        result = format_local_time("2026-01-15T12:00:00Z")
        parts = result.split()
        self.assertEqual(len(parts), 3)
        self.assertRegex(parts[0], r'\d{4}-\d{2}-\d{2}')
        self.assertRegex(parts[1], r'\d{2}:\d{2}')

    def test_known_utc_midnight(self):
        """Test that UTC midnight converts correctly."""
        result = format_local_time("2026-06-15T00:00:00Z")
        self.assertIn("2026", result)
        self.assertNotIn("T00:00:00", result)


if __name__ == '__main__':
    unittest.main()
