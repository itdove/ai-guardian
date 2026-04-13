"""
Unit tests for config_utils module
"""

import unittest
from datetime import datetime, timezone, timedelta

from ai_guardian.config_utils import parse_iso8601, is_expired


class ConfigUtilsTest(unittest.TestCase):
    """Test suite for config_utils timestamp functions"""

    def test_parse_iso8601_with_z_suffix(self):
        """Test parsing ISO 8601 timestamp with Z suffix"""
        result = parse_iso8601("2026-04-13T12:00:00Z")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 4)
        self.assertEqual(result.day, 13)
        self.assertEqual(result.hour, 12)
        self.assertEqual(result.minute, 0)
        self.assertEqual(result.second, 0)
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_parse_iso8601_with_offset(self):
        """Test parsing ISO 8601 timestamp with +00:00 offset"""
        result = parse_iso8601("2026-04-13T12:00:00+00:00")
        self.assertIsNotNone(result)
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_parse_iso8601_without_timezone(self):
        """Test parsing ISO 8601 timestamp without timezone (assumes UTC)"""
        result = parse_iso8601("2026-04-13T12:00:00")
        self.assertIsNotNone(result)
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_parse_iso8601_with_different_timezone(self):
        """Test parsing ISO 8601 timestamp with non-UTC timezone (converts to UTC)"""
        # +05:00 timezone
        result = parse_iso8601("2026-04-13T17:00:00+05:00")
        self.assertIsNotNone(result)
        self.assertEqual(result.tzinfo, timezone.utc)
        # Should be converted to UTC (17:00 +05:00 = 12:00 UTC)
        self.assertEqual(result.hour, 12)

    def test_parse_iso8601_invalid_format(self):
        """Test parsing invalid timestamp format returns None"""
        result = parse_iso8601("invalid-timestamp")
        self.assertIsNone(result)

    def test_parse_iso8601_empty_string(self):
        """Test parsing empty string returns None"""
        result = parse_iso8601("")
        self.assertIsNone(result)

    def test_parse_iso8601_none_value(self):
        """Test parsing None value returns None"""
        result = parse_iso8601(None)
        self.assertIsNone(result)

    def test_parse_iso8601_non_string(self):
        """Test parsing non-string value returns None"""
        result = parse_iso8601(12345)
        self.assertIsNone(result)

    def test_is_expired_past_timestamp(self):
        """Test that past timestamps are expired"""
        past_timestamp = "2020-01-01T00:00:00Z"
        self.assertTrue(is_expired(past_timestamp))

    def test_is_expired_future_timestamp(self):
        """Test that future timestamps are not expired"""
        future_timestamp = "2099-12-31T23:59:59Z"
        self.assertFalse(is_expired(future_timestamp))

    def test_is_expired_with_current_time(self):
        """Test expiration check with custom current time"""
        valid_until = "2026-04-13T12:00:00Z"

        # Current time before valid_until - not expired
        current_time = datetime(2026, 4, 13, 11, 0, 0, tzinfo=timezone.utc)
        self.assertFalse(is_expired(valid_until, current_time))

        # Current time equal to valid_until - expired (boundary)
        current_time = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)
        self.assertTrue(is_expired(valid_until, current_time))

        # Current time after valid_until - expired
        current_time = datetime(2026, 4, 13, 13, 0, 0, tzinfo=timezone.utc)
        self.assertTrue(is_expired(valid_until, current_time))

    def test_is_expired_boundary_condition(self):
        """Test expiration exactly at the boundary (current_time == valid_until)"""
        valid_until = "2026-04-13T12:00:00Z"
        current_time = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)
        # Should be expired when current_time >= valid_until
        self.assertTrue(is_expired(valid_until, current_time))

    def test_is_expired_one_second_before(self):
        """Test not expired one second before valid_until"""
        valid_until = "2026-04-13T12:00:00Z"
        current_time = datetime(2026, 4, 13, 11, 59, 59, tzinfo=timezone.utc)
        self.assertFalse(is_expired(valid_until, current_time))

    def test_is_expired_one_second_after(self):
        """Test expired one second after valid_until"""
        valid_until = "2026-04-13T12:00:00Z"
        current_time = datetime(2026, 4, 13, 12, 0, 1, tzinfo=timezone.utc)
        self.assertTrue(is_expired(valid_until, current_time))

    def test_is_expired_invalid_timestamp(self):
        """Test that invalid timestamps are treated as non-expired (fail-safe)"""
        invalid_timestamp = "not-a-timestamp"
        self.assertFalse(is_expired(invalid_timestamp))

    def test_is_expired_empty_string(self):
        """Test that empty string is treated as non-expired (fail-safe)"""
        self.assertFalse(is_expired(""))

    def test_is_expired_with_current_time_no_timezone(self):
        """Test that current_time without timezone is handled correctly"""
        valid_until = "2026-04-13T12:00:00Z"
        # Current time without timezone - should be assumed UTC
        current_time = datetime(2026, 4, 13, 11, 0, 0)
        self.assertFalse(is_expired(valid_until, current_time))

    def test_parse_iso8601_with_milliseconds(self):
        """Test parsing timestamp with milliseconds"""
        result = parse_iso8601("2026-04-13T12:00:00.123Z")
        self.assertIsNotNone(result)
        self.assertEqual(result.microsecond, 123000)

    def test_is_expired_real_world_example(self):
        """Test real-world example: temporary debug access expires at noon"""
        debug_expires = "2026-04-13T12:00:00Z"

        # Morning: debug access still valid
        morning = datetime(2026, 4, 13, 9, 30, 0, tzinfo=timezone.utc)
        self.assertFalse(is_expired(debug_expires, morning))

        # Afternoon: debug access expired
        afternoon = datetime(2026, 4, 13, 14, 30, 0, tzinfo=timezone.utc)
        self.assertTrue(is_expired(debug_expires, afternoon))


if __name__ == '__main__':
    unittest.main()
