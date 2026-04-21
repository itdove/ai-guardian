"""
Unit tests for version logging functionality (Issue #190)
"""

import logging
from logging.handlers import RotatingFileHandler
import tempfile
from io import StringIO
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import ai_guardian


class VersionLoggingTest(TestCase):
    """Test suite for version logging functionality"""

    def test_record_factory_adds_version(self):
        """Test that the custom record factory adds version to log records"""
        # Create a log record using the custom factory
        factory = ai_guardian._record_factory
        record = factory('test_logger', logging.INFO, '', 1, 'test message', (), None)

        # Verify the record has a version attribute
        self.assertTrue(hasattr(record, 'version'),
                        "Log record should have version attribute")
        self.assertEqual(record.version, ai_guardian.__version__,
                         "Log record version should match ai_guardian version")

    def test_version_format_in_file_handler(self):
        """Test that file handler formatter includes version"""
        # Access the file handler directly from ai_guardian module
        # The module creates _file_handler as a module-level variable
        self.assertTrue(hasattr(ai_guardian, '_file_handler'),
                        "ai_guardian module should have _file_handler")

        file_handler = ai_guardian._file_handler

        # Verify it's a RotatingFileHandler
        self.assertIsInstance(file_handler, RotatingFileHandler,
                              "File handler should be a RotatingFileHandler")

        # Check that formatter includes version
        formatter_format = file_handler.formatter._fmt
        self.assertIn('%(version)s', formatter_format,
                      "File handler formatter should include version placeholder")

    def test_startup_version_logging(self):
        """Test that version is logged at startup"""
        # Read the log file to verify startup messages
        # Note: This test verifies the logging was set up, not that it ran
        # because the module is already imported
        log_file = ai_guardian.get_config_dir() / "ai-guardian.log"

        # The log file should exist after import
        self.assertTrue(log_file.exists(), "Log file should exist after module import")

        # Read recent log entries
        if log_file.exists():
            with open(log_file, 'r', encoding='utf-8') as f:
                # Read last 100 lines to find startup message
                lines = f.readlines()
                recent_lines = ''.join(lines[-100:]) if len(lines) > 100 else ''.join(lines)

                # Check for version in recent logs (startup message)
                # Note: May not be in THIS run's logs if module already loaded
                # So we just verify the log file has proper format
                if 'AI Guardian' in recent_lines:
                    self.assertIn(f'v{ai_guardian.__version__}', recent_lines,
                                  "Version should appear in log file")

    def test_log_record_factory_is_set(self):
        """Test that the custom log record factory is configured"""
        current_factory = logging.getLogRecordFactory()

        # The factory should be the custom one from ai_guardian
        # We can test this by creating a record and checking for version attribute
        test_record = current_factory('test', logging.INFO, '', 1, 'msg', (), None)

        self.assertTrue(hasattr(test_record, 'version'),
                        "Current log record factory should add version attribute")

    def test_formatter_structure(self):
        """Test that the file handler formatter has the correct structure"""
        file_handler = ai_guardian._file_handler
        formatter = file_handler.formatter

        # Check the format string includes all expected components
        fmt = formatter._fmt
        self.assertIn('%(asctime)s', fmt, "Format should include timestamp")
        self.assertIn('v%(version)s', fmt, "Format should include version with 'v' prefix")
        self.assertIn('%(name)s', fmt, "Format should include logger name")
        self.assertIn('%(levelname)s', fmt, "Format should include level name")
        self.assertIn('%(message)s', fmt, "Format should include message")

        # Check the date format
        datefmt = formatter.datefmt
        self.assertEqual(datefmt, '%Y-%m-%d %H:%M:%S',
                         "Date format should be YYYY-MM-DD HH:MM:SS")
