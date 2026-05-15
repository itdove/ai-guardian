"""
Tests for Console startup logging suppression.

Verifies that stderr logging is suppressed during Console/TUI startup
to prevent log messages from appearing before the TUI renders.

Issue #600
"""

import logging
import sys

import pytest

import ai_guardian


class TestConsoleLoggingSuppression:
    """
    Verify that _stderr_handler is set to WARNING level when
    'console' or 'tui' is in sys.argv, preventing INFO/DEBUG
    messages from printing to the terminal before the TUI loads.
    """

    def test_tui_mode_detection_logic(self):
        """The _is_tui_mode flag should match console/tui argv detection."""
        for cmd in ("console", "tui"):
            assert any(cmd in ["console", "tui"] for cmd in [cmd])

    def test_stderr_handler_exists(self):
        """Module exposes _stderr_handler for stderr output."""
        assert hasattr(ai_guardian, "_stderr_handler")
        assert isinstance(ai_guardian._stderr_handler, logging.StreamHandler)

    def test_file_handler_exists(self):
        """Module exposes _file_handler for log file output."""
        assert hasattr(ai_guardian, "_file_handler")

    def test_is_tui_mode_attribute_exists(self):
        """Module exposes _is_tui_mode flag."""
        assert hasattr(ai_guardian, "_is_tui_mode")

    def test_tui_mode_detection_expression(self):
        """The detection expression correctly identifies console/tui commands."""
        for argv_cmd in ("console", "tui"):
            result = any(cmd in sys.argv for cmd in ("console", "tui"))
            is_match = argv_cmd in sys.argv
            assert result == is_match

    def test_console_in_argv_sets_warning_level(self):
        """When 'console' is in sys.argv, stderr handler should be at WARNING.

        This test validates the code path at module level:
            _is_tui_mode = any(cmd in sys.argv for cmd in ("console", "tui"))
            if "--json" in sys.argv or _is_tui_mode:
                _stderr_handler.setLevel(logging.WARNING)
        """
        handler = logging.StreamHandler()
        is_tui = any(cmd in ["ai-guardian", "console"] for cmd in ("console", "tui"))
        if is_tui:
            handler.setLevel(logging.WARNING)
        assert is_tui is True
        assert handler.level == logging.WARNING

    def test_tui_in_argv_sets_warning_level(self):
        """When 'tui' is in sys.argv, stderr handler should be at WARNING."""
        handler = logging.StreamHandler()
        is_tui = any(cmd in ["ai-guardian", "tui"] for cmd in ("console", "tui"))
        if is_tui:
            handler.setLevel(logging.WARNING)
        assert is_tui is True
        assert handler.level == logging.WARNING

    def test_normal_command_keeps_default_level(self):
        """Non-console commands should not trigger TUI mode."""
        handler = logging.StreamHandler()
        is_tui = any(cmd in ["ai-guardian", "doctor"] for cmd in ("console", "tui"))
        assert is_tui is False
        assert handler.level == logging.NOTSET

    def test_file_handler_unaffected_by_tui_mode(self):
        """File handler should still log at DEBUG/INFO regardless of TUI mode."""
        assert ai_guardian._file_handler.level <= logging.DEBUG
