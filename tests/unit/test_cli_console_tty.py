"""
Tests for Console TTY guard (Issue #627).

Verifies that `ai-guardian console` refuses to run when stdin is not
an interactive terminal (i.e., inside an AI agent session).
"""

import sys
from unittest.mock import MagicMock, patch

import pytest


class TestConsoleTTYGuard:
    """Console must refuse to run when stdin is not a TTY."""

    @patch("sys.stdin")
    def test_console_refuses_non_tty(self, mock_stdin):
        """Console should exit with error when stdin is not a TTY."""
        mock_stdin.isatty.return_value = False

        from ai_guardian.cli import main

        with patch("sys.argv", ["ai-guardian", "console"]):
            with patch("sys.stderr") as mock_stderr:
                result = main()

        assert result == 1

    @patch("sys.stdin")
    def test_console_error_message(self, mock_stdin, capsys):
        """Error message should tell user to run directly in terminal."""
        mock_stdin.isatty.return_value = False

        from ai_guardian.cli import main

        with patch("sys.argv", ["ai-guardian", "console"]):
            result = main()

        captured = capsys.readouterr()
        assert "interactive terminal" in captured.err
        assert "ai-guardian console" in captured.err

    @patch("ai_guardian.tui.AIGuardianTUI")
    @patch("sys.stdin")
    def test_console_allows_tty(self, mock_stdin, mock_tui_cls):
        """Console should proceed when stdin is a TTY."""
        mock_stdin.isatty.return_value = True
        mock_app = MagicMock()
        mock_tui_cls.return_value = mock_app

        from ai_guardian.cli import main

        with patch("sys.argv", ["ai-guardian", "console"]):
            result = main()

        assert result == 0
        mock_app.run.assert_called_once()

    @patch("sys.stdin")
    def test_tui_alias_also_guarded(self, mock_stdin):
        """The 'tui' alias should have the same TTY guard."""
        mock_stdin.isatty.return_value = False

        from ai_guardian.cli import main

        with patch("sys.argv", ["ai-guardian", "tui"]):
            result = main()

        assert result == 1
