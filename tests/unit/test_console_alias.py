"""Tests for the 'console' command alias (Issue #389)."""

import sys
from unittest.mock import patch, MagicMock

import ai_guardian


class TestConsoleAlias:
    """Test that 'console' works as an alias for 'tui'."""

    @patch("ai_guardian.tui.AIGuardianTUI")
    def test_console_launches_tui(self, mock_tui_cls):
        mock_app = MagicMock()
        mock_tui_cls.return_value = mock_app

        with patch.object(sys, "argv", ["ai-guardian", "console"]):
            result = ai_guardian.main()

        mock_tui_cls.assert_called_once()
        mock_app.run.assert_called_once()
        assert result == 0

    @patch("ai_guardian.tui.AIGuardianTUI")
    def test_tui_still_works(self, mock_tui_cls):
        mock_app = MagicMock()
        mock_tui_cls.return_value = mock_app

        with patch.object(sys, "argv", ["ai-guardian", "tui"]):
            result = ai_guardian.main()

        mock_tui_cls.assert_called_once()
        mock_app.run.assert_called_once()
        assert result == 0

    def test_help_shows_console_command(self, capsys):
        with patch.object(sys, "argv", ["ai-guardian", "--help"]):
            try:
                ai_guardian.main()
            except SystemExit:
                pass
        captured = capsys.readouterr()
        assert "console" in captured.out
        assert "tui" in captured.out

    def test_console_help_shows_alias(self, capsys):
        with patch.object(sys, "argv", ["ai-guardian", "console", "--help"]):
            try:
                ai_guardian.main()
            except SystemExit:
                pass
        captured = capsys.readouterr()
        assert "alias" in captured.out.lower() or "console" in captured.out.lower()
