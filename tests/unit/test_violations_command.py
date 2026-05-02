"""Tests for the violations --clear --yes flag (Issue #360)."""

import argparse
from unittest.mock import patch, MagicMock

from ai_guardian import _handle_violations_command


class TestViolationsClearYesFlag:
    """Test --yes/-y flag for non-interactive violations --clear."""

    def _make_args(self, clear=False, yes=False, export=None, limit=10, type=None):
        return argparse.Namespace(
            clear=clear, yes=yes, export=export, limit=limit, type=type
        )

    @patch("ai_guardian.violation_logger.ViolationLogger")
    def test_clear_with_yes_skips_prompt(self, mock_logger_cls):
        mock_logger = MagicMock()
        mock_logger.clear_log.return_value = True
        mock_logger_cls.return_value = mock_logger

        args = self._make_args(clear=True, yes=True)

        with patch("builtins.input") as mock_input:
            result = _handle_violations_command(args)

        mock_input.assert_not_called()
        mock_logger.clear_log.assert_called_once()
        assert result == 0

    @patch("ai_guardian.violation_logger.ViolationLogger")
    def test_clear_without_yes_prompts(self, mock_logger_cls):
        mock_logger = MagicMock()
        mock_logger.clear_log.return_value = True
        mock_logger_cls.return_value = mock_logger

        args = self._make_args(clear=True, yes=False)

        with patch("builtins.input", return_value="y") as mock_input:
            result = _handle_violations_command(args)

        mock_input.assert_called_once()
        mock_logger.clear_log.assert_called_once()
        assert result == 0

    @patch("ai_guardian.violation_logger.ViolationLogger")
    def test_clear_without_yes_cancelled(self, mock_logger_cls):
        mock_logger = MagicMock()
        mock_logger_cls.return_value = mock_logger

        args = self._make_args(clear=True, yes=False)

        with patch("builtins.input", return_value="n"):
            result = _handle_violations_command(args)

        mock_logger.clear_log.assert_not_called()
        assert result == 0

    @patch("ai_guardian.violation_logger.ViolationLogger")
    def test_clear_with_yes_handles_failure(self, mock_logger_cls):
        mock_logger = MagicMock()
        mock_logger.clear_log.return_value = False
        mock_logger_cls.return_value = mock_logger

        args = self._make_args(clear=True, yes=True)

        with patch("builtins.input") as mock_input:
            result = _handle_violations_command(args)

        mock_input.assert_not_called()
        assert result == 1


class TestViolationsYesFlagCLIParsing:
    """Test that --yes/-y is correctly parsed by argparse."""

    def test_yes_long_flag_parsed(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--clear", action="store_true")
        parser.add_argument("--yes", "-y", action="store_true")
        args = parser.parse_args(["--clear", "--yes"])
        assert args.yes is True

    def test_y_short_flag_parsed(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--clear", action="store_true")
        parser.add_argument("--yes", "-y", action="store_true")
        args = parser.parse_args(["--clear", "-y"])
        assert args.yes is True

    def test_no_flag_defaults_false(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--clear", action="store_true")
        parser.add_argument("--yes", "-y", action="store_true")
        args = parser.parse_args(["--clear"])
        assert args.yes is False
