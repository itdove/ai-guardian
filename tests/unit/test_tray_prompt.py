"""Tests for tray prompt Textual app and CLI handler."""

import json
import sys
from unittest import mock

import pytest


class TestHandleTrayPrompt:
    """Tests for _handle_tray_prompt CLI handler."""

    def test_rejects_invalid_json(self):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        args = mock.MagicMock()
        args.params = "not valid json"
        args.template = "echo"
        args.type = "terminal"
        result = _handle_tray_prompt(args)
        assert result == 1

    def test_rejects_non_array_params(self):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        args = mock.MagicMock()
        args.params = '{"name": "not-an-array"}'
        args.template = "echo"
        args.type = "terminal"
        result = _handle_tray_prompt(args)
        assert result == 1

    def test_rejects_non_tty(self):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        args = mock.MagicMock()
        args.params = '[{"name": "x"}]'
        args.template = "echo {x}"
        args.type = "terminal"
        with mock.patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            result = _handle_tray_prompt(args)
        assert result == 1

    def test_handles_import_error(self):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        args = mock.MagicMock()
        args.params = '[{"name": "x"}]'
        args.template = "echo {x}"
        args.type = "terminal"
        with mock.patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            with mock.patch.dict("sys.modules", {"ai_guardian.tui.tray_prompt": None}):
                result = _handle_tray_prompt(args)
        assert result == 1

    def test_cancel_returns_zero(self):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        args = mock.MagicMock()
        args.params = '[{"name": "x"}]'
        args.template = "echo {x}"
        args.type = "background"
        mock_app = mock.MagicMock()
        mock_app.run.return_value = None
        with mock.patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            with mock.patch("ai_guardian.tui.tray_prompt.TrayPromptApp", return_value=mock_app):
                result = _handle_tray_prompt(args)
        assert result == 0

    def test_info_type_runs_subprocess(self):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        args = mock.MagicMock()
        args.params = '[]'
        args.template = "echo hello"
        args.type = "background"
        mock_app = mock.MagicMock()
        mock_app.run.return_value = "echo hello"
        with mock.patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            with mock.patch("ai_guardian.tui.tray_prompt.TrayPromptApp", return_value=mock_app):
                with mock.patch("subprocess.run") as mock_run:
                    mock_run.return_value = mock.MagicMock(returncode=0)
                    result = _handle_tray_prompt(args)
        assert result == 0
        mock_run.assert_called_once()


class TestTrayPromptAppCreation:
    """Tests for TrayPromptApp construction (no async needed)."""

    def test_app_stores_params(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        params = [{"name": "env", "hint": "Environment", "default": "dev"}]
        app = TrayPromptApp(params, "deploy {env}", "terminal")
        assert app._params == params
        assert app._command_template == "deploy {env}"
        assert app._command_type == "terminal"

    def test_app_with_empty_params(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        app = TrayPromptApp([], "echo hello", "background")
        assert app._params == []

    def test_app_with_options_param(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        params = [{"name": "env", "options": ["dev", "staging", "prod"]}]
        app = TrayPromptApp(params, "deploy {env}")
        assert app._params[0]["options"] == ["dev", "staging", "prod"]
