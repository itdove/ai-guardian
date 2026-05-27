"""Tests for tray prompt Textual app and CLI handler."""

import json
import os
import sys
import tempfile
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
        args.template = "echo {tray.x}"
        args.type = "terminal"
        with mock.patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            result = _handle_tray_prompt(args)
        assert result == 1

    def test_handles_import_error(self):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        args = mock.MagicMock()
        args.params = '[{"name": "x"}]'
        args.template = "echo {tray.x}"
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
        args.template = "echo {tray.x}"
        args.type = "background"
        args.output_file = None
        mock_app = mock.MagicMock()
        mock_app.run.return_value = None
        with mock.patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            with mock.patch("ai_guardian.tui.tray_prompt.TrayPromptApp", return_value=mock_app):
                result = _handle_tray_prompt(args)
        assert result == 0

    def test_cancel_creates_empty_output_file(self):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cmd") as tmp:
            tmp_path = tmp.name
        os.unlink(tmp_path)
        try:
            args = mock.MagicMock()
            args.params = '[{"name": "x"}]'
            args.template = "echo {tray.x}"
            args.type = "terminal"
            args.output_file = tmp_path
            mock_app = mock.MagicMock()
            mock_app.run.return_value = None
            with mock.patch("sys.stdin") as mock_stdin:
                mock_stdin.isatty.return_value = True
                with mock.patch("ai_guardian.tui.tray_prompt.TrayPromptApp", return_value=mock_app):
                    result = _handle_tray_prompt(args)
            assert result == 0
            assert os.path.exists(tmp_path)
            with open(tmp_path) as f:
                assert f.read() == ""
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_submit_writes_command_to_output_file(self):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cmd") as tmp:
            tmp_path = tmp.name
        os.unlink(tmp_path)
        try:
            args = mock.MagicMock()
            args.params = '[]'
            args.template = "echo hello"
            args.type = "terminal"
            args.output_file = tmp_path
            mock_app = mock.MagicMock()
            mock_app.run.return_value = "echo hello"
            with mock.patch("sys.stdin") as mock_stdin:
                mock_stdin.isatty.return_value = True
                with mock.patch("ai_guardian.tui.tray_prompt.TrayPromptApp", return_value=mock_app):
                    result = _handle_tray_prompt(args)
            assert result == 0
            with open(tmp_path) as f:
                assert f.read() == "echo hello"
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_submit_prints_to_stdout_without_output_file(self, capsys):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        args = mock.MagicMock()
        args.params = '[]'
        args.template = "echo hello"
        args.type = "terminal"
        args.output_file = None
        mock_app = mock.MagicMock()
        mock_app.run.return_value = "echo hello"
        with mock.patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            with mock.patch("ai_guardian.tui.tray_prompt.TrayPromptApp", return_value=mock_app):
                result = _handle_tray_prompt(args)
        assert result == 0
        assert capsys.readouterr().out.strip() == "echo hello"

    def test_shell_operators_written_to_output_file(self):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cmd") as tmp:
            tmp_path = tmp.name
        os.unlink(tmp_path)
        try:
            args = mock.MagicMock()
            args.params = '[]'
            args.template = "echo a && echo b"
            args.type = "background"
            args.output_file = tmp_path
            mock_app = mock.MagicMock()
            mock_app.run.return_value = "echo a && echo b"
            with mock.patch("sys.stdin") as mock_stdin:
                mock_stdin.isatty.return_value = True
                with mock.patch("ai_guardian.tui.tray_prompt.TrayPromptApp", return_value=mock_app):
                    result = _handle_tray_prompt(args)
            assert result == 0
            with open(tmp_path) as f:
                assert f.read() == "echo a && echo b"
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


class TestTrayPromptAppCreation:
    """Tests for TrayPromptApp construction (no async needed)."""

    def test_app_stores_params(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        params = [{"name": "env", "hint": "Environment", "default": "dev"}]
        app = TrayPromptApp(params, "deploy {tray.env}", "terminal")
        assert app._params == params
        assert app._command_template == "deploy {tray.env}"
        assert app._command_type == "terminal"

    def test_app_with_empty_params(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        app = TrayPromptApp([], "echo hello", "background")
        assert app._params == []

    def test_app_with_options_param(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        params = [{"name": "env", "options": ["dev", "staging", "prod"]}]
        app = TrayPromptApp(params, "deploy {tray.env}")
        assert app._params[0]["options"] == ["dev", "staging", "prod"]

    def test_app_stores_typed_params(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        params = [
            {"name": "count", "type": "int", "min": 1, "max": 10},
            {"name": "flag", "type": "boolean", "default": "true"},
            {"name": "branch", "required": True, "pattern": "^[a-z]+$"},
        ]
        app = TrayPromptApp(params, "cmd {tray.count} {tray.flag} {tray.branch}")
        assert app._params[0]["type"] == "int"
        assert app._params[1]["type"] == "boolean"
        assert app._params[2]["required"] is True

    def test_app_with_combobox_param(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        params = [{"name": "tag", "type": "combobox", "options": ["latest", "stable"]}]
        app = TrayPromptApp(params, "deploy --tag {tray.tag}")
        assert app._params[0]["type"] == "combobox"
        assert app._params[0]["options"] == ["latest", "stable"]
