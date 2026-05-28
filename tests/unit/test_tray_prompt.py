"""Tests for tray prompt tkinter/Textual app and CLI handler."""

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

    def test_handles_import_error(self):
        from ai_guardian.cli_handlers import _handle_tray_prompt
        args = mock.MagicMock()
        args.params = '[{"name": "x"}]'
        args.template = "echo {tray.x}"
        args.type = "terminal"
        with mock.patch.dict("sys.modules", {"ai_guardian.tui.tray_prompt": None}):
            result = _handle_tray_prompt(args)
        assert result == 1

    def test_rejects_non_tty_when_textual_fallback(self):
        """When tkinter unavailable and no TTY, should reject."""
        from ai_guardian.cli_handlers import _handle_tray_prompt
        args = mock.MagicMock()
        args.params = '[{"name": "x"}]'
        args.template = "echo {tray.x}"
        args.type = "terminal"
        mock_app = mock.MagicMock()
        mock_app.needs_terminal = True
        with mock.patch("ai_guardian.tui.tray_prompt.TrayPromptApp", return_value=mock_app):
            with mock.patch("sys.stdin") as mock_stdin:
                mock_stdin.isatty.return_value = False
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
        mock_app.needs_terminal = False
        mock_app.run.return_value = None
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
            mock_app.needs_terminal = False
            mock_app.run.return_value = None
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
            mock_app.needs_terminal = False
            mock_app.run.return_value = "echo hello"
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
        mock_app.needs_terminal = False
        mock_app.run.return_value = "echo hello"
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
            mock_app.needs_terminal = False
            mock_app.run.return_value = "echo a && echo b"
            with mock.patch("ai_guardian.tui.tray_prompt.TrayPromptApp", return_value=mock_app):
                result = _handle_tray_prompt(args)
            assert result == 0
            with open(tmp_path) as f:
                assert f.read() == "echo a && echo b"
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


class TestTrayPromptAppCreation:
    """Tests for TrayPromptApp construction (no GUI needed)."""

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

    def test_result_defaults_to_none(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        app = TrayPromptApp([], "echo hello")
        assert app._result is None

    def test_extra_vars_stored(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        extra = {"working_dir": "/tmp"}
        app = TrayPromptApp([], "echo", extra_vars=extra)
        assert app._extra_vars == extra

    def test_extra_vars_default_empty(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        app = TrayPromptApp([], "echo")
        assert app._extra_vars == {}


class TestTrayPromptFallback:
    """Tests for tkinter-first / Textual-fallback selection."""

    def test_needs_terminal_false_when_tkinter_available(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        with mock.patch("ai_guardian.tui.tray_prompt._tkinter_available", return_value=True):
            app = TrayPromptApp([], "echo")
            assert app.needs_terminal is False

    def test_needs_terminal_true_when_tkinter_missing(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        with mock.patch("ai_guardian.tui.tray_prompt._tkinter_available", return_value=False):
            app = TrayPromptApp([], "echo")
            assert app.needs_terminal is True

    def test_tkinter_available_returns_bool(self):
        from ai_guardian.tui.tray_prompt import _tkinter_available
        result = _tkinter_available()
        assert isinstance(result, bool)


class TestTrayPromptResolveDefault:
    """Tests for _resolve_default without launching GUI."""

    def test_plain_string_unchanged(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        app = TrayPromptApp([], "echo", extra_vars={"working_dir": "/home"})
        assert app._resolve_default("hello") == "hello"

    def test_empty_string_unchanged(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        app = TrayPromptApp([], "echo")
        assert app._resolve_default("") == ""

    def test_none_unchanged(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        app = TrayPromptApp([], "echo")
        assert app._resolve_default(None) is None

    def test_no_extra_vars_unchanged(self):
        from ai_guardian.tui.tray_prompt import TrayPromptApp
        app = TrayPromptApp([], "echo")
        assert app._resolve_default("{tray.working_dir}") == "{tray.working_dir}"
