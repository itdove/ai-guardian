#!/usr/bin/env python3
"""
Tests for TUI Console Settings Panel
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from ai_guardian.tui.console_settings import (
    ConsoleSettingsContent,
    THEME_OPTIONS,
    DEFAULT_THEME,
    load_editor_theme,
    save_editor_theme,
)


class TestLoadEditorTheme:
    """Tests for loading the editor theme from config."""

    def test_default_when_no_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("ai_guardian.tui.console_settings.get_config_dir", return_value=Path(tmpdir)):
                assert load_editor_theme() == DEFAULT_THEME

    def test_reads_theme_from_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({
                "console": {"editor_theme": "dracula"}
            }), encoding="utf-8")
            with patch("ai_guardian.tui.console_settings.get_config_dir", return_value=Path(tmpdir)):
                assert load_editor_theme() == "dracula"

    def test_default_when_console_section_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({"permissions": {"enabled": True}}), encoding="utf-8")
            with patch("ai_guardian.tui.console_settings.get_config_dir", return_value=Path(tmpdir)):
                assert load_editor_theme() == DEFAULT_THEME

    def test_default_when_editor_theme_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({"console": {}}), encoding="utf-8")
            with patch("ai_guardian.tui.console_settings.get_config_dir", return_value=Path(tmpdir)):
                assert load_editor_theme() == DEFAULT_THEME

    def test_default_when_invalid_theme(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({
                "console": {"editor_theme": "nonexistent_theme"}
            }), encoding="utf-8")
            with patch("ai_guardian.tui.console_settings.get_config_dir", return_value=Path(tmpdir)):
                assert load_editor_theme() == DEFAULT_THEME

    def test_default_when_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text("not valid json{", encoding="utf-8")
            with patch("ai_guardian.tui.console_settings.get_config_dir", return_value=Path(tmpdir)):
                assert load_editor_theme() == DEFAULT_THEME

    @pytest.mark.parametrize("theme", ["monokai", "vscode_dark", "dracula", "github_light"])
    def test_all_valid_themes(self, theme):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({
                "console": {"editor_theme": theme}
            }), encoding="utf-8")
            with patch("ai_guardian.tui.console_settings.get_config_dir", return_value=Path(tmpdir)):
                assert load_editor_theme() == theme


class TestSaveEditorTheme:
    """Tests for saving the editor theme to config."""

    def test_save_to_new_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("ai_guardian.tui.console_settings.get_config_dir", return_value=Path(tmpdir)):
                success, error = save_editor_theme("dracula")
                assert success is True
                assert error is None

                config_path = Path(tmpdir) / "ai-guardian.json"
                config = json.loads(config_path.read_text(encoding="utf-8"))
                assert config["console"]["editor_theme"] == "dracula"

    def test_save_preserves_existing_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({
                "permissions": {"enabled": True},
                "console": {"editor_theme": "monokai"}
            }), encoding="utf-8")
            with patch("ai_guardian.tui.console_settings.get_config_dir", return_value=Path(tmpdir)):
                success, error = save_editor_theme("vscode_dark")
                assert success is True

                config = json.loads(config_path.read_text(encoding="utf-8"))
                assert config["console"]["editor_theme"] == "vscode_dark"
                assert config["permissions"]["enabled"] is True

    def test_save_creates_console_section(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({"permissions": {"enabled": True}}), encoding="utf-8")
            with patch("ai_guardian.tui.console_settings.get_config_dir", return_value=Path(tmpdir)):
                success, error = save_editor_theme("github_light")
                assert success is True

                config = json.loads(config_path.read_text(encoding="utf-8"))
                assert config["console"]["editor_theme"] == "github_light"

    def test_save_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "subdir"
            with patch("ai_guardian.tui.console_settings.get_config_dir", return_value=nested):
                success, error = save_editor_theme("monokai")
                assert success is True
                assert (nested / "ai-guardian.json").exists()


class TestThemeOptions:
    """Tests for theme option constants."""

    def test_default_theme_is_monokai(self):
        assert DEFAULT_THEME == "monokai"

    def test_four_theme_options(self):
        assert len(THEME_OPTIONS) == 4

    def test_all_themes_have_label_and_value(self):
        for label, value in THEME_OPTIONS:
            assert isinstance(label, str)
            assert isinstance(value, str)
            assert len(label) > 0
            assert len(value) > 0

    def test_default_theme_in_options(self):
        values = [v for _, v in THEME_OPTIONS]
        assert DEFAULT_THEME in values


class TestConsoleSettingsContent:
    """Tests for the console settings widget."""

    def test_instantiation(self):
        widget = ConsoleSettingsContent()
        assert widget is not None
