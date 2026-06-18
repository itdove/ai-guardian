"""Tests for web config_helpers shared load/save utilities."""

import json
from unittest.mock import patch

import pytest

from ai_guardian.web.config_helpers import load_web_config, save_web_config


class TestLoadWebConfig:
    """Tests for load_web_config."""

    def test_returns_empty_dict_when_missing(self, tmp_path):
        with patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path), \
             patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path):
            assert load_web_config() == {}

    def test_returns_empty_dict_on_invalid_json(self, tmp_path):
        (tmp_path / "ai-guardian.json").write_text("not json", encoding="utf-8")
        with patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path), \
             patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path):
            assert load_web_config() == {}

    def test_returns_parsed_dict(self, tmp_path):
        data = {"features": {"secrets": True}}
        (tmp_path / "ai-guardian.json").write_text(json.dumps(data), encoding="utf-8")
        with patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path), \
             patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path):
            assert load_web_config() == data


class TestSaveWebConfig:
    """Tests for save_web_config."""

    def test_creates_file(self, tmp_path):
        with patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path), \
             patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path):
            save_web_config({"key": "value"})
        written = (tmp_path / "ai-guardian.json").read_text(encoding="utf-8")
        assert json.loads(written) == {"key": "value"}
        assert written.endswith("\n")

    def test_creates_parent_dirs(self, tmp_path):
        nested = tmp_path / "sub" / "dir"
        with patch("ai_guardian.config_utils.get_config_dir", return_value=nested), \
             patch("ai_guardian.config_writer.get_config_dir", return_value=nested):
            save_web_config({"a": 1})
        assert (nested / "ai-guardian.json").exists()

    def test_indent_is_two(self, tmp_path):
        with patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path), \
             patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path):
            save_web_config({"a": 1})
        written = (tmp_path / "ai-guardian.json").read_text(encoding="utf-8")
        assert '  "a": 1' in written


class TestRoundTrip:
    """Verify save then load returns same data."""

    def test_round_trip(self, tmp_path):
        data = {"features": {"pii": True}, "permissions": {"rules": []}}
        with patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path), \
             patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path):
            save_web_config(data)
            assert load_web_config() == data
