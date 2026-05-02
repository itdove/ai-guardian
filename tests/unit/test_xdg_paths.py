"""
Tests for XDG Base Directory compliance.

Verifies that get_state_dir(), get_cache_dir(), and migrate_state_files()
follow the XDG spec and maintain backward compatibility.
"""

import os
import json
from pathlib import Path
from unittest import mock

import pytest

from ai_guardian.config_utils import (
    get_cache_dir,
    get_config_dir,
    get_state_dir,
    migrate_state_files,
)


class TestGetStateDir:
    """Tests for get_state_dir() priority order."""

    def test_direct_override(self, tmp_path):
        custom = str(tmp_path / "custom-state")
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_STATE_DIR": custom}, clear=False):
            result = get_state_dir()
        assert result == Path(custom)

    def test_xdg_state_home(self, tmp_path):
        xdg = str(tmp_path / "xdg-state")
        env = {"XDG_STATE_HOME": xdg}
        with mock.patch.dict(os.environ, env, clear=False):
            os.environ.pop("AI_GUARDIAN_STATE_DIR", None)
            result = get_state_dir()
        assert result == Path(xdg) / "ai-guardian"

    def test_default_fallback(self, tmp_path):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AI_GUARDIAN_STATE_DIR", None)
            os.environ.pop("XDG_STATE_HOME", None)
            result = get_state_dir()
        assert result == Path("~/.local/state/ai-guardian").expanduser()

    def test_direct_override_takes_precedence_over_xdg(self, tmp_path):
        custom = str(tmp_path / "direct")
        xdg = str(tmp_path / "xdg")
        env = {"AI_GUARDIAN_STATE_DIR": custom, "XDG_STATE_HOME": xdg}
        with mock.patch.dict(os.environ, env, clear=False):
            result = get_state_dir()
        assert result == Path(custom)

    def test_expanduser_on_tilde(self, tmp_path):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_STATE_DIR": "~/my-state"}, clear=False):
            result = get_state_dir()
        assert "~" not in str(result)


class TestGetCacheDir:
    """Tests for get_cache_dir() priority order."""

    def test_direct_override(self, tmp_path):
        custom = str(tmp_path / "custom-cache")
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_CACHE_DIR": custom}, clear=False):
            result = get_cache_dir()
        assert result == Path(custom)

    def test_xdg_cache_home(self, tmp_path):
        xdg = str(tmp_path / "xdg-cache")
        env = {"XDG_CACHE_HOME": xdg}
        with mock.patch.dict(os.environ, env, clear=False):
            os.environ.pop("AI_GUARDIAN_CACHE_DIR", None)
            result = get_cache_dir()
        assert result == Path(xdg) / "ai-guardian"

    def test_default_fallback(self, tmp_path):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AI_GUARDIAN_CACHE_DIR", None)
            os.environ.pop("XDG_CACHE_HOME", None)
            result = get_cache_dir()
        assert result == Path("~/.cache/ai-guardian").expanduser()

    def test_direct_override_takes_precedence_over_xdg(self, tmp_path):
        custom = str(tmp_path / "direct")
        xdg = str(tmp_path / "xdg")
        env = {"AI_GUARDIAN_CACHE_DIR": custom, "XDG_CACHE_HOME": xdg}
        with mock.patch.dict(os.environ, env, clear=False):
            result = get_cache_dir()
        assert result == Path(custom)

    def test_expanduser_on_tilde(self, tmp_path):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_CACHE_DIR": "~/my-cache"}, clear=False):
            result = get_cache_dir()
        assert "~" not in str(result)


class TestMigrateStateFiles:
    """Tests for backward-compatible migration of state files."""

    def test_migrates_violations_from_config_to_state(self, tmp_path):
        config_dir = tmp_path / "config"
        state_dir = tmp_path / "state"
        config_dir.mkdir()

        violations = config_dir / "violations.jsonl"
        violations.write_text('{"test": true}\n')

        env = {
            "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
            "AI_GUARDIAN_STATE_DIR": str(state_dir),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            migrate_state_files()

        assert (state_dir / "violations.jsonl").exists()
        assert (state_dir / "violations.jsonl").read_text() == '{"test": true}\n'

    def test_migrates_log_from_config_to_state(self, tmp_path):
        config_dir = tmp_path / "config"
        state_dir = tmp_path / "state"
        config_dir.mkdir()

        log_file = config_dir / "ai-guardian.log"
        log_file.write_text("log entry\n")

        env = {
            "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
            "AI_GUARDIAN_STATE_DIR": str(state_dir),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            migrate_state_files()

        assert (state_dir / "ai-guardian.log").exists()
        assert (state_dir / "ai-guardian.log").read_text() == "log entry\n"

    def test_does_not_overwrite_existing_state_files(self, tmp_path):
        config_dir = tmp_path / "config"
        state_dir = tmp_path / "state"
        config_dir.mkdir()
        state_dir.mkdir()

        (config_dir / "violations.jsonl").write_text("old data\n")
        (state_dir / "violations.jsonl").write_text("new data\n")

        env = {
            "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
            "AI_GUARDIAN_STATE_DIR": str(state_dir),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            migrate_state_files()

        assert (state_dir / "violations.jsonl").read_text() == "new data\n"

    def test_noop_when_no_old_files(self, tmp_path):
        config_dir = tmp_path / "config"
        state_dir = tmp_path / "state"
        config_dir.mkdir()

        env = {
            "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
            "AI_GUARDIAN_STATE_DIR": str(state_dir),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            migrate_state_files()

        assert not state_dir.exists() or not any(state_dir.iterdir())

    def test_noop_when_same_directory(self, tmp_path):
        same_dir = tmp_path / "same"
        same_dir.mkdir()
        (same_dir / "violations.jsonl").write_text("data\n")

        env = {
            "AI_GUARDIAN_CONFIG_DIR": str(same_dir),
            "AI_GUARDIAN_STATE_DIR": str(same_dir),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            migrate_state_files()

        assert (same_dir / "violations.jsonl").read_text() == "data\n"


class TestViolationLoggerUsesStateDir:
    """Test that ViolationLogger stores violations in state dir."""

    def test_default_path_is_state_dir(self, tmp_path):
        state_dir = tmp_path / "state"
        state_dir.mkdir()

        env = {"AI_GUARDIAN_STATE_DIR": str(state_dir)}
        with mock.patch.dict(os.environ, env, clear=False):
            from ai_guardian.violation_logger import ViolationLogger
            vl = ViolationLogger()
            assert vl.log_path == state_dir / "violations.jsonl"

    def test_custom_path_overrides_state_dir(self, tmp_path):
        custom = tmp_path / "custom" / "my-violations.jsonl"
        from ai_guardian.violation_logger import ViolationLogger
        vl = ViolationLogger(log_path=custom)
        assert vl.log_path == custom
