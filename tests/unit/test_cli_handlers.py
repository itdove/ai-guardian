"""Tests for ai_guardian.cli_handlers module."""

import json
from unittest import mock

from ai_guardian.cli_handlers import (
    _handle_violations_command,
    _get_daemon_mode,
    _get_client_timeout,
    _set_daemon_mode_in_config,
    _handle_daemon_command,
)


class TestGetDaemonMode:
    def test_default_is_auto(self):
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(None, None)):
            assert _get_daemon_mode() == "auto"

    def test_reads_env_var(self, monkeypatch):
        monkeypatch.setenv("AI_GUARDIAN_DAEMON_MODE", "daemon")
        assert _get_daemon_mode() == "daemon"

    def test_reads_from_config(self):
        config = {"daemon": {"mode": "local"}}
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(config, None)):
            assert _get_daemon_mode() == "local"

    def test_invalid_env_var_falls_through(self, monkeypatch):
        monkeypatch.setenv("AI_GUARDIAN_DAEMON_MODE", "invalid")
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(None, None)):
            assert _get_daemon_mode() == "auto"


class TestGetClientTimeout:
    def test_default(self):
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(None, None)):
            assert _get_client_timeout() == 2.0

    def test_reads_from_config(self):
        config = {"daemon": {"client_timeout_seconds": 5.0}}
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(config, None)):
            assert _get_client_timeout() == 5.0

    def test_clamped_low(self):
        config = {"daemon": {"client_timeout_seconds": 0.1}}
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(config, None)):
            assert _get_client_timeout() == 0.5

    def test_clamped_high(self):
        config = {"daemon": {"client_timeout_seconds": 99.0}}
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(config, None)):
            assert _get_client_timeout() == 10.0


class TestSetDaemonModeInConfig:
    def test_writes_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr("ai_guardian.cli_handlers.get_config_dir", lambda: tmp_path)
        config_path = tmp_path / "ai-guardian.json"

        _set_daemon_mode_in_config("daemon")

        config = json.loads(config_path.read_text())
        assert config["daemon"]["mode"] == "daemon"

    def test_updates_existing_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr("ai_guardian.cli_handlers.get_config_dir", lambda: tmp_path)
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps({"existing": "value"}))

        _set_daemon_mode_in_config("local")

        config = json.loads(config_path.read_text())
        assert config["daemon"]["mode"] == "local"
        assert config["existing"] == "value"


class TestBackwardCompatImports:
    def test_import_from_package_level(self):
        from ai_guardian import _handle_violations_command as hvc
        from ai_guardian import _get_daemon_mode as gdm
        from ai_guardian import _get_client_timeout as gct
        from ai_guardian import _set_daemon_mode_in_config as sdm
        from ai_guardian import _handle_daemon_command as hdc

        assert callable(hvc)
        assert callable(gdm)
        assert callable(gct)
        assert callable(sdm)
        assert callable(hdc)
