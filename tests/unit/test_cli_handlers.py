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
    def test_always_returns_auto(self):
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
    def test_is_noop(self):
        _set_daemon_mode_in_config("daemon")


class TestDaemonReloadCommand:
    def test_reload_when_running(self, capsys):
        args = mock.MagicMock()
        args.daemon_command = "reload"

        with mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True), \
             mock.patch("ai_guardian.daemon.client.send_reload_config", return_value=True), \
             mock.patch("ai_guardian.cli_handlers._get_client_timeout", return_value=2.0):
            result = _handle_daemon_command(args)

        assert result == 0
        assert "config reloaded" in capsys.readouterr().out

    def test_reload_when_not_running(self, capsys):
        args = mock.MagicMock()
        args.daemon_command = "reload"

        with mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=False), \
             mock.patch("ai_guardian.daemon.client.send_reload_config") as mock_reload:
            result = _handle_daemon_command(args)

        assert result == 1
        assert "not running" in capsys.readouterr().err
        mock_reload.assert_not_called()

    def test_reload_send_fails(self, capsys):
        args = mock.MagicMock()
        args.daemon_command = "reload"

        with mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True), \
             mock.patch("ai_guardian.daemon.client.send_reload_config", return_value=False), \
             mock.patch("ai_guardian.cli_handlers._get_client_timeout", return_value=2.0):
            result = _handle_daemon_command(args)

        assert result == 1
        assert "Failed" in capsys.readouterr().err


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
