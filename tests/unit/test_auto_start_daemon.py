"""Tests for daemon auto-start on CLI commands (Issue #680)."""

from unittest import mock

from ai_guardian.cli import _ensure_daemon_started


class TestEnsureDaemonStarted:
    def test_starts_when_not_running(self):
        with mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=False), \
             mock.patch("ai_guardian.daemon.client.start_daemon_background") as mock_start:
            _ensure_daemon_started()

        mock_start.assert_called_once()

    def test_skips_when_already_running(self):
        with mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True), \
             mock.patch("ai_guardian.daemon.client.start_daemon_background") as mock_start:
            _ensure_daemon_started()

        mock_start.assert_not_called()

    def test_silences_runtime_errors(self):
        with mock.patch("ai_guardian.daemon.client.is_daemon_running", side_effect=RuntimeError("fail")):
            _ensure_daemon_started()
