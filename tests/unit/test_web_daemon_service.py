"""Tests for web console DaemonService."""

from unittest import mock

import pytest

from ai_guardian.web.services.daemon_service import DaemonService


@pytest.fixture
def mock_target():
    target = mock.MagicMock()
    target.name = "test-daemon"
    target.runtime = "local"
    target.status = "running"
    return target


@pytest.fixture
def service():
    svc = DaemonService()
    svc._discovery = mock.MagicMock()
    svc._client = mock.MagicMock()
    return svc


class TestDaemonServiceTargets:
    def test_refresh_targets(self, service, mock_target):
        service._discovery.discover_all.return_value = [mock_target]
        targets = service.refresh_targets()
        assert len(targets) == 1
        assert targets[0].name == "test-daemon"

    def test_get_target_by_name_found(self, service, mock_target):
        service._targets = [mock_target]
        result = service.get_target_by_name("test-daemon")
        assert result is mock_target

    def test_get_target_by_name_not_found(self, service, mock_target):
        service._targets = [mock_target]
        result = service.get_target_by_name("nonexistent")
        assert result is None

    def test_targets_property(self, service, mock_target):
        service._targets = [mock_target]
        assert service.targets == [mock_target]


class TestDaemonServiceStatus:
    def test_get_all_daemon_status(self, service, mock_target):
        service._targets = [mock_target]
        service._client.get_status.return_value = {
            "request_count": 42,
            "blocked_count": 3,
        }
        result = service.get_all_daemon_status()
        assert len(result) == 1
        assert result[0]["target"] is mock_target
        assert result[0]["status"]["request_count"] == 42

    def test_get_all_daemon_status_handles_error(self, service, mock_target):
        service._targets = [mock_target]
        service._client.get_status.side_effect = Exception("connection failed")
        result = service.get_all_daemon_status()
        assert len(result) == 1
        assert result[0]["status"] is None


class TestDaemonServiceConfig:
    def test_get_daemon_config(self, service, mock_target):
        service._client.get_config.return_value = {
            "features": {"secret_scanning": True}
        }
        result = service.get_daemon_config(mock_target)
        assert result["features"]["secret_scanning"] is True

    def test_get_daemon_config_handles_error(self, service, mock_target):
        service._client.get_config.side_effect = Exception("fail")
        result = service.get_daemon_config(mock_target)
        assert result is None


class TestDaemonServiceViolations:
    def test_get_daemon_violations(self, service, mock_target):
        service._client.get_violations.return_value = {
            "violations": [{"type": "secret_detected"}],
            "count": 1,
        }
        result = service.get_daemon_violations(mock_target, limit=10)
        assert result["count"] == 1
        service._client.get_violations.assert_called_once_with(
            mock_target, limit=10, violation_type=None
        )

    def test_get_daemon_violations_with_type(self, service, mock_target):
        service._client.get_violations.return_value = {"violations": [], "count": 0}
        service.get_daemon_violations(mock_target, violation_type="pii_detected")
        service._client.get_violations.assert_called_once_with(
            mock_target, limit=50, violation_type="pii_detected"
        )

    def test_get_daemon_violations_handles_error(self, service, mock_target):
        service._client.get_violations.side_effect = Exception("fail")
        result = service.get_daemon_violations(mock_target)
        assert result is None


class TestDaemonServiceMetrics:
    def test_get_daemon_metrics(self, service, mock_target):
        service._client.get_metrics.return_value = {
            "total_violations": 10,
            "by_type": {},
        }
        result = service.get_daemon_metrics(mock_target, since_days=7)
        assert result["total_violations"] == 10
        service._client.get_metrics.assert_called_once_with(mock_target, since_days=7)

    def test_get_daemon_metrics_handles_error(self, service, mock_target):
        service._client.get_metrics.side_effect = Exception("fail")
        result = service.get_daemon_metrics(mock_target)
        assert result is None


class TestDaemonServiceControl:
    def test_pause_daemon(self, service, mock_target):
        service._client.send_pause.return_value = True
        assert service.pause_daemon(mock_target, 30) is True
        service._client.send_pause.assert_called_once_with(mock_target, 30)

    def test_resume_daemon(self, service, mock_target):
        service._client.send_resume.return_value = True
        assert service.resume_daemon(mock_target) is True

    def test_pause_handles_error(self, service, mock_target):
        service._client.send_pause.side_effect = Exception("fail")
        assert service.pause_daemon(mock_target, 30) is False

    def test_reload_daemon_local(self, service, mock_target):
        with mock.patch(
            "ai_guardian.daemon.client.send_reload_config", return_value=True
        ):
            assert service.reload_daemon(mock_target) is True

    def test_reload_daemon_remote(self, service, mock_target):
        mock_target.runtime = "container"
        service._client._rest_request.return_value = {"status": "reloaded"}
        assert service.reload_daemon(mock_target) is True
