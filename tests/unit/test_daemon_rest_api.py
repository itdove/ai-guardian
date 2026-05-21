"""Tests for daemon REST API."""

import json
import threading
import time
from unittest import mock
from urllib.request import Request, urlopen

import pytest

from ai_guardian.daemon.rest_api import DaemonRestAPI


class MockDaemonState:
    """Minimal mock for DaemonState with pause/resume and stats."""

    def __init__(self):
        self._paused = False
        self._pause_minutes = 0
        self._config_reloaded = False

    def get_stats(self):
        return {
            "request_count": 42,
            "blocked_count": 3,
            "paused": self._paused,
            "uptime_seconds": 300.0,
        }

    def pause(self, minutes):
        self._paused = True
        self._pause_minutes = minutes

    def resume(self):
        self._paused = False
        self._pause_minutes = 0

    def force_reload_config(self):
        self._config_reloaded = True


@pytest.fixture
def rest_api():
    """Start a REST API server on a random port and yield (api, port)."""
    state = MockDaemonState()
    api = DaemonRestAPI(state=state, host="127.0.0.1", port=0)
    port = api.start()
    yield api, port, state
    api.stop()


class TestRestAPIEndpoints:
    def test_get_health(self, rest_api):
        api, port, state = rest_api
        url = f"http://127.0.0.1:{port}/api/health"
        with urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        assert data["status"] == "ok"

    def test_get_status(self, rest_api):
        api, port, state = rest_api
        url = f"http://127.0.0.1:{port}/api/status"
        with urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        assert data["running"] is True
        assert data["name"] == "ai-guardian"

    def test_get_stats(self, rest_api):
        api, port, state = rest_api
        url = f"http://127.0.0.1:{port}/api/stats"
        with urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        assert data["request_count"] == 42
        assert data["blocked_count"] == 3

    def test_post_pause(self, rest_api):
        api, port, state = rest_api
        url = f"http://127.0.0.1:{port}/api/pause"
        body = json.dumps({"minutes": 15}).encode("utf-8")
        req = Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        assert data["status"] == "paused"
        assert data["minutes"] == 15
        assert state._paused is True

    def test_post_resume(self, rest_api):
        api, port, state = rest_api
        state.pause(15)

        url = f"http://127.0.0.1:{port}/api/resume"
        req = Request(url, data=b"", method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Content-Length", "0")
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        assert data["status"] == "resumed"
        assert state._paused is False

    def test_post_reload(self, rest_api):
        api, port, state = rest_api
        url = f"http://127.0.0.1:{port}/api/reload"
        req = Request(url, data=b"", method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Content-Length", "0")
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        assert data["status"] == "config_reloaded"
        assert state._config_reloaded is True

    def test_unknown_path_returns_404(self, rest_api):
        api, port, state = rest_api
        url = f"http://127.0.0.1:{port}/api/nonexistent"
        from urllib.error import HTTPError
        with pytest.raises(HTTPError) as exc_info:
            urlopen(url, timeout=5)
        assert exc_info.value.code == 404


class TestRestAPILifecycle:
    def test_start_binds_port(self):
        state = MockDaemonState()
        api = DaemonRestAPI(state=state, host="127.0.0.1", port=0)
        port = api.start()
        assert port > 0
        assert api.port == port
        api.stop()

    def test_stop_shuts_down(self):
        state = MockDaemonState()
        api = DaemonRestAPI(state=state, host="127.0.0.1", port=0)
        port = api.start()
        api.stop()
        assert api._server is None

    def test_port_zero_before_start(self):
        state = MockDaemonState()
        api = DaemonRestAPI(state=state)
        assert api.port == 0
