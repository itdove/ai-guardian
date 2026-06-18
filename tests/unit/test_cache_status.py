"""Tests for per-project config cache status feature (#1231)."""

import time
from unittest.mock import MagicMock, patch

import pytest


class TestDaemonStateGetProjectCacheStatus:
    """Test DaemonState.get_project_cache_status()."""

    def _make_state(self):
        with patch("ai_guardian.daemon.state.get_config_dir") as mock_dir, \
             patch("ai_guardian.daemon.state.get_state_dir") as mock_state:
            mock_dir.return_value = MagicMock()
            mock_dir.return_value.__truediv__ = lambda s, k: MagicMock(
                exists=lambda: False
            )
            mock_state.return_value = MagicMock()
            mock_state.return_value.__truediv__ = lambda s, k: MagicMock(
                exists=lambda: False
            )
            with patch("ai_guardian.daemon.state.DaemonState._reload_config"):
                with patch(
                    "ai_guardian.daemon.state.DaemonState._load_sessions"
                ):
                    with patch(
                        "ai_guardian.daemon.state.DaemonState._check_mcp_installed",
                        return_value=False,
                    ):
                        from ai_guardian.daemon.state import DaemonState
                        return DaemonState.__new__(DaemonState)

    def _init_state(self):
        import threading
        state = self._make_state()
        state._lock = threading.Lock()
        state._project_config_mtimes = {}
        state._project_config_paths = {}
        state._project_dir_last_seen = {}
        state._last_project_config_reload_at = None
        return state

    def test_empty_returns_empty_projects(self):
        state = self._init_state()
        with patch("ai_guardian.daemon.state._caches", {}, create=True), \
             patch("ai_guardian.config_loaders._caches", {}):
            result = state.get_project_cache_status()
        assert result["projects"] == []
        assert result["total_tracked"] == 0
        assert result["last_project_config_reload_at"] is None
        assert "timestamp" in result

    def test_single_project_no_override(self):
        state = self._init_state()
        now = time.monotonic()
        state._project_dir_last_seen = {"/home/user/myproject": now}
        state._project_config_paths = {"/home/user/myproject": None}
        state._project_config_mtimes = {}

        with patch("ai_guardian.config_loaders._caches", {}):
            result = state.get_project_cache_status()

        assert result["total_tracked"] == 1
        proj = result["projects"][0]
        assert proj["project_dir"] == "/home/user/myproject"
        assert proj["config_path"] is None
        assert proj["has_project_override"] is False
        assert proj["last_seen_seconds_ago"] >= 0

    def test_project_with_override(self):
        state = self._init_state()
        now = time.monotonic()
        config_path = "/home/user/proj/.ai-guardian/ai-guardian.json"
        state._project_dir_last_seen = {"/home/user/proj": now}
        state._project_config_paths = {"/home/user/proj": config_path}
        state._project_config_mtimes = {"/home/user/proj": 1718000000.0}

        with patch("ai_guardian.config_loaders._caches", {}):
            result = state.get_project_cache_status()

        proj = result["projects"][0]
        assert proj["has_project_override"] is True
        assert proj["config_path"] == config_path
        assert proj["config_mtime"] == 1718000000.0

    def test_multiple_projects_sorted(self):
        state = self._init_state()
        now = time.monotonic()
        state._project_dir_last_seen = {
            "/z/project": now,
            "/a/project": now - 10,
        }
        state._project_config_paths = {
            "/z/project": None,
            "/a/project": None,
        }

        with patch("ai_guardian.config_loaders._caches", {}):
            result = state.get_project_cache_status()

        assert result["total_tracked"] == 2
        assert result["projects"][0]["project_dir"] == "/a/project"
        assert result["projects"][1]["project_dir"] == "/z/project"

    def test_includes_config_loader_cache_data(self):
        from dataclasses import dataclass
        from typing import Any, Optional
        from pathlib import Path

        @dataclass
        class FakeCacheEntry:
            result: Any = None
            global_mtime: Optional[float] = 1718000100.0
            project_mtime: Optional[float] = 1718000200.0
            global_path: Optional[Path] = None
            project_path: Optional[Path] = None
            last_accessed: float = 0.0

        state = self._init_state()
        now = time.monotonic()
        config_path = "/proj/.ai-guardian/ai-guardian.json"
        state._project_dir_last_seen = {"/proj": now}
        state._project_config_paths = {"/proj": config_path}
        state._project_config_mtimes = {"/proj": 1718000200.0}

        fake_entry = FakeCacheEntry(
            global_path=Path("/home/.config/ai-guardian/ai-guardian.json"),
            project_path=Path(config_path),
            last_accessed=now - 5,
        )

        with patch(
            "ai_guardian.config_loaders._caches",
            {config_path: fake_entry},
        ):
            result = state.get_project_cache_status()

        proj = result["projects"][0]
        assert proj["global_config_path"] is not None
        assert proj["global_config_mtime"] == 1718000100.0
        assert proj["cached_project_path"] == config_path
        assert proj["cache_last_accessed_seconds_ago"] >= 4

    def test_last_reload_at_propagated(self):
        state = self._init_state()
        state._last_project_config_reload_at = 1718000500.0

        with patch("ai_guardian.config_loaders._caches", {}):
            result = state.get_project_cache_status()

        assert result["last_project_config_reload_at"] == 1718000500.0


class TestRestAPICacheStatusEndpoint:
    """Test GET /api/cache-status in the REST API."""

    def test_endpoint_calls_state_method(self):
        from ai_guardian.daemon.rest_api import _RestHandler

        handler = MagicMock(spec=_RestHandler)
        handler._check_auth = MagicMock(return_value=True)
        handler._send_json = MagicMock()
        handler.path = "/api/cache-status"
        handler.server = MagicMock()
        handler.server.daemon_state = MagicMock()
        handler.server.daemon_state.get_project_cache_status.return_value = {
            "projects": [],
            "total_tracked": 0,
        }

        handler.headers = MagicMock()

        _RestHandler.do_GET(handler)

        handler.server.daemon_state.get_project_cache_status.assert_called_once()
        handler._send_json.assert_called_once()
        result = handler._send_json.call_args[0][0]
        assert result["total_tracked"] == 0


class TestMultiDaemonClientCacheStatus:
    """Test MultiDaemonClient.get_cache_status()."""

    def test_local_cache_status_returns_structure(self):
        from ai_guardian.daemon.multi_client import MultiDaemonClient

        with patch("ai_guardian.config_loaders._caches", {}):
            result = MultiDaemonClient._local_cache_status()

        assert "projects" in result
        assert "total_tracked" in result
        assert "timestamp" in result
        assert isinstance(result["projects"], list)

    def test_local_cache_status_with_entries(self):
        from dataclasses import dataclass
        from typing import Any, Optional
        from pathlib import Path

        @dataclass
        class FakeCacheEntry:
            result: Any = None
            global_mtime: Optional[float] = 100.0
            project_mtime: Optional[float] = 200.0
            global_path: Optional[Path] = Path("/g/config.json")
            project_path: Optional[Path] = Path("/p/config.json")
            last_accessed: float = 0.0

        from ai_guardian.daemon.multi_client import MultiDaemonClient
        import time as _time

        entry = FakeCacheEntry(last_accessed=_time.monotonic())

        with patch(
            "ai_guardian.config_loaders._caches",
            {"/p/config.json": entry},
        ):
            result = MultiDaemonClient._local_cache_status()

        assert result["total_tracked"] == 1
        proj = result["projects"][0]
        assert proj["has_project_override"] is True
        assert proj["global_config_path"] == "/g/config.json"


    def test_get_cache_status_uses_rest_for_local_target(self):
        from ai_guardian.daemon.multi_client import MultiDaemonClient
        from ai_guardian.daemon.discovery import DaemonTarget

        client = MultiDaemonClient()
        target = MagicMock(spec=DaemonTarget)
        target.runtime = "local"

        with patch.object(
            client, "_rest_request", return_value={"projects": [], "total_tracked": 0}
        ) as mock_rest:
            result = client.get_cache_status(target)

        mock_rest.assert_called_once_with(target, "GET", "/api/cache-status")
        assert result["total_tracked"] == 0


class TestDaemonServiceCacheStatus:
    """Test DaemonService.get_cache_status()."""

    def test_returns_none_on_error(self):
        from ai_guardian.web.services.daemon_service import DaemonService

        service = DaemonService.__new__(DaemonService)
        service._client = MagicMock()
        service._client.get_cache_status.side_effect = Exception("fail")

        result = service.get_cache_status(MagicMock())
        assert result is None

    def test_delegates_to_client(self):
        from ai_guardian.web.services.daemon_service import DaemonService

        service = DaemonService.__new__(DaemonService)
        service._client = MagicMock()
        service._client.get_cache_status.return_value = {
            "projects": [], "total_tracked": 0,
        }

        target = MagicMock()
        result = service.get_cache_status(target)
        service._client.get_cache_status.assert_called_once_with(target)
        assert result["total_tracked"] == 0
