"""Tests for web config_helpers shared load/save utilities."""

import json
from dataclasses import dataclass
from unittest.mock import patch, MagicMock

from ai_guardian.web.config_helpers import (
    load_web_config,
    load_web_config_global,
    save_web_config,
    get_web_config_provenance,
    get_web_config_scope_label,
    set_daemon_service,
    set_current_daemon_name,
    _is_remote_target,
)


class TestLoadWebConfig:
    """Tests for load_web_config."""

    def test_returns_empty_dict_when_missing(self, tmp_path):
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path),
        ):
            assert load_web_config() == {}

    def test_returns_empty_dict_on_invalid_json(self, tmp_path):
        (tmp_path / "ai-guardian.json").write_text("not json", encoding="utf-8")
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path),
        ):
            assert load_web_config() == {}

    def test_returns_parsed_dict(self, tmp_path):
        data = {"features": {"secrets": True}}
        (tmp_path / "ai-guardian.json").write_text(json.dumps(data), encoding="utf-8")
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path),
        ):
            assert load_web_config() == data


class TestSaveWebConfig:
    """Tests for save_web_config."""

    def test_creates_file(self, tmp_path):
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path),
        ):
            save_web_config({"key": "value"})
        written = (tmp_path / "ai-guardian.json").read_text(encoding="utf-8")
        assert json.loads(written) == {"key": "value"}
        assert written.endswith("\n")

    def test_creates_parent_dirs(self, tmp_path):
        nested = tmp_path / "sub" / "dir"
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=nested),
            patch("ai_guardian.config_writer.get_config_dir", return_value=nested),
        ):
            save_web_config({"a": 1})
        assert (nested / "ai-guardian.json").exists()

    def test_indent_is_two(self, tmp_path):
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path),
        ):
            save_web_config({"a": 1})
        written = (tmp_path / "ai-guardian.json").read_text(encoding="utf-8")
        assert '  "a": 1' in written


class TestCacheInvalidation:
    """Tests for config cache invalidation on save (#1301)."""

    def test_save_clears_config_cache(self, tmp_path):
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_loaders._clear_config_cache") as mock_clear,
        ):
            save_web_config({"key": "value"})
        assert mock_clear.called

    def test_save_global_scope_clears_all_caches(self, tmp_path):
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_loaders._clear_config_cache") as mock_clear,
        ):
            save_web_config({"key": "value"})
        assert any(c == ((), {}) for c in mock_clear.call_args_list)


class TestRoundTrip:
    """Verify save then load returns same data."""

    def test_round_trip(self, tmp_path):
        data = {"features": {"pii": True}, "permissions": {"rules": []}}
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path),
        ):
            save_web_config(data)
            assert load_web_config() == data


@dataclass
class _FakeTarget:
    name: str = "test-daemon"
    runtime: str = "container"


class _FakeService:
    def __init__(self):
        self._target = _FakeTarget()
        self.calls = []

    def get_target_by_name(self, name):
        if name == self._target.name:
            return self._target
        return None

    def get_config_scoped(self, target, scope, project_dir=None):
        self.calls.append(("get_config_scoped", scope))
        return {"remote": True, "scope": scope}

    def get_config_provenance(self, target, project_dir=None):
        self.calls.append(("get_config_provenance",))
        return {"source": "remote"}

    def write_config_bulk(self, target, scope, config, project_dir=None):
        self.calls.append(("write_config_bulk", scope, config))
        return {"status": "ok"}


class TestIsRemoteTarget:
    """Tests for _is_remote_target helper."""

    def test_none_target(self):
        assert _is_remote_target(None) is False

    def test_local_target(self):
        assert _is_remote_target(_FakeTarget(runtime="local")) is False

    def test_container_target(self):
        assert _is_remote_target(_FakeTarget(runtime="container")) is True

    def test_kubernetes_target(self):
        assert _is_remote_target(_FakeTarget(runtime="kubernetes")) is True

    def test_manual_target(self):
        assert _is_remote_target(_FakeTarget(runtime="manual")) is True


class TestRemoteConfigRouting:
    """Tests for config_helpers routing to DaemonService for remote targets."""

    def setup_method(self):
        self._svc = _FakeService()
        set_daemon_service(self._svc)
        set_current_daemon_name("test-daemon")

    def teardown_method(self):
        set_daemon_service(None)
        set_current_daemon_name("")

    def test_load_web_config_routes_to_remote(self):
        result = load_web_config()
        assert result == {"remote": True, "scope": "merged"}
        assert ("get_config_scoped", "merged") in self._svc.calls

    def test_load_web_config_local_when_no_daemon_name(self, tmp_path):
        set_current_daemon_name("")
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path),
        ):
            result = load_web_config()
        assert result == {}
        assert len(self._svc.calls) == 0

    def test_load_web_config_local_when_target_is_local(self, tmp_path):
        self._svc._target = _FakeTarget(runtime="local")
        data = {"features": {"test": True}}
        (tmp_path / "ai-guardian.json").write_text(json.dumps(data), encoding="utf-8")
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path),
        ):
            result = load_web_config()
        assert result == data
        assert len(self._svc.calls) == 0

    def test_load_web_config_global_routes_to_remote(self):
        result = load_web_config_global()
        assert result == {"remote": True, "scope": "global"}
        assert ("get_config_scoped", "global") in self._svc.calls

    def test_save_web_config_routes_to_remote(self):
        config = {"secret_scanning": {"enabled": True}}
        save_web_config(config)
        assert ("write_config_bulk", "global", config) in self._svc.calls

    def test_save_web_config_always_global_for_remote(self):
        config = {"test": True}
        with patch(
            "ai_guardian.web.config_helpers._get_current_scope",
            return_value="project",
        ):
            save_web_config(config)
        assert self._svc.calls[0][1] == "global"

    def test_provenance_routes_to_remote(self):
        result = get_web_config_provenance()
        assert result == {"source": "remote"}
        assert ("get_config_provenance",) in self._svc.calls

    def test_scope_label_always_global_for_remote(self):
        assert get_web_config_scope_label() == "Global"

    def test_load_returns_empty_on_service_error(self):
        self._svc.get_config_scoped = MagicMock(return_value=None)
        result = load_web_config()
        assert result == {}

    def test_no_service_falls_through_to_local(self, tmp_path):
        set_daemon_service(None)
        with (
            patch("ai_guardian.config_utils.get_config_dir", return_value=tmp_path),
            patch("ai_guardian.config_writer.get_config_dir", return_value=tmp_path),
        ):
            result = load_web_config()
        assert result == {}
