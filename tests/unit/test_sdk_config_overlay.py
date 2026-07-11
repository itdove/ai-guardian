"""
Tests for SDK config overlay (Issue #1139).

Tests cover:
- _resolve_sdk_overlay(): env var file, inline JSON, configure() API, priority
- _load_config_file(): overlay merge on top of global + project config
- configure(): cache clearing, overlay replacement
- Cache invalidation: mtime, inline value, SDK overlay id
- Doctor check_config_overlay: source detection
- SDK monitor() integration with overlay
"""

import json
import os
from unittest import mock


from ai_guardian.config.loaders import (
    _clear_config_cache,
    _load_config_file,
    _resolve_sdk_overlay,
    configure,
)


class TestResolveSDKOverlay:
    """Tests for _resolve_sdk_overlay()."""

    def test_no_overlay_returns_none(self):
        assert _resolve_sdk_overlay() is None

    def test_file_overlay_via_env_var(self, tmp_path):
        overlay_file = tmp_path / "overlay.json"
        overlay_file.write_text(json.dumps({"preferred_ui": "headless"}))
        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_OVERLAY": str(overlay_file),
            },
        ):
            result = _resolve_sdk_overlay()
        assert result == {"preferred_ui": "headless"}

    def test_inline_overlay_via_env_var(self):
        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_INLINE": '{"ssrf_protection": {"action": "block"}}',
            },
        ):
            result = _resolve_sdk_overlay()
        assert result == {"ssrf_protection": {"action": "block"}}

    def test_configure_overlay(self):
        import ai_guardian.config.loaders as cl

        old = cl._sdk_overlay
        try:
            cl._sdk_overlay = {"preferred_ui": "headless"}
            result = _resolve_sdk_overlay()
            assert result == {"preferred_ui": "headless"}
        finally:
            cl._sdk_overlay = old

    def test_inline_overrides_file(self, tmp_path):
        overlay_file = tmp_path / "overlay.json"
        overlay_file.write_text(
            json.dumps(
                {
                    "preferred_ui": "tkinter",
                    "ssrf_protection": {"action": "warn"},
                }
            )
        )
        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_OVERLAY": str(overlay_file),
                "AI_GUARDIAN_CONFIG_INLINE": '{"preferred_ui": "headless"}',
            },
        ):
            result = _resolve_sdk_overlay()
        assert result["preferred_ui"] == "headless"
        assert result["ssrf_protection"]["action"] == "warn"

    def test_configure_overrides_inline(self):
        import ai_guardian.config.loaders as cl

        old = cl._sdk_overlay
        try:
            cl._sdk_overlay = {"preferred_ui": "nicegui"}
            with mock.patch.dict(
                os.environ,
                {
                    "AI_GUARDIAN_CONFIG_INLINE": '{"preferred_ui": "headless"}',
                },
            ):
                result = _resolve_sdk_overlay()
            assert result["preferred_ui"] == "nicegui"
        finally:
            cl._sdk_overlay = old

    def test_all_three_merged(self, tmp_path):
        overlay_file = tmp_path / "overlay.json"
        overlay_file.write_text(json.dumps({"from_file": True, "shared": "file"}))
        import ai_guardian.config.loaders as cl

        old = cl._sdk_overlay
        try:
            cl._sdk_overlay = {"from_api": True, "shared": "api"}
            with mock.patch.dict(
                os.environ,
                {
                    "AI_GUARDIAN_CONFIG_OVERLAY": str(overlay_file),
                    "AI_GUARDIAN_CONFIG_INLINE": '{"from_inline": true, "shared": "inline"}',
                },
            ):
                result = _resolve_sdk_overlay()
            assert result["from_file"] is True
            assert result["from_inline"] is True
            assert result["from_api"] is True
            assert result["shared"] == "api"
        finally:
            cl._sdk_overlay = old

    def test_invalid_file_path_returns_none(self):
        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_OVERLAY": "/nonexistent/overlay.json",
            },
        ):
            result = _resolve_sdk_overlay()
        assert result is None

    def test_invalid_inline_json_returns_none(self):
        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_INLINE": "not valid json {{{",
            },
        ):
            result = _resolve_sdk_overlay()
        assert result is None

    def test_inline_not_dict_returns_none(self):
        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_INLINE": '["not", "a", "dict"]',
            },
        ):
            result = _resolve_sdk_overlay()
        assert result is None


class TestLoadConfigFileWithOverlay:
    """Tests for _load_config_file() with SDK overlay."""

    def setup_method(self):
        _clear_config_cache()

    def test_overlay_merges_on_top_of_global(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        global_config = {
            "secret_scanning": {"enabled": True},
            "ssrf_protection": {"action": "warn"},
            "preferred_ui": "tkinter",
        }
        (config_dir / "ai-guardian.json").write_text(json.dumps(global_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
                "AI_GUARDIAN_CONFIG_INLINE": '{"ssrf_protection": {"action": "block"}}',
            },
        ):
            _clear_config_cache()
            config, err = _load_config_file()

        assert err is None
        assert config["secret_scanning"]["enabled"] is True
        assert config["ssrf_protection"]["action"] == "block"
        assert config["preferred_ui"] == "tkinter"

    def test_overlay_merges_on_top_of_project(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        global_config = {
            "secret_scanning": {"enabled": True},
            "ssrf_protection": {"action": "warn"},
        }
        (config_dir / "ai-guardian.json").write_text(json.dumps(global_config))

        project_dir = tmp_path / "project" / ".ai-guardian"
        project_dir.mkdir(parents=True)
        project_config = {
            "ssrf_protection": {"action": "log-only"},
            "prompt_injection": {"enabled": False},
        }
        (project_dir / "ai-guardian.json").write_text(json.dumps(project_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
                "AI_GUARDIAN_PROJECT_CONFIG": str(project_dir / "ai-guardian.json"),
                "AI_GUARDIAN_CONFIG_INLINE": '{"ssrf_protection": {"action": "block"}}',
            },
        ):
            _clear_config_cache()
            config, err = _load_config_file()

        assert err is None
        assert config["secret_scanning"]["enabled"] is True
        assert config["ssrf_protection"]["action"] == "block"
        assert config["prompt_injection"]["enabled"] is False

    def test_overlay_respects_immutable_true(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        global_config = {
            "ssrf_protection": {
                "immutable": True,
                "action": "warn",
            },
        }
        (config_dir / "ai-guardian.json").write_text(json.dumps(global_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
                "AI_GUARDIAN_CONFIG_INLINE": '{"ssrf_protection": {"action": "block"}}',
            },
        ):
            _clear_config_cache()
            config, err = _load_config_file()

        assert err is None
        assert config["ssrf_protection"]["action"] == "warn"

    def test_overlay_respects_immutable_fields(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        global_config = {
            "secret_scanning": {
                "enabled": True,
                "immutable": ["enabled"],
            },
            "ssrf_protection": {
                "action": "warn",
            },
        }
        (config_dir / "ai-guardian.json").write_text(json.dumps(global_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
                "AI_GUARDIAN_CONFIG_INLINE": '{"secret_scanning": {"enabled": false}, "ssrf_protection": {"action": "block"}}',
            },
        ):
            _clear_config_cache()
            config, err = _load_config_file()

        assert err is None
        assert config["secret_scanning"]["enabled"] is True
        assert config["ssrf_protection"]["action"] == "block"

    def test_overlay_can_set_global_only_sections(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        global_config = {"secret_scanning": {"enabled": True}}
        (config_dir / "ai-guardian.json").write_text(json.dumps(global_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
                "AI_GUARDIAN_CONFIG_INLINE": '{"daemon": {"host": "0.0.0.0"}}',
            },
        ):
            _clear_config_cache()
            config, err = _load_config_file()

        assert err is None
        assert config["daemon"]["host"] == "0.0.0.0"

    def test_overlay_does_not_mutate_overlay_dict(self):
        import ai_guardian.config.loaders as cl

        old = cl._sdk_overlay
        try:
            overlay = {"ssrf_protection": {"action": "block"}}
            cl._sdk_overlay = overlay
            _clear_config_cache()
            _load_config_file()
            assert overlay == {"ssrf_protection": {"action": "block"}}
        finally:
            cl._sdk_overlay = old

    def test_no_overlay_backward_compatible(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        global_config = {"secret_scanning": {"enabled": True}, "ssrf_protection": {"action": "warn"}}
        (config_dir / "ai-guardian.json").write_text(json.dumps(global_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
            },
        ):
            _clear_config_cache()
            config, err = _load_config_file()

        assert err is None
        assert config == {"secret_scanning": {"enabled": True}, "ssrf_protection": {"action": "warn"}}

    def test_overlay_only_no_config_files(self):
        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_INLINE": '{"preferred_ui": "headless"}',
            },
        ):
            _clear_config_cache()
            config, err = _load_config_file()

        assert err is None
        assert config == {"preferred_ui": "headless"}


class TestConfigure:
    """Tests for configure() API."""

    def setup_method(self):
        _clear_config_cache()

    def test_configure_clears_cache(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        global_config = {"ssrf_protection": {"action": "warn"}}
        (config_dir / "ai-guardian.json").write_text(json.dumps(global_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
            },
        ):
            _clear_config_cache()
            config1, _ = _load_config_file()
            assert config1["ssrf_protection"]["action"] == "warn"

            configure(overlay={"ssrf_protection": {"action": "block"}})
            config2, _ = _load_config_file()
            assert config2["ssrf_protection"]["action"] == "block"

    def test_configure_none_clears_overlay(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        global_config = {"ssrf_protection": {"action": "warn"}}
        (config_dir / "ai-guardian.json").write_text(json.dumps(global_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
            },
        ):
            configure(overlay={"ssrf_protection": {"action": "block"}})
            config1, _ = _load_config_file()
            assert config1["ssrf_protection"]["action"] == "block"

            configure(overlay=None)
            config2, _ = _load_config_file()
            assert config2["ssrf_protection"]["action"] == "warn"

    def test_configure_replaces_previous(self):
        configure(overlay={"a": 1})
        configure(overlay={"b": 2})
        import ai_guardian.config.loaders as cl

        assert cl._sdk_overlay == {"b": 2}


class TestCacheInvalidation:
    """Tests for cache invalidation with overlay changes."""

    def setup_method(self):
        _clear_config_cache()

    def test_file_overlay_mtime_change_invalidates(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        global_config = {"base": True}
        (config_dir / "ai-guardian.json").write_text(json.dumps(global_config))

        overlay_file = tmp_path / "overlay.json"
        overlay_file.write_text(json.dumps({"version": 1}))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
                "AI_GUARDIAN_CONFIG_OVERLAY": str(overlay_file),
            },
        ):
            _clear_config_cache()
            config1, _ = _load_config_file()
            assert config1["version"] == 1

            overlay_file.write_text(json.dumps({"version": 2}))
            # Force mtime change (some filesystems have coarse resolution)
            import time

            os.utime(overlay_file, (time.time() + 1, time.time() + 1))

            config2, _ = _load_config_file()
            assert config2["version"] == 2

    def test_inline_env_change_invalidates(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        global_config = {"base": True}
        (config_dir / "ai-guardian.json").write_text(json.dumps(global_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
                "AI_GUARDIAN_CONFIG_INLINE": '{"version": 1}',
            },
        ):
            _clear_config_cache()
            config1, _ = _load_config_file()
            assert config1["version"] == 1

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
                "AI_GUARDIAN_CONFIG_INLINE": '{"version": 2}',
            },
        ):
            config2, _ = _load_config_file()
            assert config2["version"] == 2


class TestDoctorOverlayCheck:
    """Tests for doctor check_config_overlay."""

    def _make_doctor(self):
        from ai_guardian.doctor import Doctor

        return Doctor()

    def test_no_overlay_passes(self):
        doctor = self._make_doctor()
        result = doctor.check_config_overlay()
        assert result.status.value == "pass"
        assert "No SDK overlay" in result.message

    def test_file_overlay_detected(self, tmp_path):
        overlay_file = tmp_path / "overlay.json"
        overlay_file.write_text(json.dumps({"test": True}))
        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_OVERLAY": str(overlay_file),
            },
        ):
            doctor = self._make_doctor()
            result = doctor.check_config_overlay()
        assert result.status.value == "pass"
        assert "file:" in result.message

    def test_inline_overlay_detected(self):
        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_INLINE": '{"test": true}',
            },
        ):
            doctor = self._make_doctor()
            result = doctor.check_config_overlay()
        assert result.status.value == "pass"
        assert "inline env var" in result.message

    def test_configure_overlay_detected(self):
        import ai_guardian.config.loaders as cl

        old = cl._sdk_overlay
        try:
            cl._sdk_overlay = {"test": True}
            doctor = self._make_doctor()
            result = doctor.check_config_overlay()
            assert result.status.value == "pass"
            assert "configure() API" in result.message
        finally:
            cl._sdk_overlay = old

    def test_missing_file_warns(self):
        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_OVERLAY": "/nonexistent/overlay.json",
            },
        ):
            doctor = self._make_doctor()
            result = doctor.check_config_overlay()
        assert result.status.value == "warn"
        assert "not found" in result.message


class TestSDKMonitorWithOverlay:
    """Tests for SDK monitor() integration with configure() overlay."""

    def test_monitor_with_configure(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        global_config = {"secret_scanning": {"enabled": False}}
        (config_dir / "ai-guardian.json").write_text(json.dumps(global_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
            },
        ):
            configure(overlay={"secret_scanning": {"enabled": True}, "ssrf_protection": {"action": "block"}})
            from ai_guardian.sdk import monitor

            with monitor(action="log") as session:
                assert session._config["secret_scanning"]["enabled"] is True
                assert session._config["ssrf_protection"]["action"] == "block"

    def test_monitor_config_param_still_replaces(self):
        configure(overlay={"ssrf_protection": {"action": "block"}})
        custom_config = {"my_custom": True}
        from ai_guardian.sdk import monitor

        with monitor(action="log", config=custom_config) as session:
            assert session._config == {"my_custom": True}
            assert "ssrf_protection" not in session._config
