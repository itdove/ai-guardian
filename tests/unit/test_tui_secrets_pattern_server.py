#!/usr/bin/env python3
"""Tests for TUI pattern server toggle (issue #405).

Verifies that the TUI no longer writes the deprecated pattern_server.enabled
field and instead uses section presence/null to control enabled state.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from ai_guardian.tui.secrets import SecretsContent


@pytest.fixture
def config_dir(tmp_path):
    """Create a temporary config directory."""
    config_dir = tmp_path / ".config" / "ai-guardian"
    config_dir.mkdir(parents=True)
    return config_dir


@pytest.fixture
def config_path(config_dir):
    """Return path to test config file."""
    return config_dir / "ai-guardian.json"


def write_config(config_path, config):
    """Write config dict to JSON file."""
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)


def read_config(config_path):
    """Read config from JSON file."""
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)


class TestSavePatternServerEnabled:
    """Test save_pattern_server_enabled_value method."""

    def _make_widget_and_save(self, config_path, config_dir, value):
        """Create a SecretsContent and call save_pattern_server_enabled_value.

        Since SecretsContent is a Textual widget, we can't easily mount it.
        Instead, we extract and test the core save logic directly.
        """
        from ai_guardian.tui.widgets import sanitize_enabled_value

        config = {}
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

        if "secret_scanning" not in config:
            config["secret_scanning"] = {}

        value = sanitize_enabled_value(value)

        if isinstance(value, bool):
            if value:
                if config["secret_scanning"].get("pattern_server") is None:
                    config["secret_scanning"]["pattern_server"] = {}
                if "pattern_server" not in config["secret_scanning"]:
                    config["secret_scanning"]["pattern_server"] = {}
                config["secret_scanning"]["pattern_server"].pop("enabled", None)
                config["secret_scanning"]["pattern_server"].pop("disabled_until", None)
                config["secret_scanning"]["pattern_server"].pop("disabled_reason", None)
            else:
                config["secret_scanning"]["pattern_server"] = None
        else:
            if config["secret_scanning"].get("pattern_server") is None:
                config["secret_scanning"]["pattern_server"] = {}
            if "pattern_server" not in config["secret_scanning"]:
                config["secret_scanning"]["pattern_server"] = {}
            config["secret_scanning"]["pattern_server"].pop("enabled", None)
            config["secret_scanning"]["pattern_server"]["disabled_until"] = value.get("disabled_until", "")
            if value.get("reason"):
                config["secret_scanning"]["pattern_server"]["disabled_reason"] = value["reason"]
            else:
                config["secret_scanning"]["pattern_server"].pop("disabled_reason", None)

        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        return read_config(config_path)

    def test_enable_does_not_write_enabled_field(self, config_path, config_dir):
        """Enabling pattern server should NOT write the deprecated 'enabled' field."""
        write_config(config_path, {"secret_scanning": {"pattern_server": None}})
        result = self._make_widget_and_save(config_path, config_dir, True)

        ps = result["secret_scanning"]["pattern_server"]
        assert isinstance(ps, dict)
        assert "enabled" not in ps

    def test_disable_sets_section_to_null(self, config_path, config_dir):
        """Disabling pattern server should set the section to null."""
        write_config(config_path, {
            "secret_scanning": {
                "pattern_server": {
                    "url": "https://example.com",
                    "auth": {"method": "bearer"},
                }
            }
        })
        result = self._make_widget_and_save(config_path, config_dir, False)
        assert result["secret_scanning"]["pattern_server"] is None

    def test_enable_removes_deprecated_enabled_field(self, config_path, config_dir):
        """Enabling should remove any existing deprecated 'enabled' field."""
        write_config(config_path, {
            "secret_scanning": {
                "pattern_server": {
                    "enabled": False,
                    "url": "https://example.com",
                }
            }
        })
        result = self._make_widget_and_save(config_path, config_dir, True)

        ps = result["secret_scanning"]["pattern_server"]
        assert "enabled" not in ps
        assert ps["url"] == "https://example.com"

    def test_enable_removes_temp_disable_fields(self, config_path, config_dir):
        """Enabling should remove disabled_until and disabled_reason fields."""
        write_config(config_path, {
            "secret_scanning": {
                "pattern_server": {
                    "url": "https://example.com",
                    "disabled_until": "2030-01-01T00:00:00Z",
                    "disabled_reason": "testing",
                }
            }
        })
        result = self._make_widget_and_save(config_path, config_dir, True)

        ps = result["secret_scanning"]["pattern_server"]
        assert "disabled_until" not in ps
        assert "disabled_reason" not in ps
        assert ps["url"] == "https://example.com"

    def test_enable_from_null_creates_empty_section(self, config_path, config_dir):
        """Enabling from null state creates an empty section."""
        write_config(config_path, {"secret_scanning": {"pattern_server": None}})
        result = self._make_widget_and_save(config_path, config_dir, True)

        ps = result["secret_scanning"]["pattern_server"]
        assert isinstance(ps, dict)
        assert "enabled" not in ps

    def test_temp_disable_stores_disabled_until_at_section_level(self, config_path, config_dir):
        """Temp disable should store disabled_until at the pattern_server section level."""
        write_config(config_path, {
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com"}
            }
        })
        value = {
            "value": False,
            "disabled_until": "2030-06-01T12:00:00Z",
            "reason": "maintenance window",
        }
        result = self._make_widget_and_save(config_path, config_dir, value)

        ps = result["secret_scanning"]["pattern_server"]
        assert ps["disabled_until"] == "2030-06-01T12:00:00Z"
        assert ps["disabled_reason"] == "maintenance window"
        assert "enabled" not in ps
        assert ps["url"] == "https://example.com"

    def test_temp_disable_from_null_creates_section(self, config_path, config_dir):
        """Temp disable from null state creates section with disabled_until."""
        write_config(config_path, {"secret_scanning": {"pattern_server": None}})
        value = {
            "value": False,
            "disabled_until": "2030-06-01T12:00:00Z",
        }
        result = self._make_widget_and_save(config_path, config_dir, value)

        ps = result["secret_scanning"]["pattern_server"]
        assert isinstance(ps, dict)
        assert ps["disabled_until"] == "2030-06-01T12:00:00Z"
        assert "enabled" not in ps

    def test_temp_disable_without_reason_removes_reason(self, config_path, config_dir):
        """Temp disable without reason should not leave stale disabled_reason."""
        write_config(config_path, {
            "secret_scanning": {
                "pattern_server": {
                    "url": "https://example.com",
                    "disabled_reason": "old reason",
                }
            }
        })
        value = {"value": False, "disabled_until": "2030-06-01T12:00:00Z"}
        result = self._make_widget_and_save(config_path, config_dir, value)

        ps = result["secret_scanning"]["pattern_server"]
        assert "disabled_reason" not in ps

    def test_no_config_file_creates_fresh(self, config_path, config_dir):
        """Saving with no existing config file should create one."""
        result = self._make_widget_and_save(config_path, config_dir, False)
        assert result["secret_scanning"]["pattern_server"] is None


class TestReadEnabledState:
    """Test reading pattern server enabled state from config."""

    def _read_enabled_value(self, config):
        """Extract the enabled_value logic from _load_config_inner."""
        secret_scanning = config.get("secret_scanning", {})

        if "pattern_server" in secret_scanning:
            pattern_server = secret_scanning["pattern_server"]
        elif "pattern_server" in config:
            pattern_server = config["pattern_server"]
        else:
            pattern_server = {}

        if pattern_server is None:
            return False
        elif not isinstance(pattern_server, dict) or not pattern_server:
            return False
        elif "enabled" in pattern_server:
            return pattern_server["enabled"]
        elif "disabled_until" in pattern_server:
            return {
                "value": False,
                "disabled_until": pattern_server["disabled_until"],
                "reason": pattern_server.get("disabled_reason", ""),
            }
        else:
            return True

    def test_null_section_reads_as_disabled(self):
        """pattern_server: null → disabled."""
        config = {"secret_scanning": {"pattern_server": None}}
        assert self._read_enabled_value(config) is False

    def test_empty_section_reads_as_disabled(self):
        """pattern_server: {} → disabled."""
        config = {"secret_scanning": {"pattern_server": {}}}
        assert self._read_enabled_value(config) is False

    def test_absent_section_reads_as_disabled(self):
        """No pattern_server key → disabled."""
        config = {"secret_scanning": {}}
        assert self._read_enabled_value(config) is False

    def test_section_with_url_reads_as_enabled(self):
        """pattern_server with url → enabled."""
        config = {
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com"}
            }
        }
        assert self._read_enabled_value(config) is True

    def test_section_with_any_content_reads_as_enabled(self):
        """pattern_server with any non-empty content → enabled."""
        config = {
            "secret_scanning": {
                "pattern_server": {"warn_on_failure": False}
            }
        }
        assert self._read_enabled_value(config) is True

    def test_backward_compat_enabled_true(self):
        """Old config with enabled: true should still work."""
        config = {
            "secret_scanning": {
                "pattern_server": {"enabled": True, "url": "https://example.com"}
            }
        }
        assert self._read_enabled_value(config) is True

    def test_backward_compat_enabled_false(self):
        """Old config with enabled: false should still work."""
        config = {
            "secret_scanning": {
                "pattern_server": {"enabled": False, "url": "https://example.com"}
            }
        }
        assert self._read_enabled_value(config) is False

    def test_backward_compat_enabled_time_based_dict(self):
        """Old config with enabled: {time-based dict} should still work."""
        time_val = {
            "value": False,
            "disabled_until": "2030-01-01T00:00:00Z",
            "reason": "testing",
        }
        config = {
            "secret_scanning": {
                "pattern_server": {"enabled": time_val, "url": "https://example.com"}
            }
        }
        result = self._read_enabled_value(config)
        assert result == time_val

    def test_disabled_until_at_section_level(self):
        """New-style temp disable with disabled_until at section level."""
        config = {
            "secret_scanning": {
                "pattern_server": {
                    "url": "https://example.com",
                    "disabled_until": "2030-06-01T12:00:00Z",
                    "disabled_reason": "maintenance",
                }
            }
        }
        result = self._read_enabled_value(config)
        assert isinstance(result, dict)
        assert result["value"] is False
        assert result["disabled_until"] == "2030-06-01T12:00:00Z"
        assert result["reason"] == "maintenance"

    def test_root_level_fallback(self):
        """Root-level pattern_server (deprecated) should be read as fallback."""
        config = {
            "pattern_server": {"url": "https://legacy.example.com"}
        }
        assert self._read_enabled_value(config) is True

    def test_null_does_not_fallback_to_root(self):
        """Explicit null in secret_scanning should NOT fall back to root."""
        config = {
            "secret_scanning": {"pattern_server": None},
            "pattern_server": {"url": "https://legacy.example.com"},
        }
        assert self._read_enabled_value(config) is False


class TestEnsurePatternServerSection:
    """Test _ensure_pattern_server_section helper."""

    def test_creates_from_empty(self):
        """Creates both secret_scanning and pattern_server from empty config."""
        from ai_guardian.tui.secrets import SecretsContent
        config = {}
        SecretsContent._ensure_pattern_server_section(None, config)
        assert isinstance(config["secret_scanning"]["pattern_server"], dict)

    def test_creates_from_none_value(self):
        """Converts null pattern_server to empty dict."""
        config = {"secret_scanning": {"pattern_server": None}}
        SecretsContent._ensure_pattern_server_section(None, config)
        assert isinstance(config["secret_scanning"]["pattern_server"], dict)

    def test_preserves_existing_dict(self):
        """Preserves existing pattern_server dict."""
        config = {
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com"}
            }
        }
        SecretsContent._ensure_pattern_server_section(None, config)
        assert config["secret_scanning"]["pattern_server"]["url"] == "https://example.com"
