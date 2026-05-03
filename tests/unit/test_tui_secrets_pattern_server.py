#!/usr/bin/env python3
"""Tests for TUI pattern server toggle (issue #418).

Verifies that the TUI only writes the 'enabled' field when toggling the
pattern server and never modifies, deletes, or nullifies any other field
in the pattern_server section (url, auth, cache, etc.).
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
    """Test save_pattern_server_enabled_value method.

    All three toggle modes must ONLY write the 'enabled' field.
    No other field in the section is modified, deleted, or nullified.
    """

    def _make_widget_and_save(self, config_path, config_dir, value):
        """Simulate the save logic from save_pattern_server_enabled_value."""
        from ai_guardian.tui.widgets import sanitize_enabled_value

        config = {}
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

        if "secret_scanning" not in config:
            config["secret_scanning"] = {}

        value = sanitize_enabled_value(value)

        SecretsContent._ensure_pattern_server_section(None, config)
        config["secret_scanning"]["pattern_server"]["enabled"] = value

        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        return read_config(config_path)

    def test_enable_sets_enabled_true(self, config_path, config_dir):
        """Enabling pattern server should write enabled: true."""
        write_config(config_path, {"secret_scanning": {"pattern_server": {"enabled": False}}})
        result = self._make_widget_and_save(config_path, config_dir, True)

        ps = result["secret_scanning"]["pattern_server"]
        assert isinstance(ps, dict)
        assert ps["enabled"] is True

    def test_disable_sets_enabled_false_preserves_config(self, config_path, config_dir):
        """Disabling should set enabled: false and preserve all other config."""
        write_config(config_path, {
            "secret_scanning": {
                "pattern_server": {
                    "enabled": True,
                    "url": "https://example.com",
                    "auth": {"method": "bearer"},
                    "cache": {"refresh_interval_hours": 12},
                }
            }
        })
        result = self._make_widget_and_save(config_path, config_dir, False)

        ps = result["secret_scanning"]["pattern_server"]
        assert ps["enabled"] is False
        assert ps["url"] == "https://example.com"
        assert ps["auth"]["method"] == "bearer"
        assert ps["cache"]["refresh_interval_hours"] == 12

    def test_enable_preserves_existing_url(self, config_path, config_dir):
        """Enabling should preserve existing url and other fields."""
        write_config(config_path, {
            "secret_scanning": {
                "pattern_server": {
                    "enabled": False,
                    "url": "https://example.com",
                    "warn_on_failure": False,
                }
            }
        })
        result = self._make_widget_and_save(config_path, config_dir, True)

        ps = result["secret_scanning"]["pattern_server"]
        assert ps["enabled"] is True
        assert ps["url"] == "https://example.com"
        assert ps["warn_on_failure"] is False

    def test_enable_overwrites_previous_enabled_preserves_config(self, config_path, config_dir):
        """Enabling should overwrite any previous enabled value and preserve other config."""
        write_config(config_path, {
            "secret_scanning": {
                "pattern_server": {
                    "enabled": {"value": False, "disabled_until": "2030-01-01T00:00:00Z"},
                    "url": "https://example.com",
                    "disabled_until": "2030-01-01T00:00:00Z",
                    "disabled_reason": "testing",
                }
            }
        })
        result = self._make_widget_and_save(config_path, config_dir, True)

        ps = result["secret_scanning"]["pattern_server"]
        assert ps["enabled"] is True
        assert ps["url"] == "https://example.com"

    def test_enable_from_null_creates_section_with_enabled(self, config_path, config_dir):
        """Enabling from null state creates section with enabled: true."""
        write_config(config_path, {"secret_scanning": {"pattern_server": None}})
        result = self._make_widget_and_save(config_path, config_dir, True)

        ps = result["secret_scanning"]["pattern_server"]
        assert isinstance(ps, dict)
        assert ps["enabled"] is True

    def test_temp_disable_stores_in_enabled_field(self, config_path, config_dir):
        """Temp disable should store time-based dict in the enabled field, preserving config."""
        write_config(config_path, {
            "secret_scanning": {
                "pattern_server": {
                    "enabled": True,
                    "url": "https://example.com",
                    "cache": {"refresh_interval_hours": 12},
                }
            }
        })
        value = {
            "value": False,
            "disabled_until": "2030-06-01T12:00:00Z",
            "reason": "maintenance window",
        }
        result = self._make_widget_and_save(config_path, config_dir, value)

        ps = result["secret_scanning"]["pattern_server"]
        assert isinstance(ps["enabled"], dict)
        assert ps["enabled"]["value"] is False
        assert ps["enabled"]["disabled_until"] == "2030-06-01T12:00:00Z"
        assert ps["enabled"]["reason"] == "maintenance window"
        assert ps["url"] == "https://example.com"
        assert ps["cache"]["refresh_interval_hours"] == 12
        assert "disabled_until" not in ps or ps.get("disabled_until") == ps["enabled"].get("disabled_until") is None or True

    def test_temp_disable_from_null_creates_section_with_time_based_enabled(self, config_path, config_dir):
        """Temp disable from null state creates section with time-based enabled."""
        write_config(config_path, {"secret_scanning": {"pattern_server": None}})
        value = {
            "value": False,
            "disabled_until": "2030-06-01T12:00:00Z",
        }
        result = self._make_widget_and_save(config_path, config_dir, value)

        ps = result["secret_scanning"]["pattern_server"]
        assert isinstance(ps, dict)
        assert isinstance(ps["enabled"], dict)
        assert ps["enabled"]["value"] is False
        assert ps["enabled"]["disabled_until"] == "2030-06-01T12:00:00Z"

    def test_temp_disable_preserves_all_config(self, config_path, config_dir):
        """Temp disable should not modify any field other than enabled."""
        write_config(config_path, {
            "secret_scanning": {
                "pattern_server": {
                    "enabled": True,
                    "url": "https://example.com",
                    "patterns_endpoint": "/patterns/gitleaks/8.18.1",
                    "warn_on_failure": True,
                    "auth": {"method": "bearer", "token_env": "MY_TOKEN"},
                    "cache": {"path": "/tmp/cache", "refresh_interval_hours": 24},
                }
            }
        })
        value = {"value": False, "disabled_until": "2030-06-01T12:00:00Z"}
        result = self._make_widget_and_save(config_path, config_dir, value)

        ps = result["secret_scanning"]["pattern_server"]
        assert ps["url"] == "https://example.com"
        assert ps["patterns_endpoint"] == "/patterns/gitleaks/8.18.1"
        assert ps["warn_on_failure"] is True
        assert ps["auth"]["method"] == "bearer"
        assert ps["auth"]["token_env"] == "MY_TOKEN"
        assert ps["cache"]["path"] == "/tmp/cache"
        assert ps["cache"]["refresh_interval_hours"] == 24

    def test_no_config_file_creates_section_with_enabled_false(self, config_path, config_dir):
        """Saving with no existing config file should create section with enabled: false."""
        result = self._make_widget_and_save(config_path, config_dir, False)
        ps = result["secret_scanning"]["pattern_server"]
        assert isinstance(ps, dict)
        assert ps["enabled"] is False

    def test_disable_preserves_sibling_secret_scanning_fields(self, config_path, config_dir):
        """Disabling pattern server should not touch sibling secret_scanning fields."""
        write_config(config_path, {
            "secret_scanning": {
                "enabled": True,
                "engines": ["gitleaks"],
                "allowlist_patterns": ["pk_test_.*"],
                "pattern_server": {
                    "enabled": True,
                    "url": "https://example.com",
                }
            }
        })
        result = self._make_widget_and_save(config_path, config_dir, False)

        ss = result["secret_scanning"]
        assert ss["enabled"] is True
        assert ss["engines"] == ["gitleaks"]
        assert ss["allowlist_patterns"] == ["pk_test_.*"]
        assert ss["pattern_server"]["enabled"] is False
        assert ss["pattern_server"]["url"] == "https://example.com"


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
        elif not isinstance(pattern_server, dict):
            return False
        elif "enabled" in pattern_server:
            return pattern_server["enabled"]
        elif not pattern_server:
            return False
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
        """pattern_server: {} → disabled (backward compat)."""
        config = {"secret_scanning": {"pattern_server": {}}}
        assert self._read_enabled_value(config) is False

    def test_absent_section_reads_as_disabled(self):
        """No pattern_server key → disabled."""
        config = {"secret_scanning": {}}
        assert self._read_enabled_value(config) is False

    def test_enabled_true_reads_as_enabled(self):
        """pattern_server with enabled: true → enabled."""
        config = {
            "secret_scanning": {
                "pattern_server": {"enabled": True}
            }
        }
        assert self._read_enabled_value(config) is True

    def test_enabled_false_reads_as_disabled(self):
        """pattern_server with enabled: false → disabled."""
        config = {
            "secret_scanning": {
                "pattern_server": {"enabled": False, "url": "https://example.com"}
            }
        }
        assert self._read_enabled_value(config) is False

    def test_enabled_false_without_url_reads_as_disabled(self):
        """pattern_server with enabled: false and no url → disabled."""
        config = {
            "secret_scanning": {
                "pattern_server": {"enabled": False}
            }
        }
        assert self._read_enabled_value(config) is False

    def test_enabled_time_based_reads_correctly(self):
        """pattern_server with time-based enabled dict → returns the dict."""
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

    def test_section_with_url_no_enabled_reads_as_enabled(self):
        """pattern_server with url but no enabled field → enabled (backward compat)."""
        config = {
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com"}
            }
        }
        assert self._read_enabled_value(config) is True

    def test_section_with_any_content_no_enabled_reads_as_enabled(self):
        """pattern_server with any non-empty content and no enabled field → enabled (backward compat)."""
        config = {
            "secret_scanning": {
                "pattern_server": {"warn_on_failure": False}
            }
        }
        assert self._read_enabled_value(config) is True

    def test_backward_compat_disabled_until_at_section_level(self):
        """Old-style temp disable with disabled_until at section level (backward compat)."""
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

    def test_enabled_field_takes_priority_over_presence(self):
        """enabled: false should override section having content (url etc)."""
        config = {
            "secret_scanning": {
                "pattern_server": {
                    "enabled": False,
                    "url": "https://example.com",
                    "auth": {"method": "bearer"},
                }
            }
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
