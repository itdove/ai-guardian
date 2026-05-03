#!/usr/bin/env python3
"""
Tests for TUI Global Settings

Test the global settings panel's feature mapping and save logic.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from ai_guardian.tui.global_settings import GlobalSettingsContent, FEATURES


class TestFeatureMap:
    """Test FEATURES defines correct mappings."""

    def test_has_seven_features(self):
        assert len(FEATURES) == 7

    def test_expected_sections(self):
        sections = [s for s, _, _ in FEATURES]
        assert "permissions" in sections
        assert "secret_scanning" in sections
        assert "prompt_injection" in sections
        assert "scan_pii" in sections
        assert "ssrf_protection" in sections
        assert "config_file_scanning" in sections
        assert "violation_logging" in sections

    def test_all_have_labels(self):
        for section, config_key, label in FEATURES:
            assert isinstance(label, str) and len(label) > 0

    def test_sections_unique(self):
        sections = [s for s, _, _ in FEATURES]
        assert len(sections) == len(set(sections))

    def test_config_keys_unique(self):
        keys = [k for _, k, _ in FEATURES]
        assert len(keys) == len(set(keys))


class TestSaveLogic:
    """Test _save writes correct config structure."""

    def _do_save(self, section, value, existing_config=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            if existing_config:
                with open(config_path, 'w') as f:
                    json.dump(existing_config, f)

            content = GlobalSettingsContent()
            content._loading = False

            with patch("ai_guardian.tui.global_settings.get_config_dir", return_value=Path(tmpdir)), \
                 patch.object(type(content), "app", new_callable=lambda: property(lambda self: MagicMock())):
                content._save(section, value, "Test Feature")

            with open(config_path, 'r') as f:
                return json.load(f)

    def test_save_enabled(self):
        result = self._do_save("permissions", True)
        assert result["permissions"]["enabled"] is True

    def test_save_disabled(self):
        result = self._do_save("prompt_injection", False)
        assert result["prompt_injection"]["enabled"] is False

    def test_save_temp_disabled(self):
        value = {"value": False, "disabled_until": "2026-12-31T23:59:59Z"}
        result = self._do_save("ssrf_protection", value)
        assert result["ssrf_protection"]["enabled"] == value

    def test_save_preserves_existing(self):
        existing = {"secret_scanning": {"engine": "gitleaks", "enabled": True}}
        result = self._do_save("secret_scanning", False, existing)
        assert result["secret_scanning"]["enabled"] is False
        assert result["secret_scanning"]["engine"] == "gitleaks"

    def test_save_all_seven_sections(self):
        for section, _, _ in FEATURES:
            result = self._do_save(section, True)
            assert result[section]["enabled"] is True
