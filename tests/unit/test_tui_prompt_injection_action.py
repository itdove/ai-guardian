#!/usr/bin/env python3
"""
Tests for Prompt Injection Detection Panel action field.

Verifies that the action Select is included in SCHEMA_FIELDS
and that _save_field writes action correctly to config.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from ai_guardian.tui.pi_detection import PIDetectionContent


class TestSchemaFields:
    """Test SCHEMA_FIELDS includes action select."""

    def test_action_select_in_schema_fields(self):
        fields = PIDetectionContent.SCHEMA_FIELDS
        action_entries = [f for f in fields if f[1] == "action"]
        assert len(action_entries) == 1
        assert action_entries[0] == ("pi-action-select", "action", "select")

    def test_schema_section(self):
        assert PIDetectionContent.SCHEMA_SECTION == "prompt_injection"


class TestActionSaveField:
    """Test _save_field writes action correctly to config."""

    def _do_save(self, field, value, existing_config=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            if existing_config:
                with open(config_path, 'w') as f:
                    json.dump(existing_config, f)

            content = PIDetectionContent()
            content._loading = False

            with patch("ai_guardian.tui.pi_detection.get_config_dir", return_value=Path(tmpdir)), \
                 patch.object(type(content), "app", new_callable=lambda: property(lambda self: MagicMock())):
                content._save_field(field, value)

            with open(config_path, 'r') as f:
                return json.load(f)

    def test_save_action_block(self):
        result = self._do_save("action", "block")
        assert result["prompt_injection"]["action"] == "block"

    def test_save_action_warn(self):
        result = self._do_save("action", "warn")
        assert result["prompt_injection"]["action"] == "warn"

    def test_save_action_log_only(self):
        result = self._do_save("action", "log-only")
        assert result["prompt_injection"]["action"] == "log-only"

    def test_save_action_preserves_existing(self):
        existing = {"prompt_injection": {"enabled": True, "detector": "heuristic", "sensitivity": "medium"}}
        result = self._do_save("action", "warn", existing)
        assert result["prompt_injection"]["action"] == "warn"
        assert result["prompt_injection"]["enabled"] is True
        assert result["prompt_injection"]["detector"] == "heuristic"
        assert result["prompt_injection"]["sensitivity"] == "medium"
