"""
Unit tests for support bundle module.
"""

import json
import os
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from ai_guardian.support_bundle import (
    _sanitize_config,
    _sanitize_violations,
    _get_system_info,
    prepare_bundle,
    send_bundle,
    _active_bundles,
    _cleanup_bundle,
)


class TestSanitizeConfig:
    """Test config sanitization."""

    def test_redacts_sensitive_keys(self):
        config = {
            "secret_scanning": {"enabled": True},
            "pattern_server": {"auth_token": "my-secret-token", "url": "https://example.com/patterns"},
        }
        sanitized, count = _sanitize_config(config)
        assert sanitized["pattern_server"]["auth_token"] == "[REDACTED]"
        assert sanitized["pattern_server"]["url"] == "[REDACTED]"
        assert count == 2

    def test_strips_comments(self):
        config = {
            "_comment_test": "This is a comment",
            "enabled": True,
        }
        sanitized, _ = _sanitize_config(config)
        assert "_comment_test" not in sanitized
        assert sanitized["enabled"] is True

    def test_preserves_non_sensitive(self):
        config = {"secret_scanning": {"enabled": True, "action": "block"}}
        sanitized, count = _sanitize_config(config)
        assert sanitized["secret_scanning"]["enabled"] is True
        assert sanitized["secret_scanning"]["action"] == "block"
        assert count == 0


class TestSanitizeViolations:
    """Test violation sanitization."""

    def test_truncates_file_paths(self):
        violations = [{
            "timestamp": "2026-05-09T10:00:00Z",
            "violation_type": "secret_detected",
            "context": {"file_path": "/home/user/project/src/secrets.py"},
        }]
        sanitized, count = _sanitize_violations(violations)
        assert sanitized[0]["context"]["file_path"] == str(Path("...") / "src" / "secrets.py")
        assert count >= 1

    def test_removes_content_preview(self):
        violations = [{
            "context": {"content_preview": "password = 'hunter2'", "file_path": ""},
        }]
        sanitized, count = _sanitize_violations(violations)
        assert "content_preview" not in sanitized[0]["context"]


class TestGetSystemInfo:
    """Test system info collection."""

    def test_returns_expected_fields(self):
        info = _get_system_info()
        assert "ai_guardian_version" in info
        assert "python_version" in info
        assert "platform" in info
        assert "os" in info


class TestPrepareBundle:
    """Test bundle preparation."""

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_creates_bundle(self, mock_config):
        mock_config.return_value = {"export_destination": "~/support", "bundle_ttl_minutes": 30}

        result = prepare_bundle()

        assert "bundle_id" in result
        assert result["bundle_id"].startswith("support-")
        assert "temp_path" in result
        assert "files" in result
        assert len(result["files"]) > 0

        # System info should always be present
        file_names = [f["name"] for f in result["files"]]
        assert "system-info.json" in file_names

        # Cleanup
        _cleanup_bundle(result["bundle_id"])

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_bundle_files_exist_on_disk(self, mock_config):
        mock_config.return_value = {"export_destination": "~/support"}

        result = prepare_bundle()
        temp_path = Path(result["temp_path"])
        assert temp_path.exists()

        for f in result["files"]:
            assert (temp_path / f["name"]).exists()

        _cleanup_bundle(result["bundle_id"])


class TestSendBundle:
    """Test bundle sending."""

    def test_rejects_unknown_bundle_id(self):
        result = send_bundle("nonexistent-bundle")
        assert result["status"] == "error"
        assert "not found" in result["message"]

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_sends_to_local_directory(self, mock_config, tmp_path):
        dest = tmp_path / "support-output"
        mock_config.return_value = {"export_destination": str(dest), "bundle_ttl_minutes": 30}

        bundle = prepare_bundle()
        result = send_bundle(bundle["bundle_id"])

        assert result["status"] == "sent"
        assert dest.exists()

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_defaults_to_xdg_state_dir(self, mock_config):
        """When no export_destination configured, defaults to XDG state dir."""
        mock_config.return_value = {}

        bundle = prepare_bundle()
        assert "support-bundles" in bundle["destination"]

        result = send_bundle(bundle["bundle_id"])
        assert result["status"] == "sent"

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_cleanup_after_send(self, mock_config, tmp_path):
        dest = tmp_path / "output"
        mock_config.return_value = {"export_destination": str(dest), "bundle_ttl_minutes": 30}

        bundle = prepare_bundle()
        bundle_id = bundle["bundle_id"]
        temp_path = Path(bundle["temp_path"])

        send_bundle(bundle_id)

        assert not temp_path.exists()
        assert bundle_id not in _active_bundles
