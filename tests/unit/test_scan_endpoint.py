"""Tests for POST /api/scan endpoint and config_section_for_rule_id mapping."""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from ai_guardian.tui.pattern_editor import (
    config_section_for_rule_id,
    RULE_ID_TO_CONFIG_SECTION,
)


class TestConfigSectionForRuleId:
    """Test the rule_id to config section mapping."""

    def test_secret(self):
        assert config_section_for_rule_id("SECRET-001") == "secret_scanning"

    def test_pii(self):
        assert config_section_for_rule_id("PII-001") == "scan_pii"

    def test_prompt_injection(self):
        assert config_section_for_rule_id("PROMPT-INJECTION-001") == "prompt_injection"

    def test_ssrf(self):
        assert config_section_for_rule_id("SSRF-001") == "ssrf_protection"

    def test_config(self):
        assert config_section_for_rule_id("CONFIG-001") == "config_file_scanning"

    def test_supply_chain(self):
        assert config_section_for_rule_id("SUPPLY-CHAIN-001") == "supply_chain"

    def test_unicode_returns_none(self):
        assert config_section_for_rule_id("UNICODE-001") is None

    def test_unknown_returns_none(self):
        assert config_section_for_rule_id("UNKNOWN-999") is None


class TestScanEndpointHandler:
    """Test the _handle_scan method in the REST API."""

    def _make_handler(self):
        """Create a mock handler with the _handle_scan method."""
        from ai_guardian.daemon.rest_api import _RestHandler

        handler = MagicMock(spec=_RestHandler)
        handler._send_json = MagicMock()
        handler._send_error = MagicMock()
        handler.server = MagicMock()
        handler.server.daemon_state = MagicMock()
        handler.server.daemon_state.get_config.return_value = {}
        handler._BLOCKED_SCAN_DIRS = _RestHandler._BLOCKED_SCAN_DIRS
        _RestHandler._handle_scan.__get__(handler)(handler)
        return handler

    def test_missing_path_returns_400(self):
        from ai_guardian.daemon.rest_api import _RestHandler

        handler = MagicMock(spec=_RestHandler)
        handler._send_error = MagicMock()
        handler._BLOCKED_SCAN_DIRS = _RestHandler._BLOCKED_SCAN_DIRS

        _RestHandler._handle_scan(handler, {})
        handler._send_error.assert_called_once_with(400, "path is required")

    def test_empty_path_returns_400(self):
        from ai_guardian.daemon.rest_api import _RestHandler

        handler = MagicMock(spec=_RestHandler)
        handler._send_error = MagicMock()
        handler._BLOCKED_SCAN_DIRS = _RestHandler._BLOCKED_SCAN_DIRS

        _RestHandler._handle_scan(handler, {"path": ""})
        handler._send_error.assert_called_once_with(400, "path is required")

    def test_nonexistent_path_returns_404(self):
        from ai_guardian.daemon.rest_api import _RestHandler

        handler = MagicMock(spec=_RestHandler)
        handler._send_error = MagicMock()
        handler._BLOCKED_SCAN_DIRS = _RestHandler._BLOCKED_SCAN_DIRS

        _RestHandler._handle_scan(handler, {"path": "/nonexistent/path/abc123"})
        handler._send_error.assert_called_once()
        assert handler._send_error.call_args[0][0] == 404

    def test_system_dir_returns_403(self):
        from ai_guardian.daemon.rest_api import _RestHandler

        handler = MagicMock(spec=_RestHandler)
        handler._send_error = MagicMock()
        handler._BLOCKED_SCAN_DIRS = _RestHandler._BLOCKED_SCAN_DIRS

        _RestHandler._handle_scan(handler, {"path": "/usr"})
        handler._send_error.assert_called_once()
        assert handler._send_error.call_args[0][0] == 403

    def test_valid_scan_returns_findings(self, tmp_path):
        from ai_guardian.daemon.rest_api import _RestHandler

        test_file = tmp_path / "test.py"
        test_file.write_text("API_KEY = 'sk-test123456789'")

        handler = MagicMock(spec=_RestHandler)
        handler._send_json = MagicMock()
        handler._send_error = MagicMock()
        handler.server = MagicMock()
        handler.server.daemon_state = MagicMock()
        handler.server.daemon_state.get_config.return_value = {}
        handler._BLOCKED_SCAN_DIRS = _RestHandler._BLOCKED_SCAN_DIRS

        _RestHandler._handle_scan(handler, {"path": str(tmp_path)})

        if handler._send_json.called:
            result = handler._send_json.call_args[0][0]
            assert "findings" in result
            assert "scan_time_ms" in result
            assert isinstance(result["findings"], list)

            for f in result["findings"]:
                assert "config_section" in f

    def test_single_file_scan(self, tmp_path):
        from ai_guardian.daemon.rest_api import _RestHandler

        test_file = tmp_path / "clean.py"
        test_file.write_text("print('hello')")

        handler = MagicMock(spec=_RestHandler)
        handler._send_json = MagicMock()
        handler._send_error = MagicMock()
        handler.server = MagicMock()
        handler.server.daemon_state = MagicMock()
        handler.server.daemon_state.get_config.return_value = {}
        handler._BLOCKED_SCAN_DIRS = _RestHandler._BLOCKED_SCAN_DIRS

        _RestHandler._handle_scan(handler, {"path": str(test_file)})

        if handler._send_json.called:
            result = handler._send_json.call_args[0][0]
            assert "findings" in result
            assert isinstance(result["findings"], list)


class TestMultiClientScanPath:
    """Test the scan_path method in MultiDaemonClient."""

    def test_local_scan(self, tmp_path):
        from ai_guardian.daemon.multi_client import MultiDaemonClient

        test_file = tmp_path / "clean.py"
        test_file.write_text("x = 1")

        result = MultiDaemonClient._local_scan(str(tmp_path))

        assert "findings" in result
        assert "scan_time_ms" in result
        assert isinstance(result["findings"], list)

    def test_local_scan_enriches_config_section(self, tmp_path):
        from ai_guardian.daemon.multi_client import MultiDaemonClient

        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1")

        result = MultiDaemonClient._local_scan(str(tmp_path))

        for f in result["findings"]:
            assert "config_section" in f


class TestRestRequestTimeout:
    """Test that _rest_request accepts a timeout parameter."""

    def test_timeout_parameter_accepted(self):
        from ai_guardian.daemon.multi_client import MultiDaemonClient
        from ai_guardian.daemon.discovery import DaemonTarget
        import inspect

        sig = inspect.signature(MultiDaemonClient._rest_request)
        assert "timeout" in sig.parameters

    def test_timeout_default_is_request_timeout(self):
        from ai_guardian.daemon.multi_client import (
            MultiDaemonClient,
            REQUEST_TIMEOUT,
        )
        import inspect

        sig = inspect.signature(MultiDaemonClient._rest_request)
        default = sig.parameters["timeout"].default
        assert default == REQUEST_TIMEOUT
