"""Tests for violation_rescan module (Issue #1146)."""

import json
import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest

from ai_guardian.daemon.violation_rescan import (
    rescan_violation,
    _extract_line_near,
    _find_nearest_redaction,
)
from ai_guardian.tui.pattern_editor import (
    config_section_for_violation,
    VIOLATION_TYPE_TO_CONFIG,
)


class TestConfigSectionForViolation:
    """Test the violation type to config section mapping."""

    def test_secret_detected(self):
        assert config_section_for_violation("secret_detected") == "secret_scanning"

    def test_pii_detected(self):
        assert config_section_for_violation("pii_detected") == "scan_pii"

    def test_prompt_injection(self):
        assert config_section_for_violation("prompt_injection") == "prompt_injection"

    def test_jailbreak_detected(self):
        assert config_section_for_violation("jailbreak_detected") == "prompt_injection"

    def test_directory_blocking(self):
        assert config_section_for_violation("directory_blocking") == "directory_rules"

    def test_ssrf_blocked(self):
        assert config_section_for_violation("ssrf_blocked") == "ssrf_protection"

    def test_config_file_exfil(self):
        assert config_section_for_violation("config_file_exfil") == "config_file_scanning"

    def test_context_poisoning(self):
        assert config_section_for_violation("context_poisoning") == "context_poisoning"

    def test_supply_chain(self):
        assert config_section_for_violation("supply_chain") == "supply_chain"

    def test_tool_permission(self):
        assert config_section_for_violation("tool_permission") == "permissions"

    def test_unknown_type_returns_empty(self):
        assert config_section_for_violation("unknown_type") == ""


class TestExtractLineNear:
    """Test the _extract_line_near helper."""

    def test_extracts_correct_line(self):
        content = "line1\nline2\nline3\n"
        assert _extract_line_near(content, 2) == "line2"

    def test_first_line(self):
        content = "first\nsecond"
        assert _extract_line_near(content, 1) == "first"

    def test_last_line(self):
        content = "first\nlast"
        assert _extract_line_near(content, 2) == "last"

    def test_out_of_range_clamps(self):
        content = "only_line"
        assert _extract_line_near(content, 5) == "only_line"

    def test_empty_content(self):
        assert _extract_line_near("", 1) == ""

    def test_zero_line(self):
        assert _extract_line_near("content", 0) == ""

    def test_strips_whitespace(self):
        content = "  spaced  \n"
        assert _extract_line_near(content, 1) == "spaced"


class TestFindNearestRedaction:
    """Test the _find_nearest_redaction helper."""

    def test_finds_nearest_by_line(self):
        content = "0123456789" * 10
        redactions = [
            {"type": "pii-ssn", "line_number": 5, "position": 0, "original_length": 3},
            {"type": "pii-ssn", "line_number": 10, "position": 5, "original_length": 3},
        ]
        result = _find_nearest_redaction(redactions, 6, "pii-ssn", content)
        assert result is not None
        assert result["line_number"] == 5

    def test_filters_by_sub_type(self):
        content = "abcdef"
        redactions = [
            {"type": "pii-phone", "line_number": 1, "position": 0, "original_length": 3},
            {"type": "pii-ssn", "line_number": 2, "position": 3, "original_length": 3},
        ]
        result = _find_nearest_redaction(redactions, 1, "pii-ssn", content)
        assert result is not None
        assert result["line_number"] == 2

    def test_empty_redactions(self):
        result = _find_nearest_redaction([], 1, "", "content")
        assert result is None


class TestRescanViolation:
    """Test the rescan_violation function."""

    def test_file_not_found(self):
        result = rescan_violation(
            file_path="/nonexistent/path/file.py",
            line_number=1,
            violation_type="secret_detected",
        )
        assert result["status"] == "file_not_found"

    def test_empty_file_path(self):
        result = rescan_violation(
            file_path="",
            line_number=1,
            violation_type="secret_detected",
        )
        assert result["status"] == "not_found"

    def test_unsupported_violation_type(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("content")
            f.flush()
            try:
                result = rescan_violation(
                    file_path=f.name,
                    line_number=1,
                    violation_type="unknown_type_xyz",
                )
                assert result["status"] == "not_found"
                assert "Unsupported" in result.get("message", "")
            finally:
                os.unlink(f.name)

    def test_passthrough_types_return_line_content(self):
        """directory_blocking, ssrf_blocked etc. return line content directly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("line1\nblocked_path\nline3\n")
            f.flush()
            try:
                result = rescan_violation(
                    file_path=f.name,
                    line_number=2,
                    violation_type="directory_blocking",
                )
                assert result["status"] == "found"
                assert result["matched_text"] == "blocked_path"
            finally:
                os.unlink(f.name)

    @patch("ai_guardian.hook_processing.check_secrets_with_gitleaks")
    def test_secret_scan_found(self, mock_scan):
        """Secret rescan returns matched text when scanner finds secrets."""
        mock_scan.return_value = (True, "Secret detected")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("normal\nAPI_KEY=secret123\nnormal\n")
            f.flush()
            try:
                import ai_guardian.hook_processing as hp
                hp._last_secret_matched_text = "API_KEY=secret123"

                result = rescan_violation(
                    file_path=f.name,
                    line_number=2,
                    violation_type="secret_detected",
                    sub_type="env-variable",
                    config={"secret_scanning": {"enabled": True}},
                )
                assert result["status"] == "found"
                assert "API_KEY" in result["matched_text"]
            finally:
                os.unlink(f.name)

    @patch("ai_guardian.hook_processing.check_secrets_with_gitleaks")
    def test_secret_scan_not_found(self, mock_scan):
        """Secret rescan returns not_found when scanner finds nothing."""
        mock_scan.return_value = (False, None)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("clean content\n")
            f.flush()
            try:
                result = rescan_violation(
                    file_path=f.name,
                    line_number=1,
                    violation_type="secret_detected",
                    config={"secret_scanning": {"enabled": True}},
                )
                assert result["status"] == "not_found"
            finally:
                os.unlink(f.name)

    @patch("ai_guardian.hook_processing._scan_for_pii")
    def test_pii_scan_found(self, mock_pii):
        """PII rescan returns matched text."""
        mock_pii.return_value = (
            True,
            "***REDACTED***",
            [{"type": "pii-ssn", "line_number": 2, "position": 4, "original_length": 11}],
            "PII found",
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("name\nssn=078-05-1120\naddr\n")
            f.flush()
            try:
                result = rescan_violation(
                    file_path=f.name,
                    line_number=2,
                    violation_type="pii_detected",
                    sub_type="pii-ssn",
                    config={"scan_pii": {"enabled": True}},
                )
                assert result["status"] == "found"
                assert result["violation_type"] == "pii_detected"
            finally:
                os.unlink(f.name)


class TestRestEndpoint:
    """Test the REST API endpoint for violation-context."""

    def test_handler_requires_violation_type(self):
        """Handler returns 400 if violation_type missing."""
        from ai_guardian.daemon.rest_api import _RestHandler
        handler = MagicMock(spec=_RestHandler)
        handler.headers = {"Authorization": "Bearer test"}
        handler._read_body = MagicMock(return_value={"file_path": "/tmp/x"})
        handler._send_error = MagicMock()
        handler._send_json = MagicMock()

        _RestHandler._handle_violation_context(handler, {"file_path": "/tmp/x"})
        handler._send_error.assert_called_once_with(400, "violation_type is required")

    def test_handler_calls_rescan(self):
        """Handler calls rescan_violation and returns result."""
        from ai_guardian.daemon.rest_api import _RestHandler

        handler = MagicMock(spec=_RestHandler)
        handler.server = MagicMock()
        handler.server.daemon_state.get_config.return_value = {}
        handler._send_json = MagicMock()

        body = {
            "file_path": "/nonexistent",
            "violation_type": "secret_detected",
            "line_number": 1,
            "secret_type": "env-variable",
        }

        _RestHandler._handle_violation_context(handler, body)
        handler._send_json.assert_called_once()
        result = handler._send_json.call_args[0][0]
        assert result["status"] == "file_not_found"
