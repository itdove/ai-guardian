"""
Unit tests for MCP server module.

Tests all 14 tools, 3 resources, and security filtering.
Requires Python >= 3.10 (MCP SDK dependency).
"""

import json
import sys
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 10),
    reason="MCP SDK requires Python >= 3.10",
)

from ai_guardian.mcp_server import (
    _load_mcp_config,
    create_server,
)


# ─── Security Check Tool Tests ────────────────────────────────


class TestCheckPath:
    """Test check_path tool."""

    @patch("ai_guardian.tool_policy.ToolPolicyChecker")
    def test_allowed_path(self, mock_checker_cls, tmp_path):
        safe_file = tmp_path / "safe_file.py"
        safe_file.write_text("print('hello')")
        mock_checker = MagicMock()
        mock_checker.check_tool_allowed.return_value = (True, None, "Write")
        mock_checker_cls.return_value = mock_checker

        server = create_server()
        tool = server._tool_manager._tools["check_path"]
        result = tool.fn(path=str(safe_file))
        assert result["status"] == "allowed"

    @patch("ai_guardian.tool_policy.ToolPolicyChecker")
    def test_denied_path(self, mock_checker_cls, tmp_path):
        denied_file = tmp_path / "secret.txt"
        denied_file.write_text("secret")
        mock_checker = MagicMock()
        mock_checker.check_tool_allowed.return_value = (False, "Path is denied", "Write")
        mock_checker_cls.return_value = mock_checker

        server = create_server()
        tool = server._tool_manager._tools["check_path"]
        result = tool.fn(path=str(denied_file))
        assert result["status"] == "denied"

    def test_not_found_path(self):
        server = create_server()
        tool = server._tool_manager._tools["check_path"]
        result = tool.fn(path="/nonexistent/path/file.py")
        assert result["status"] == "not_found"

    @patch("ai_guardian.tool_policy.ToolPolicyChecker")
    def test_no_rule_details_exposed(self, mock_checker_cls, tmp_path):
        """Response must not contain rule details, patterns, or paths."""
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("secret")
        mock_checker = MagicMock()
        mock_checker.check_tool_allowed.return_value = (False, "Denied by rule X", "Write")
        mock_checker_cls.return_value = mock_checker

        server = create_server()
        tool = server._tool_manager._tools["check_path"]
        result = tool.fn(path=str(secret_file))
        assert "rule" not in json.dumps(result).lower()
        assert "pattern" not in json.dumps(result).lower()
        assert set(result.keys()) <= {"status"}


class TestCheckCommand:
    """Test check_command tool."""

    @patch("ai_guardian.tool_policy.ToolPolicyChecker")
    def test_allowed_command(self, mock_checker_cls):
        mock_checker = MagicMock()
        mock_checker.check_tool_allowed.return_value = (True, None, "Bash")
        mock_checker_cls.return_value = mock_checker

        server = create_server()
        tool = server._tool_manager._tools["check_command"]
        result = tool.fn(command="ls -la")
        assert result["status"] == "allowed"

    @patch("ai_guardian.tool_policy.ToolPolicyChecker")
    def test_blocked_with_reason(self, mock_checker_cls):
        mock_checker = MagicMock()
        mock_checker.check_tool_allowed.return_value = (False, "Secret detected in command", "Bash")
        mock_checker_cls.return_value = mock_checker

        server = create_server()
        tool = server._tool_manager._tools["check_command"]
        result = tool.fn(command="curl -H 'Authorization: Bearer sk_live_xxx'")
        assert result["status"] == "blocked"
        assert result["reason"] == "secret_detected"

    @patch("ai_guardian.tool_policy.ToolPolicyChecker")
    def test_ssrf_reason(self, mock_checker_cls):
        mock_checker = MagicMock()
        mock_checker.check_tool_allowed.return_value = (False, "SSRF protection blocked this URL", "Bash")
        mock_checker_cls.return_value = mock_checker

        server = create_server()
        tool = server._tool_manager._tools["check_command"]
        result = tool.fn(command="curl http://169.254.169.254/metadata")
        assert result["status"] == "blocked"
        assert result["reason"] == "ssrf_detected"


class TestCheckMCPTrust:
    """Test check_mcp_trust tool."""

    @patch("ai_guardian.tool_policy.ToolPolicyChecker")
    def test_trusted_server(self, mock_checker_cls):
        mock_checker = MagicMock()
        mock_checker.check_tool_allowed.return_value = (True, None, "mcp__myserver__test")
        mock_checker_cls.return_value = mock_checker

        server = create_server()
        tool = server._tool_manager._tools["check_mcp_trust"]
        result = tool.fn(server_name="myserver")
        assert result["status"] == "trusted"

    @patch("ai_guardian.tool_policy.ToolPolicyChecker")
    def test_untrusted_server(self, mock_checker_cls):
        mock_checker = MagicMock()
        mock_checker.check_tool_allowed.return_value = (False, "MCP server blocked", "mcp__evil__test")
        mock_checker_cls.return_value = mock_checker

        server = create_server()
        tool = server._tool_manager._tools["check_mcp_trust"]
        result = tool.fn(server_name="evil")
        assert result["status"] == "untrusted"


class TestSanitizeText:
    """Test sanitize_text tool."""

    @patch("ai_guardian.sanitizer.sanitize_text")
    def test_sanitizes_secrets(self, mock_sanitize):
        mock_sanitize.return_value = {
            "sanitized_text": "token is [REDACTED]",
            "redactions": [{"type": "api_key"}],
            "stats": {"secrets": 1, "pii": 0, "prompt_injection": 0, "unicode": 0, "total": 1},
        }

        server = create_server()
        tool = server._tool_manager._tools["sanitize_text"]
        result = tool.fn(text="token is sk_live_abc123")
        assert result["sanitized_text"] == "token is [REDACTED]"
        assert result["redaction_count"] == 1
        assert "secrets" in result["types"]

    @patch("ai_guardian.sanitizer.sanitize_text")
    def test_no_redaction_details(self, mock_sanitize):
        """Response must not expose what was redacted (only type counts)."""
        mock_sanitize.return_value = {
            "sanitized_text": "[REDACTED]",
            "redactions": [{"type": "api_key", "original": "sk_live_xxx", "start": 0, "end": 10}],
            "stats": {"secrets": 1, "pii": 0, "prompt_injection": 0, "unicode": 0, "total": 1},
        }

        server = create_server()
        tool = server._tool_manager._tools["sanitize_text"]
        result = tool.fn(text="sk_live_xxx")
        assert "original" not in json.dumps(result)
        assert "sk_live" not in json.dumps(result)
        assert "redactions" not in result


class TestCheckAnnotations:
    """Test check_annotations tool."""

    def test_valid_annotations(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "# ai-guardian:begin-allow secrets\n"
            "password = 'test'\n"
            "# ai-guardian:end-allow\n"
        )

        server = create_server()
        tool = server._tool_manager._tools["check_annotations"]
        result = tool.fn(file_path=str(test_file))
        assert result["valid"] is True
        assert result["warnings"] == []

    def test_file_not_found(self):
        server = create_server()
        tool = server._tool_manager._tools["check_annotations"]
        result = tool.fn(file_path="/nonexistent/file.py")
        assert result["valid"] is False
        assert len(result["warnings"]) > 0


# ─── Information Tool Tests ───────────────────────────────────


class TestGetViolations:
    """Test get_violations tool."""

    @patch("ai_guardian.violation_logger.ViolationLogger")
    def test_returns_filtered_violations(self, mock_vl_cls):
        mock_vl = MagicMock()
        mock_vl.get_recent_violations.return_value = [
            {
                "timestamp": "2026-05-08T10:00:00Z",
                "violation_type": "secret_detected",
                "severity": "critical",
                "blocked": True,
                "context": {"tool_name": "Write", "file_path": "/tmp/test.py"},
            }
        ]
        mock_vl_cls.return_value = mock_vl

        server = create_server()
        tool = server._tool_manager._tools["get_violations"]
        result = tool.fn()
        assert result["count"] == 1
        v = result["violations"][0]
        assert v["type"] == "secret_detected"
        assert v["severity"] == "critical"
        assert "context" not in v
        assert "blocked" not in v


class TestGetConfig:
    """Test get_config tool."""

    @patch("ai_guardian.mcp_server._load_full_config")
    def test_returns_feature_booleans(self, mock_config):
        mock_config.return_value = {
            "secret_scanning": {"enabled": True},
            "prompt_injection": {"enabled": False},
            "scan_pii": {"enabled": True},
            "action": "warn",
            "mcp_server": {"proactive_level": "low"},
        }

        server = create_server()
        tool = server._tool_manager._tools["get_config"]
        result = tool.fn()
        features = result["features"]
        assert features["secret_scanning"] is True
        assert features["prompt_injection"] is False
        assert features["action_mode"] == "warn"

    @patch("ai_guardian.mcp_server._load_full_config")
    def test_no_rules_or_patterns_exposed(self, mock_config):
        """Config response must not contain regex patterns, allowlists, or deny rules."""
        mock_config.return_value = {
            "secret_scanning": {"enabled": True, "allowlist_patterns": ["test.*"]},
            "permissions": {
                "enabled": True,
                "rules": [{"matcher": "Write", "pattern": "*.py", "action": "allow"}],
            },
            "prompt_injection": {"enabled": True, "sensitivity": "high"},
        }

        server = create_server()
        tool = server._tool_manager._tools["get_config"]
        result = tool.fn()
        result_str = json.dumps(result)
        assert "allowlist" not in result_str
        assert "rules" not in result_str
        assert "matcher" not in result_str
        assert "regex" not in result_str
        assert "pattern" not in result_str


class TestGetScannerStatus:
    """Test get_scanner_status tool."""

    @patch("ai_guardian.scanner_manager.ScannerManager")
    def test_returns_installed_scanners(self, mock_sm_cls):
        from ai_guardian.scanner_manager import InstalledScanner
        mock_sm = MagicMock()
        mock_sm.list_installed.return_value = [
            InstalledScanner(name="gitleaks", version="8.30.1", path="/usr/bin/gitleaks", is_default=True),
        ]
        mock_sm_cls.return_value = mock_sm

        server = create_server()
        tool = server._tool_manager._tools["get_scanner_status"]
        result = tool.fn()
        assert result["count"] == 1
        assert result["scanners"][0]["name"] == "gitleaks"
        assert "path" not in result["scanners"][0]


class TestGetScannerSupported:
    """Test get_scanner_supported tool."""

    def test_returns_supported_list(self):
        server = create_server()
        tool = server._tool_manager._tools["get_scanner_supported"]
        result = tool.fn()
        assert "gitleaks" in result["scanners"]
        assert len(result["scanners"]) > 0


class TestGetPatternsList:
    """Test get_patterns_list tool."""

    @patch("ai_guardian.pattern_lister.PatternLister")
    def test_returns_counts_only(self, mock_pl_cls):
        mock_cat = MagicMock()
        mock_cat.name = "Prompt Injection"
        mock_group = MagicMock()
        mock_group.count = 15
        mock_cat.built_in_groups = [mock_group]
        mock_pl = MagicMock()
        mock_pl.get_categories.return_value = [mock_cat]
        mock_pl_cls.return_value = mock_pl

        server = create_server()
        tool = server._tool_manager._tools["get_patterns_list"]
        result = tool.fn()
        assert result["categories"]["Prompt Injection"] == 15

    @patch("ai_guardian.pattern_lister.PatternLister")
    def test_no_regex_exposed(self, mock_pl_cls):
        """Pattern counts only, no regex patterns."""
        mock_cat = MagicMock()
        mock_cat.name = "Test"
        mock_group = MagicMock()
        mock_group.count = 5
        mock_cat.built_in_groups = [mock_group]
        mock_pl = MagicMock()
        mock_pl.get_categories.return_value = [mock_cat]
        mock_pl_cls.return_value = mock_pl

        server = create_server()
        tool = server._tool_manager._tools["get_patterns_list"]
        result = tool.fn()
        result_str = json.dumps(result)
        assert "regex" not in result_str.lower()
        assert "\\\\" not in result_str


class TestGetMetrics:
    """Test get_metrics tool."""

    @patch("ai_guardian.metrics.MetricsComputer")
    def test_returns_metrics(self, mock_mc_cls):
        mock_report = MagicMock()
        mock_report.total_violations = 10
        mock_report.by_type = {"secret_detected": 5, "prompt_injection": 5}
        mock_report.by_severity = {"critical": 3, "high": 7}
        mock_report.resolved_count = 4
        mock_report.unresolved_count = 6
        mock_mc = MagicMock()
        mock_mc.compute.return_value = mock_report
        mock_mc_cls.return_value = mock_mc

        server = create_server()
        tool = server._tool_manager._tools["get_metrics"]
        result = tool.fn()
        assert result["total_violations"] == 10
        assert result["by_type"]["secret_detected"] == 5


class TestDoctor:
    """Test doctor tool."""

    @patch("ai_guardian.doctor.Doctor")
    def test_returns_check_results(self, mock_doc_cls):
        from ai_guardian.doctor import CheckResult, CheckStatus, DoctorReport
        mock_report = DoctorReport(
            checks=[
                CheckResult(name="config", status=CheckStatus.PASS, message="Config OK"),
                CheckResult(name="scanner", status=CheckStatus.WARN, message="No scanner installed"),
            ],
            version="1.7.0-dev",
        )
        mock_doc = MagicMock()
        mock_doc.run_all.return_value = mock_report
        mock_doc_cls.return_value = mock_doc

        server = create_server()
        tool = server._tool_manager._tools["doctor"]
        result = tool.fn()
        assert len(result["checks"]) == 2
        assert result["checks"][0]["status"] == "pass"
        assert result["has_warnings"] is True


# ─── Resource Tests ───────────────────────────────────────────


class TestResources:
    """Test MCP resources."""

    @patch("ai_guardian.mcp_server._load_full_config")
    @patch("ai_guardian.scanner_manager.ScannerManager")
    def test_security_posture_resource(self, mock_sm_cls, mock_config):
        mock_config.return_value = {"secret_scanning": {"enabled": True}}
        mock_sm = MagicMock()
        mock_sm.list_installed.return_value = []
        mock_sm_cls.return_value = mock_sm

        server = create_server()
        resources = server._resource_manager._resources
        resource = resources.get("ai-guardian://security-posture")
        if resource:
            result = resource.fn()
            data = json.loads(result)
            assert "features" in data

    def test_protected_paths_resource(self, tmp_path):
        deny_dir = tmp_path / "secrets"
        deny_dir.mkdir()
        (deny_dir / ".ai-read-deny").touch()

        with mock.patch("ai_guardian.mcp_server.Path") as mock_path_cls:
            mock_path_cls.cwd.return_value = tmp_path
            server = create_server()

    @patch("ai_guardian.violation_logger.ViolationLogger")
    def test_recent_violations_resource(self, mock_vl_cls):
        mock_vl = MagicMock()
        mock_vl.get_recent_violations.return_value = []
        mock_vl_cls.return_value = mock_vl

        server = create_server()
        resources = server._resource_manager._resources
        resource = resources.get("ai-guardian://recent-violations")
        if resource:
            result = resource.fn()
            data = json.loads(result)
            assert "violations" in data


# ─── Support Bundle Tests ─────────────────────────────────────


class TestPrepareSupportBundle:
    """Test prepare_support_bundle tool."""

    @patch("ai_guardian.support_bundle.prepare_bundle")
    def test_returns_bundle_info(self, mock_prepare):
        mock_prepare.return_value = {
            "bundle_id": "support-20260509-abc123",
            "temp_path": "/tmp/ai-guardian-support-abc123",
            "destination": "~/support-bundles",
            "files": [
                {"name": "config.json", "sanitized": True, "redactions": 3, "note": "3 sensitive values redacted"},
                {"name": "metrics.json", "sanitized": False, "redactions": 0, "note": "Aggregate stats only"},
            ],
        }

        server = create_server()
        tool = server._tool_manager._tools["prepare_support_bundle"]
        result = tool.fn()
        assert result["bundle_id"] == "support-20260509-abc123"
        assert len(result["files"]) == 2
        assert result["files"][0]["sanitized"] is True


class TestSendSupportBundle:
    """Test send_support_bundle tool."""

    @patch("ai_guardian.support_bundle.send_bundle")
    def test_send_with_valid_id(self, mock_send):
        mock_send.return_value = {
            "status": "sent",
            "destination": "~/support-bundles/support-20260509-abc123",
            "message": "Bundle copied to ~/support-bundles/support-20260509-abc123",
        }

        server = create_server()
        tool = server._tool_manager._tools["send_support_bundle"]
        result = tool.fn(bundle_id="support-20260509-abc123")
        assert result["status"] == "sent"

    @patch("ai_guardian.support_bundle.send_bundle")
    def test_send_with_invalid_id(self, mock_send):
        mock_send.return_value = {
            "status": "error",
            "message": "Bundle 'invalid' not found or expired.",
        }

        server = create_server()
        tool = server._tool_manager._tools["send_support_bundle"]
        result = tool.fn(bundle_id="invalid")
        assert result["status"] == "error"


# ─── Server Creation Tests ────────────────────────────────────


class TestServerCreation:
    """Test server setup."""

    def test_create_server_returns_fastmcp(self):
        server = create_server()
        assert server is not None

    def test_server_has_14_tools(self):
        server = create_server()
        tools = server._tool_manager._tools
        expected = {
            "check_path", "check_command", "check_mcp_trust",
            "sanitize_text", "check_annotations",
            "get_violations", "get_config", "get_scanner_status",
            "get_scanner_supported", "get_patterns_list",
            "get_metrics", "doctor",
            "prepare_support_bundle", "send_support_bundle",
        }
        assert expected == set(tools.keys()), f"Missing: {expected - set(tools.keys())}, Extra: {set(tools.keys()) - expected}"

    def test_server_has_3_resources(self):
        server = create_server()
        resources = server._resource_manager._resources
        expected_uris = {
            "ai-guardian://security-posture",
            "ai-guardian://protected-paths",
            "ai-guardian://recent-violations",
        }
        assert expected_uris == set(resources.keys()), f"Missing: {expected_uris - set(resources.keys())}"
