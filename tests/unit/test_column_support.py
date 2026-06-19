"""Tests for column number support in violation reports (Issue #1261)."""

import json
import os
import tempfile
import unittest

from ai_guardian.scanners.output_parsers import (
    GitleaksOutputParser,
    LeakTKOutputParser,
    SecretlintOutputParser,
    GitGuardianOutputParser,
    TruffleHogOutputParser,
    DetectSecretsOutputParser,
)
from ai_guardian.scanners.sdk import Finding
from ai_guardian.scanners.strategies import SecretMatch


class TestFindingColumnFields(unittest.TestCase):
    """Finding dataclass has column fields with correct defaults."""

    def test_default_columns_are_none(self):
        f = Finding(rule_id="r", line_number=1, matched_text="x", description="d")
        self.assertIsNone(f.start_column)
        self.assertIsNone(f.end_column)

    def test_columns_can_be_set(self):
        f = Finding(rule_id="r", line_number=1, matched_text="x", description="d",
                    start_column=5, end_column=10)
        self.assertEqual(f.start_column, 5)
        self.assertEqual(f.end_column, 10)

    def test_column_zero_is_valid(self):
        f = Finding(rule_id="r", line_number=1, matched_text="x", description="d",
                    start_column=0, end_column=0)
        self.assertEqual(f.start_column, 0)
        self.assertEqual(f.end_column, 0)


class TestSecretMatchColumnFields(unittest.TestCase):
    """SecretMatch dataclass has column fields with correct defaults."""

    def test_default_columns_are_none(self):
        m = SecretMatch(rule_id="r", description="d", file="f", line_number=1)
        self.assertIsNone(m.start_column)
        self.assertIsNone(m.end_column)

    def test_columns_can_be_set(self):
        m = SecretMatch(rule_id="r", description="d", file="f", line_number=1,
                        start_column=3, end_column=20)
        self.assertEqual(m.start_column, 3)
        self.assertEqual(m.end_column, 20)


class TestGitleaksColumnParsing(unittest.TestCase):
    """GitleaksOutputParser extracts StartColumn/EndColumn."""

    def test_columns_extracted(self):
        data = [{
            "RuleID": "test-rule",
            "File": "test.py",
            "StartLine": 10,
            "EndLine": 10,
            "StartColumn": 5,
            "EndColumn": 25,
            "Description": "Test",
            "Match": "secret",
        }]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            result = GitleaksOutputParser().parse(path)
            finding = result["findings"][0]
            self.assertEqual(finding["start_column"], 5)
            self.assertEqual(finding["end_column"], 25)
        finally:
            os.unlink(path)

    def test_columns_absent(self):
        data = [{
            "RuleID": "test-rule",
            "File": "test.py",
            "StartLine": 10,
            "EndLine": 10,
            "Description": "Test",
        }]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            result = GitleaksOutputParser().parse(path)
            finding = result["findings"][0]
            self.assertIsNone(finding["start_column"])
            self.assertIsNone(finding["end_column"])
        finally:
            os.unlink(path)


class TestLeakTKColumnParsing(unittest.TestCase):
    """LeakTKOutputParser extracts StartColumn/EndColumn."""

    def test_columns_extracted(self):
        data = {"findings": [{
            "RuleID": "test-rule",
            "File": "test.py",
            "StartLine": 5,
            "EndLine": 5,
            "StartColumn": 0,
            "EndColumn": 15,
            "Description": "Test",
            "Match": "secret",
        }], "errors": []}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            result = LeakTKOutputParser().parse(path)
            finding = result["findings"][0]
            self.assertEqual(finding["start_column"], 0)
            self.assertEqual(finding["end_column"], 15)
        finally:
            os.unlink(path)


class TestSecretlintColumnParsing(unittest.TestCase):
    """SecretlintOutputParser extracts loc.start.column/end.column."""

    def test_columns_extracted(self):
        data = [{
            "filePath": "/test.py",
            "messages": [{
                "ruleId": "test-rule",
                "message": "Found secret",
                "loc": {
                    "start": {"line": 3, "column": 8},
                    "end": {"line": 3, "column": 42},
                },
            }],
        }]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            result = SecretlintOutputParser().parse(path)
            finding = result["findings"][0]
            self.assertEqual(finding["start_column"], 8)
            self.assertEqual(finding["end_column"], 42)
        finally:
            os.unlink(path)

    def test_columns_absent(self):
        data = [{
            "filePath": "/test.py",
            "messages": [{
                "ruleId": "test-rule",
                "message": "Found secret",
                "loc": {
                    "start": {"line": 3},
                    "end": {"line": 3},
                },
            }],
        }]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            result = SecretlintOutputParser().parse(path)
            finding = result["findings"][0]
            self.assertIsNone(finding["start_column"])
            self.assertIsNone(finding["end_column"])
        finally:
            os.unlink(path)


class TestGitGuardianColumnParsing(unittest.TestCase):
    """GitGuardianOutputParser extracts column_start/column_end."""

    def test_columns_extracted(self):
        data = {
            "policy_break_count": 1,
            "policies": ["Secrets detection"],
            "policy_breaks": [{
                "break_type": "AWS Keys",
                "policy": "Secrets detection",
                "validity": "valid_data",
                "incidents": [{
                    "location": {
                        "filename": "test.py",
                        "line_start": 5,
                        "line_end": 5,
                        "column_start": 10,
                        "column_end": 30,
                    },
                    "type": "aws_access_key_id",
                }],
            }],
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            result = GitGuardianOutputParser().parse(path)
            finding = result["findings"][0]
            self.assertEqual(finding["start_column"], 10)
            self.assertEqual(finding["end_column"], 30)
        finally:
            os.unlink(path)

    def test_columns_absent(self):
        data = {
            "policy_break_count": 1,
            "policies": ["Secrets detection"],
            "policy_breaks": [{
                "break_type": "AWS Keys",
                "policy": "Secrets detection",
                "validity": "",
                "incidents": [{
                    "location": {
                        "filename": "test.py",
                        "line_start": 5,
                        "line_end": 5,
                    },
                    "type": "aws_access_key_id",
                }],
            }],
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            result = GitGuardianOutputParser().parse(path)
            finding = result["findings"][0]
            self.assertIsNone(finding["start_column"])
            self.assertIsNone(finding["end_column"])
        finally:
            os.unlink(path)


class TestTruffleHogNoColumns(unittest.TestCase):
    """TruffleHog does not provide columns — findings lack column keys."""

    def test_no_column_keys(self):
        line = json.dumps({
            "SourceMetadata": {"Data": {"Filesystem": {"file": "t.py", "line": 1}}},
            "DetectorName": "AWS",
            "Verified": False,
        })
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(line + "\n")
            path = f.name
        try:
            result = TruffleHogOutputParser().parse(path)
            finding = result["findings"][0]
            self.assertNotIn("start_column", finding)
            self.assertNotIn("end_column", finding)
        finally:
            os.unlink(path)


class TestDetectSecretsNoColumns(unittest.TestCase):
    """detect-secrets does not provide columns."""

    def test_no_column_keys(self):
        data = {
            "results": {"test.py": [{"type": "API Key", "line_number": 5}]},
            "version": "1.0.0",
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            result = DetectSecretsOutputParser().parse(path)
            finding = result["findings"][0]
            self.assertNotIn("start_column", finding)
            self.assertNotIn("end_column", finding)
        finally:
            os.unlink(path)


class TestTomlPatternsColumn(unittest.TestCase):
    """TOML patterns scanner computes column from match position."""

    def _make_scanner(self):
        from ai_guardian.scanners.toml_patterns import TomlPatternsScanner
        from ai_guardian.patterns.cache import PatternCache
        cache = PatternCache()
        cache.load_rules([{
            "id": "test-secret",
            "regex": r"AKIA[0-9A-Z]{16}",
            "description": "AWS key",
            "category": "secrets",
        }], category="secrets")
        scanner = TomlPatternsScanner()
        scanner._cache = cache
        return scanner

    def test_column_computed(self):
        scanner = self._make_scanner()
        content = "some prefix AKIA0123456789ABCDEF rest"
        findings = scanner.scan(content)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.start_column, 12)
        self.assertIsNotNone(f.end_column)

    def test_column_zero_at_line_start(self):
        scanner = self._make_scanner()
        content = "AKIA0123456789ABCDEF rest"
        findings = scanner.scan(content)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].start_column, 0)

    def test_column_on_second_line(self):
        scanner = self._make_scanner()
        content = "line one\n   AKIA0123456789ABCDEF rest"
        findings = scanner.scan(content)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line_number, 2)
        self.assertEqual(findings[0].start_column, 3)


class TestEnrichBlockedFromDetails(unittest.TestCase):
    """_enrich_blocked_from_details propagates column fields."""

    def test_column_propagated(self):
        from ai_guardian.hook_processing import _enrich_blocked_from_details
        blocked = {}
        details = {"line_number": 10, "start_column": 5, "end_column": 20}
        _enrich_blocked_from_details(blocked, details)
        self.assertEqual(blocked["start_column"], 5)
        self.assertEqual(blocked["end_column"], 20)

    def test_column_zero_propagated(self):
        from ai_guardian.hook_processing import _enrich_blocked_from_details
        blocked = {}
        details = {"line_number": 1, "start_column": 0, "end_column": 0}
        _enrich_blocked_from_details(blocked, details)
        self.assertEqual(blocked["start_column"], 0)
        self.assertEqual(blocked["end_column"], 0)

    def test_column_absent(self):
        from ai_guardian.hook_processing import _enrich_blocked_from_details
        blocked = {}
        details = {"line_number": 10}
        _enrich_blocked_from_details(blocked, details)
        self.assertNotIn("start_column", blocked)
        self.assertNotIn("end_column", blocked)


class TestCacheColumnRoundtrip(unittest.TestCase):
    """Scan result cache preserves column fields."""

    def test_roundtrip(self):
        from ai_guardian.scanners.cache import ScanResultCache
        from ai_guardian.scanners.strategies import ScanResult, SecretMatch

        cache = ScanResultCache()
        result = ScanResult(
            has_secrets=True,
            secrets=[SecretMatch(
                rule_id="test",
                description="test",
                file="test.py",
                line_number=5,
                start_column=10,
                end_column=25,
                engine="test-engine",
            )],
            engine="test-engine",
        )
        cache.put("hash1", "test-engine", "cfg1", result)
        restored = cache.get("hash1", "test-engine", "cfg1")
        self.assertIsNotNone(restored)
        self.assertEqual(restored.secrets[0].start_column, 10)
        self.assertEqual(restored.secrets[0].end_column, 25)

    def test_old_cache_without_columns(self):
        """Cache entries without column fields deserialize with None."""
        m = SecretMatch(
            rule_id="test", description="test", file="f", line_number=1
        )
        self.assertIsNone(m.start_column)
        self.assertIsNone(m.end_column)


class TestAskViolationInfoColumn(unittest.TestCase):
    """AskViolationInfo dataclass has start_column field."""

    def test_default_is_none(self):
        from ai_guardian.tui.ask_dialog import AskViolationInfo
        v = AskViolationInfo(
            violation_type="test", summary="s",
            matched_text="m", config_section="c",
        )
        self.assertIsNone(v.start_column)

    def test_column_set(self):
        from ai_guardian.tui.ask_dialog import AskViolationInfo
        v = AskViolationInfo(
            violation_type="test", summary="s",
            matched_text="m", config_section="c",
            start_column=5,
        )
        self.assertEqual(v.start_column, 5)

    def test_column_zero_is_valid(self):
        from ai_guardian.tui.ask_dialog import AskViolationInfo
        v = AskViolationInfo(
            violation_type="test", summary="s",
            matched_text="m", config_section="c",
            start_column=0,
        )
        self.assertEqual(v.start_column, 0)


class TestMcpViolationsColumnExposure(unittest.TestCase):
    """MCP get_violations exposes start_column/end_column as 1-based."""

    def _make_violation(self, start_col=None, end_col=None):
        blocked = {
            "file_path": "test.py",
            "line_number": 10,
        }
        if start_col is not None:
            blocked["start_column"] = start_col
        if end_col is not None:
            blocked["end_column"] = end_col
        return {
            "timestamp": "2026-01-01T00:00:00",
            "violation_type": "secret_detected",
            "severity": "high",
            "blocked": blocked,
            "context": {"tool_name": "Write"},
        }

    def test_column_included_as_1_based(self):
        from unittest.mock import patch, MagicMock
        from ai_guardian.mcp_server import create_server
        violation = self._make_violation(start_col=4, end_col=10)
        with patch("ai_guardian.violation_logger.ViolationLogger") as MockVL:
            MockVL.return_value.get_recent_violations.return_value = [violation]
            server = create_server()
            tool = server._tool_manager._tools["get_violations"]
            result = tool.fn(limit=10)
            entry = result["violations"][0]
            self.assertEqual(entry["start_column"], 5)
            self.assertEqual(entry["end_column"], 11)

    def test_column_absent_when_none(self):
        from unittest.mock import patch
        from ai_guardian.mcp_server import create_server
        violation = self._make_violation()
        with patch("ai_guardian.violation_logger.ViolationLogger") as MockVL:
            MockVL.return_value.get_recent_violations.return_value = [violation]
            server = create_server()
            tool = server._tool_manager._tools["get_violations"]
            result = tool.fn(limit=10)
            entry = result["violations"][0]
            self.assertNotIn("start_column", entry)
            self.assertNotIn("end_column", entry)


class TestWebDetailFieldsHaveColumn(unittest.TestCase):
    """All relevant DETAIL_FIELDS entries include Column."""

    def test_all_types_with_line_have_column(self):
        from ai_guardian.web.pages.violations import DETAIL_FIELDS
        types_needing_column = [
            "tool_permission", "secret_detected", "prompt_injection",
            "secret_redaction", "pii_detected", "jailbreak_detected",
            "ssrf_blocked", "secret_in_transcript", "pii_in_transcript",
        ]
        for vtype in types_needing_column:
            fields = DETAIL_FIELDS.get(vtype, [])
            field_keys = [f[1] for f in fields]
            self.assertIn(
                "start_column", field_keys,
                f"{vtype} missing start_column in DETAIL_FIELDS",
            )


class TestHandleAskModeColumn(unittest.TestCase):
    """_handle_ask_mode passes start_column to AskViolationInfo."""

    def test_column_passed_through(self):
        from unittest.mock import patch, MagicMock
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskDecision, AskResult

        mock_result = AskResult(decision=AskDecision.BLOCK)
        captured = {}

        def capture_dialog(violation_info, **kwargs):
            captured["start_column"] = violation_info.start_column
            return mock_result

        with patch("ai_guardian.tui.ask_dialog.show_ask_dialog", side_effect=capture_dialog):
            _handle_ask_mode(
                "ask", "secret_detected",
                matched_text="test", config_section="secret_scanning",
                error_msg="err", file_path="test.py",
                line_number=10, start_column=5,
            )
        self.assertEqual(captured.get("start_column"), 5)


if __name__ == "__main__":
    unittest.main()
