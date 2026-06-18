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


if __name__ == "__main__":
    unittest.main()
