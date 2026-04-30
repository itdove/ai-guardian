"""Tests for TruffleHog output parser."""

import json
import tempfile
import unittest
from pathlib import Path

from ai_guardian.scanners.output_parsers import TruffleHogOutputParser


class TestTruffleHogOutputParser(unittest.TestCase):
    """Test TruffleHog JSON output parsing."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = TruffleHogOutputParser()

    def test_parse_empty_output(self):
        """Test parsing empty TruffleHog output (no secrets)."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            # Empty file means no secrets found
            f.write("")
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            self.assertFalse(result["has_secrets"])
            self.assertEqual(len(result["findings"]), 0)
            self.assertEqual(result["total_findings"], 0)
        finally:
            Path(temp_file).unlink()

    def test_parse_single_finding(self):
        """Test parsing TruffleHog output with single finding."""
        finding = {
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "test.txt",
                        "line": 5
                    }
                }
            },
            "DetectorName": "AWS",
            "DetectorType": 2,
            "Verified": False
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json.dumps(finding) + "\n")
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])
            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(result["total_findings"], 1)

            # Check first finding
            finding_result = result["findings"][0]
            self.assertEqual(finding_result["rule_id"], "aws")
            self.assertEqual(finding_result["file"], "test.txt")
            self.assertEqual(finding_result["line_number"], 5)
            self.assertEqual(finding_result["description"], "AWS secret detected")
            self.assertFalse(finding_result["verified"])
        finally:
            Path(temp_file).unlink()

    def test_parse_multiple_findings(self):
        """Test parsing TruffleHog output with multiple findings."""
        findings = [
            {
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "file": "test.txt",
                            "line": 5
                        }
                    }
                },
                "DetectorName": "AWS",
                "DetectorType": 2,
                "Verified": False
            },
            {
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "file": "config.py",
                            "line": 10
                        }
                    }
                },
                "DetectorName": "GitHub",
                "DetectorType": 13,
                "Verified": True
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            for finding in findings:
                f.write(json.dumps(finding) + "\n")
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])
            self.assertEqual(len(result["findings"]), 2)
            self.assertEqual(result["total_findings"], 2)

            # Check first finding
            self.assertEqual(result["findings"][0]["rule_id"], "aws")
            self.assertEqual(result["findings"][0]["file"], "test.txt")
            self.assertFalse(result["findings"][0]["verified"])

            # Check second finding
            self.assertEqual(result["findings"][1]["rule_id"], "github")
            self.assertEqual(result["findings"][1]["file"], "config.py")
            self.assertTrue(result["findings"][1]["verified"])
        finally:
            Path(temp_file).unlink()

    def test_parse_verified_finding(self):
        """Test that verified findings are marked correctly."""
        finding = {
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "creds.txt",
                        "line": 1
                    }
                }
            },
            "DetectorName": "Stripe",
            "DetectorType": 42,
            "Verified": True
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json.dumps(finding) + "\n")
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])

            finding_result = result["findings"][0]
            self.assertTrue(finding_result["verified"])
            self.assertIn("verified", finding_result["description"].lower())
        finally:
            Path(temp_file).unlink()

    def test_parse_malformed_json_line(self):
        """Test that parser handles malformed JSON gracefully."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"valid": "json"}\n')
            f.write('invalid json line\n')  # Malformed
            f.write('{"SourceMetadata":{"Data":{"Filesystem":{"file":"test.txt","line":1}}},"DetectorName":"Test","Verified":false}\n')
            temp_file = f.name

        try:
            # Should skip malformed line but process valid ones
            result = self.parser.parse(temp_file)

            # Should still return a result (not crash)
            self.assertIsNotNone(result)
        finally:
            Path(temp_file).unlink()

    def test_parse_missing_source_metadata(self):
        """Test parsing finding with missing source metadata."""
        finding = {
            "DetectorName": "AWS",
            "DetectorType": 2,
            "Verified": False
            # Missing SourceMetadata
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json.dumps(finding) + "\n")
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            # Should still parse, using default values
            if result["has_secrets"]:
                self.assertEqual(result["findings"][0]["file"], "unknown")
                self.assertEqual(result["findings"][0]["line_number"], 0)
        finally:
            Path(temp_file).unlink()

    def test_parse_nonexistent_file(self):
        """Test parsing nonexistent file returns None."""
        result = self.parser.parse("/nonexistent/file.json")
        self.assertIsNone(result)

    def test_rule_id_normalization(self):
        """Test that detector names are normalized to rule IDs."""
        finding = {
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "test.txt",
                        "line": 1
                    }
                }
            },
            "DetectorName": "Generic API Key",
            "Verified": False
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json.dumps(finding) + "\n")
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            # Spaces should be replaced with hyphens, lowercased
            self.assertEqual(result["findings"][0]["rule_id"], "generic-api-key")
        finally:
            Path(temp_file).unlink()


if __name__ == '__main__':
    unittest.main()
