"""Tests for detect-secrets output parser."""

import json
import tempfile
import unittest
from pathlib import Path

from ai_guardian.scanners.output_parsers import DetectSecretsOutputParser


class TestDetectSecretsOutputParser(unittest.TestCase):
    """Test detect-secrets baseline JSON output parsing."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = DetectSecretsOutputParser()

    def test_parse_empty_results(self):
        """Test parsing detect-secrets output with no secrets."""
        baseline = {
            "results": {},
            "version": "1.0.0"
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(baseline, f)
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
        """Test parsing detect-secrets output with single finding."""
        baseline = {
            "results": {
                "test.txt": [
                    {
                        "type": "AWS Access Key",
                        "line_number": 5,
                        "hashed_secret": "abc123def456"
                    }
                ]
            },
            "version": "1.0.0"
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(baseline, f)
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])
            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(result["total_findings"], 1)

            # Check finding
            finding = result["findings"][0]
            self.assertEqual(finding["rule_id"], "aws-access-key")
            self.assertEqual(finding["file"], "test.txt")
            self.assertEqual(finding["line_number"], 5)
            self.assertEqual(finding["description"], "AWS Access Key detected")
        finally:
            Path(temp_file).unlink()

    def test_parse_multiple_files(self):
        """Test parsing detect-secrets output with multiple files."""
        baseline = {
            "results": {
                "test.txt": [
                    {
                        "type": "AWS Access Key",
                        "line_number": 5,
                        "hashed_secret": "abc123"
                    }
                ],
                "config.py": [
                    {
                        "type": "Secret Keyword",
                        "line_number": 10,
                        "hashed_secret": "def456"
                    }
                ]
            },
            "version": "1.0.0"
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(baseline, f)
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])
            self.assertEqual(len(result["findings"]), 2)
            self.assertEqual(result["total_findings"], 2)

            # Check files are different
            files = {f["file"] for f in result["findings"]}
            self.assertEqual(files, {"test.txt", "config.py"})
        finally:
            Path(temp_file).unlink()

    def test_parse_multiple_findings_same_file(self):
        """Test parsing multiple findings in the same file."""
        baseline = {
            "results": {
                "secrets.env": [
                    {
                        "type": "AWS Access Key",
                        "line_number": 1,
                        "hashed_secret": "aaa"
                    },
                    {
                        "type": "Basic Auth Credentials",
                        "line_number": 5,
                        "hashed_secret": "bbb"
                    },
                    {
                        "type": "Private Key",
                        "line_number": 10,
                        "hashed_secret": "ccc"
                    }
                ]
            },
            "version": "1.0.0"
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(baseline, f)
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])
            self.assertEqual(len(result["findings"]), 3)
            self.assertEqual(result["total_findings"], 3)

            # All should be from same file
            for finding in result["findings"]:
                self.assertEqual(finding["file"], "secrets.env")

            # Check line numbers
            line_numbers = sorted([f["line_number"] for f in result["findings"]])
            self.assertEqual(line_numbers, [1, 5, 10])
        finally:
            Path(temp_file).unlink()

    def test_rule_id_normalization(self):
        """Test that secret types are normalized to rule IDs."""
        baseline = {
            "results": {
                "test.txt": [
                    {
                        "type": "High Entropy String",
                        "line_number": 1,
                        "hashed_secret": "xyz"
                    }
                ]
            },
            "version": "1.0.0"
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(baseline, f)
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            # Spaces should be replaced with hyphens, lowercased
            self.assertEqual(result["findings"][0]["rule_id"], "high-entropy-string")
        finally:
            Path(temp_file).unlink()

    def test_parse_nonexistent_file(self):
        """Test parsing nonexistent file returns None."""
        result = self.parser.parse("/nonexistent/baseline.json")
        self.assertIsNone(result)

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON returns None."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json")
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)
            self.assertIsNone(result)
        finally:
            Path(temp_file).unlink()

    def test_parse_missing_type_field(self):
        """Test parsing finding with missing type field."""
        baseline = {
            "results": {
                "test.txt": [
                    {
                        "line_number": 5,
                        "hashed_secret": "abc"
                        # Missing "type" field
                    }
                ]
            },
            "version": "1.0.0"
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(baseline, f)
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            # Should still parse, using default values
            self.assertEqual(result["findings"][0]["rule_id"], "unknown")
            self.assertEqual(result["findings"][0]["description"], "unknown detected")
        finally:
            Path(temp_file).unlink()

    def test_parse_missing_line_number(self):
        """Test parsing finding with missing line number."""
        baseline = {
            "results": {
                "test.txt": [
                    {
                        "type": "AWS Access Key",
                        "hashed_secret": "abc"
                        # Missing "line_number" field
                    }
                ]
            },
            "version": "1.0.0"
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(baseline, f)
            temp_file = f.name

        try:
            result = self.parser.parse(temp_file)

            self.assertIsNotNone(result)
            # Should use default line number of 0
            self.assertEqual(result["findings"][0]["line_number"], 0)
        finally:
            Path(temp_file).unlink()


if __name__ == '__main__':
    unittest.main()
