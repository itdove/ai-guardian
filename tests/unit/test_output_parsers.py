#!/usr/bin/env python3
"""
Tests for scanner output parsers.

Tests parsing of different scanner output formats.
"""

import json
import tempfile
import unittest
import sys
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_guardian.scanners.output_parsers import (
    GitleaksOutputParser,
    LeakTKOutputParser,
    get_parser,
    OUTPUT_PARSERS
)


class TestGitleaksOutputParser(unittest.TestCase):
    """Tests for Gitleaks output parser."""

    def test_parse_empty_findings(self):
        """Test parsing when no secrets are found."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([], f)
            output_file = f.name

        try:
            parser = GitleaksOutputParser()
            result = parser.parse(output_file)

            self.assertIsNotNone(result)
            self.assertFalse(result["has_secrets"])
            self.assertEqual(result["total_findings"], 0)
            self.assertEqual(len(result["findings"]), 0)
        finally:
            os.unlink(output_file)

    def test_parse_single_finding(self):
        """Test parsing single secret finding."""
        gitleaks_output = [
            {
                "RuleID": "aws-access-token",
                "File": "test.txt",
                "StartLine": 5,
                "EndLine": 5,
                "Description": "AWS Access Key",
                "Commit": "abc123"
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(gitleaks_output, f)
            output_file = f.name

        try:
            parser = GitleaksOutputParser()
            result = parser.parse(output_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])
            self.assertEqual(result["total_findings"], 1)
            self.assertEqual(len(result["findings"]), 1)

            finding = result["findings"][0]
            self.assertEqual(finding["rule_id"], "aws-access-token")
            self.assertEqual(finding["file"], "test.txt")
            self.assertEqual(finding["line_number"], 5)
            self.assertEqual(finding["description"], "AWS Access Key")
        finally:
            os.unlink(output_file)

    def test_parse_multiple_findings(self):
        """Test parsing multiple secret findings."""
        gitleaks_output = [
            {
                "RuleID": "aws-access-token",
                "File": "test1.txt",
                "StartLine": 5,
                "EndLine": 5,
                "Description": "AWS Access Key"
            },
            {
                "RuleID": "github-pat",
                "File": "test2.txt",
                "StartLine": 10,
                "EndLine": 10,
                "Description": "GitHub Personal Access Token"
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(gitleaks_output, f)
            output_file = f.name

        try:
            parser = GitleaksOutputParser()
            result = parser.parse(output_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])
            self.assertEqual(result["total_findings"], 2)
            self.assertEqual(len(result["findings"]), 2)
        finally:
            os.unlink(output_file)

    def test_parse_missing_fields(self):
        """Test parsing when some fields are missing."""
        gitleaks_output = [
            {
                "RuleID": "generic-api-key"
                # Missing File, StartLine, etc.
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(gitleaks_output, f)
            output_file = f.name

        try:
            parser = GitleaksOutputParser()
            result = parser.parse(output_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])
            finding = result["findings"][0]
            self.assertEqual(finding["rule_id"], "generic-api-key")
            self.assertEqual(finding["file"], "unknown")  # Default value
            self.assertEqual(finding["line_number"], 0)  # Default value
        finally:
            os.unlink(output_file)

    def test_parse_nonexistent_file(self):
        """Test parsing when output file doesn't exist."""
        parser = GitleaksOutputParser()
        result = parser.parse("/nonexistent/file.json")

        self.assertIsNone(result)

    def test_parse_invalid_json(self):
        """Test parsing when JSON is invalid."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json {")
            output_file = f.name

        try:
            parser = GitleaksOutputParser()
            result = parser.parse(output_file)

            self.assertIsNone(result)
        finally:
            os.unlink(output_file)


class TestLeakTKOutputParser(unittest.TestCase):
    """Tests for LeakTK output parser."""

    def test_parse_empty_findings(self):
        """Test parsing when no secrets are found."""
        leaktk_output = {
            "findings": [],
            "errors": []
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(leaktk_output, f)
            output_file = f.name

        try:
            parser = LeakTKOutputParser()
            result = parser.parse(output_file)

            self.assertIsNotNone(result)
            self.assertFalse(result["has_secrets"])
            self.assertEqual(result["total_findings"], 0)
            self.assertEqual(len(result["findings"]), 0)
        finally:
            os.unlink(output_file)

    def test_parse_single_finding(self):
        """Test parsing single secret finding."""
        leaktk_output = {
            "findings": [
                {
                    "RuleID": "aws-access-key",
                    "File": "config.txt",
                    "StartLine": 3,
                    "EndLine": 3,
                    "Description": "AWS Access Key ID"
                }
            ],
            "errors": []
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(leaktk_output, f)
            output_file = f.name

        try:
            parser = LeakTKOutputParser()
            result = parser.parse(output_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])
            self.assertEqual(result["total_findings"], 1)

            finding = result["findings"][0]
            self.assertEqual(finding["rule_id"], "aws-access-key")
            self.assertEqual(finding["file"], "config.txt")
            self.assertEqual(finding["line_number"], 3)
        finally:
            os.unlink(output_file)

    def test_parse_with_errors(self):
        """Test parsing when LeakTK reports errors."""
        leaktk_output = {
            "findings": [
                {
                    "RuleID": "test-secret",
                    "File": "test.txt",
                    "StartLine": 1,
                    "Description": "Test Secret"
                }
            ],
            "errors": [
                "Failed to scan file: permission denied",
                "Network timeout"
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(leaktk_output, f)
            output_file = f.name

        try:
            parser = LeakTKOutputParser()
            # Parser should still succeed and return findings
            result = parser.parse(output_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])
            self.assertEqual(result["total_findings"], 1)
        finally:
            os.unlink(output_file)

    def test_parse_multiple_findings(self):
        """Test parsing multiple findings."""
        leaktk_output = {
            "findings": [
                {
                    "RuleID": "secret-1",
                    "File": "file1.txt",
                    "StartLine": 1,
                    "Description": "Secret 1"
                },
                {
                    "RuleID": "secret-2",
                    "File": "file2.txt",
                    "StartLine": 5,
                    "Description": "Secret 2"
                },
                {
                    "RuleID": "secret-3",
                    "File": "file3.txt",
                    "StartLine": 10,
                    "Description": "Secret 3"
                }
            ],
            "errors": []
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(leaktk_output, f)
            output_file = f.name

        try:
            parser = LeakTKOutputParser()
            result = parser.parse(output_file)

            self.assertIsNotNone(result)
            self.assertTrue(result["has_secrets"])
            self.assertEqual(result["total_findings"], 3)
            self.assertEqual(len(result["findings"]), 3)
        finally:
            os.unlink(output_file)

    def test_parse_nonexistent_file(self):
        """Test parsing when output file doesn't exist."""
        parser = LeakTKOutputParser()
        result = parser.parse("/nonexistent/leaktk_output.json")

        self.assertIsNone(result)

    def test_parse_invalid_json(self):
        """Test parsing when JSON is invalid."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json")
            output_file = f.name

        try:
            parser = LeakTKOutputParser()
            result = parser.parse(output_file)

            self.assertIsNone(result)
        finally:
            os.unlink(output_file)


class TestParserRegistry(unittest.TestCase):
    """Tests for parser registry."""

    def test_get_gitleaks_parser(self):
        """Test getting gitleaks parser."""
        parser = get_parser("gitleaks")
        self.assertIsInstance(parser, GitleaksOutputParser)

    def test_get_leaktk_parser(self):
        """Test getting leaktk parser."""
        parser = get_parser("leaktk")
        self.assertIsInstance(parser, LeakTKOutputParser)

    def test_get_unknown_parser(self):
        """Test getting unknown parser raises ValueError."""
        with self.assertRaises(ValueError) as cm:
            get_parser("nonexistent")

        self.assertIn("Unknown parser", str(cm.exception))
        self.assertIn("nonexistent", str(cm.exception))

    def test_output_parsers_registry(self):
        """Test that OUTPUT_PARSERS contains expected parsers."""
        self.assertIn("gitleaks", OUTPUT_PARSERS)
        self.assertIn("leaktk", OUTPUT_PARSERS)
        self.assertIsInstance(OUTPUT_PARSERS["gitleaks"], GitleaksOutputParser)
        self.assertIsInstance(OUTPUT_PARSERS["leaktk"], LeakTKOutputParser)


class TestParserOutputFormat(unittest.TestCase):
    """Tests for standardized output format."""

    def test_gitleaks_output_format(self):
        """Test that Gitleaks parser returns standardized format."""
        gitleaks_output = [
            {
                "RuleID": "test",
                "File": "test.txt",
                "StartLine": 1,
                "EndLine": 1,
                "Description": "Test",
                "Commit": "abc"
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(gitleaks_output, f)
            output_file = f.name

        try:
            parser = GitleaksOutputParser()
            result = parser.parse(output_file)

            # Check standardized format
            self.assertIn("has_secrets", result)
            self.assertIn("findings", result)
            self.assertIn("total_findings", result)
            self.assertIsInstance(result["has_secrets"], bool)
            self.assertIsInstance(result["findings"], list)
            self.assertIsInstance(result["total_findings"], int)

            # Check finding format
            finding = result["findings"][0]
            self.assertIn("rule_id", finding)
            self.assertIn("file", finding)
            self.assertIn("line_number", finding)
            self.assertIn("description", finding)
        finally:
            os.unlink(output_file)

    def test_leaktk_output_format(self):
        """Test that LeakTK parser returns standardized format."""
        leaktk_output = {
            "findings": [
                {
                    "RuleID": "test",
                    "File": "test.txt",
                    "StartLine": 1,
                    "Description": "Test"
                }
            ],
            "errors": []
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(leaktk_output, f)
            output_file = f.name

        try:
            parser = LeakTKOutputParser()
            result = parser.parse(output_file)

            # Check standardized format (same as gitleaks)
            self.assertIn("has_secrets", result)
            self.assertIn("findings", result)
            self.assertIn("total_findings", result)

            # Check finding format (same as gitleaks)
            finding = result["findings"][0]
            self.assertIn("rule_id", finding)
            self.assertIn("file", finding)
            self.assertIn("line_number", finding)
            self.assertIn("description", finding)
        finally:
            os.unlink(output_file)


if __name__ == '__main__':
    unittest.main()
