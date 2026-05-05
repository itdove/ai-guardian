"""Tests for Secretlint output parser."""

import json
import os
import tempfile
import unittest

from ai_guardian.scanners.output_parsers import SecretlintOutputParser


class TestSecretlintOutputParser(unittest.TestCase):

    def setUp(self):
        self.parser = SecretlintOutputParser()

    def _write_output(self, data):
        fd, path = tempfile.mkstemp(suffix=".json")
        if isinstance(data, str):
            os.write(fd, data.encode("utf-8"))
        else:
            os.write(fd, json.dumps(data).encode("utf-8"))
        os.close(fd)
        return path

    def test_parse_empty_output(self):
        path = self._write_output("[]")
        result = self.parser.parse(path)
        self.assertIsNotNone(result)
        self.assertFalse(result["has_secrets"])
        self.assertEqual(result["total_findings"], 0)
        os.unlink(path)

    def test_parse_single_finding(self):
        data = [
            {
                "filePath": "/tmp/test.py",
                "messages": [
                    {
                        "ruleId": "@secretlint/secretlint-rule-preset-recommend > @secretlint/secretlint-rule-aws",
                        "message": "Found AWS Access Key ID",
                        "loc": {
                            "start": {"line": 3, "column": 0},
                            "end": {"line": 3, "column": 42},
                        },
                        "severity": "error",
                    }
                ],
            }
        ]
        path = self._write_output(data)
        result = self.parser.parse(path)
        self.assertTrue(result["has_secrets"])
        self.assertEqual(result["total_findings"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "aws")
        self.assertEqual(finding["file"], "/tmp/test.py")
        self.assertEqual(finding["line_number"], 3)
        os.unlink(path)

    def test_parse_multiple_findings(self):
        data = [
            {
                "filePath": "/tmp/a.py",
                "messages": [
                    {
                        "ruleId": "@secretlint/secretlint-rule-aws",
                        "message": "AWS key",
                        "loc": {"start": {"line": 1, "column": 0}, "end": {"line": 1, "column": 20}},
                        "severity": "error",
                    }
                ],
            },
            {
                "filePath": "/tmp/b.py",
                "messages": [
                    {
                        "ruleId": "@secretlint/secretlint-rule-github",
                        "message": "GitHub token",
                        "loc": {"start": {"line": 5, "column": 0}, "end": {"line": 5, "column": 40}},
                        "severity": "error",
                    }
                ],
            },
        ]
        path = self._write_output(data)
        result = self.parser.parse(path)
        self.assertTrue(result["has_secrets"])
        self.assertEqual(result["total_findings"], 2)
        os.unlink(path)

    def test_parse_newline_delimited(self):
        lines = [
            json.dumps({
                "filePath": "/tmp/test.py",
                "messages": [
                    {
                        "ruleId": "rule-aws",
                        "message": "AWS key",
                        "loc": {"start": {"line": 1, "column": 0}, "end": {"line": 1, "column": 20}},
                        "severity": "error",
                    }
                ],
            }),
            json.dumps({
                "filePath": "/tmp/test2.py",
                "messages": [],
            }),
        ]
        path = self._write_output("\n".join(lines))
        result = self.parser.parse(path)
        self.assertTrue(result["has_secrets"])
        self.assertEqual(result["total_findings"], 1)
        os.unlink(path)

    def test_rule_id_normalization(self):
        self.assertEqual(
            SecretlintOutputParser._normalize_rule_id(
                "@secretlint/secretlint-rule-preset-recommend > @secretlint/secretlint-rule-aws"
            ),
            "aws",
        )
        self.assertEqual(
            SecretlintOutputParser._normalize_rule_id("@secretlint/secretlint-rule-github"),
            "github",
        )
        self.assertEqual(
            SecretlintOutputParser._normalize_rule_id("custom-rule"),
            "custom-rule",
        )

    def test_parse_nonexistent_file(self):
        result = self.parser.parse("/nonexistent/file.json")
        self.assertIsNone(result)

    def test_parse_invalid_json(self):
        path = self._write_output("not valid json {{{")
        result = self.parser.parse(path)
        self.assertIsNone(result)
        os.unlink(path)

    def test_parse_no_messages(self):
        data = [{"filePath": "/tmp/test.py", "messages": []}]
        path = self._write_output(data)
        result = self.parser.parse(path)
        self.assertFalse(result["has_secrets"])
        os.unlink(path)


if __name__ == "__main__":
    unittest.main()
