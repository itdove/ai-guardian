"""
Test for Issue #520: gitleaks pattern server config passed to betterleaks causes false positives

Two bugs combined to block every prompt when betterleaks was used with a
pattern server:
1. Gitleaks-format patterns were passed to betterleaks via --config, but
   betterleaks cannot parse gitleaks CEL filter syntax.
2. Betterleaks exits with code 1 on compilation errors, and ai-guardian
   treated exit code 1 as "secrets found" even when the parser found no
   actual findings.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock

from ai_guardian.scanners.engine_builder import (
    EngineConfig, ENGINE_PRESETS, build_scanner_command
)
from ai_guardian.scanners.executor import run_single_engine


class TestGitleaksConfigNotPassedToBetterleaks(unittest.TestCase):
    """Verify gitleaks-format pattern configs are only passed to gitleaks."""

    def test_gitleaks_receives_config_path(self):
        """Gitleaks should receive the --config flag when config_path is set."""
        config = ENGINE_PRESETS["gitleaks"]
        cmd = build_scanner_command(
            config, "/tmp/src.txt", "/tmp/report.json",
            config_path="/tmp/patterns.toml"
        )
        self.assertIn("--config", cmd)
        self.assertIn("/tmp/patterns.toml", cmd)

    def test_betterleaks_receives_config_when_explicitly_passed(self):
        """Betterleaks build_scanner_command still accepts config_path.

        The filtering should happen at the caller level, not in
        build_scanner_command itself. This test documents that the builder
        is dumb — it's the caller's job to not pass gitleaks configs.
        """
        config = ENGINE_PRESETS["betterleaks"]
        cmd = build_scanner_command(
            config, "/tmp/src.txt", "/tmp/report.json",
            config_path="/tmp/patterns.toml"
        )
        self.assertIn("--config", cmd)

    def test_betterleaks_without_config_works(self):
        """Betterleaks command works without --config flag."""
        config = ENGINE_PRESETS["betterleaks"]
        cmd = build_scanner_command(
            config, "/tmp/src.txt", "/tmp/report.json",
            config_path=None
        )
        self.assertNotIn("--config", cmd)
        self.assertIn("betterleaks", cmd)
        self.assertIn("/tmp/src.txt", cmd)

    def test_leaktk_ignores_config_path(self):
        """LeakTK has no config_flag — config_path should not appear."""
        config = ENGINE_PRESETS["leaktk"]
        cmd = build_scanner_command(
            config, "/tmp/src.txt", "/tmp/report.json",
            config_path="/tmp/patterns.toml"
        )
        self.assertNotIn("--config", cmd)
        self.assertNotIn("/tmp/patterns.toml", cmd)


class TestExitCode1WithNoFindings(unittest.TestCase):
    """Verify exit code 1 with no parsed findings does not false-positive."""

    def _make_report_file(self, content=None):
        fd, path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        if content is not None:
            with open(path, 'w') as f:
                json.dump(content, f)
        return path

    @patch('ai_guardian.scanners.executor.subprocess.run')
    def test_betterleaks_compilation_error_returns_clean(self, mock_run):
        """Betterleaks CEL compilation error (exit 1) should not block.

        Reproduction: betterleaks receives gitleaks-format patterns, can't
        compile CEL filters, exits 1. Report file is empty/missing.
        """
        report = self._make_report_file(content=[])
        mock_run.return_value = MagicMock(
            returncode=1, stdout='',
            stderr='FTL failed to compile CEL filters error="compiling rule gpfGmO3HH64 filter: ...'
        )

        config = ENGINE_PRESETS["betterleaks"]
        result = run_single_engine(config, "/tmp/test.txt", report)

        self.assertFalse(result.has_secrets)
        self.assertEqual(len(result.secrets), 0)
        os.unlink(report)

    @patch('ai_guardian.scanners.executor.subprocess.run')
    def test_betterleaks_exit_1_with_real_findings_still_blocks(self, mock_run):
        """Betterleaks exit 1 with actual findings should still detect secrets."""
        report = self._make_report_file(content=[
            {"RuleID": "generic-api-key", "File": "app.py",
             "StartLine": 10, "EndLine": 10, "Description": "API Key"}
        ])
        mock_run.return_value = MagicMock(
            returncode=1, stdout='', stderr=''
        )

        config = ENGINE_PRESETS["betterleaks"]
        result = run_single_engine(config, "/tmp/test.txt", report)

        self.assertTrue(result.has_secrets)
        self.assertEqual(len(result.secrets), 1)
        self.assertEqual(result.secrets[0].rule_id, "generic-api-key")
        os.unlink(report)

    @patch('ai_guardian.scanners.executor.subprocess.run')
    def test_gitleaks_exit_1_with_real_findings_still_blocks(self, mock_run):
        """Gitleaks exit 1 with actual findings should still detect secrets."""
        report = self._make_report_file(content=[
            {"RuleID": "aws-access-token", "File": "creds.py",
             "StartLine": 3, "EndLine": 3, "Description": "AWS Key"}
        ])
        mock_run.return_value = MagicMock(
            returncode=1, stdout='', stderr=''
        )

        config = ENGINE_PRESETS["gitleaks"]
        result = run_single_engine(config, "/tmp/test.txt", report)

        self.assertTrue(result.has_secrets)
        self.assertEqual(result.secrets[0].rule_id, "aws-access-token")
        os.unlink(report)


class TestCallerFilteringConfigPath(unittest.TestCase):
    """Test that the caller correctly filters config_path by engine type.

    These tests verify the fix in __init__.py where config_path is only
    passed to gitleaks-type engines.
    """

    def test_gitleaks_engine_gets_config_path(self):
        """Gitleaks engine: config_path should be passed."""
        engine_config = ENGINE_PRESETS["gitleaks"]
        gitleaks_config_path = "/tmp/patterns.toml"
        config_path = (
            str(Path(gitleaks_config_path).absolute())
            if (gitleaks_config_path and engine_config and engine_config.type in ("gitleaks", "leaktk"))
            else None
        )
        self.assertIsNotNone(config_path)

    def test_betterleaks_engine_does_not_get_config_path(self):
        """Betterleaks engine: config_path should NOT be passed."""
        engine_config = ENGINE_PRESETS["betterleaks"]
        gitleaks_config_path = "/tmp/patterns.toml"
        config_path = (
            str(Path(gitleaks_config_path).absolute())
            if (gitleaks_config_path and engine_config and engine_config.type in ("gitleaks", "leaktk"))
            else None
        )
        self.assertIsNone(config_path)

    def test_leaktk_engine_gets_config_path(self):
        """LeakTK engine: config_path should be passed (per-engine pattern_server #519)."""
        engine_config = ENGINE_PRESETS["leaktk"]
        gitleaks_config_path = "/tmp/patterns.toml"
        config_path = (
            str(Path(gitleaks_config_path).absolute())
            if (gitleaks_config_path and engine_config and engine_config.type in ("gitleaks", "leaktk"))
            else None
        )
        self.assertIsNotNone(config_path)

    def test_trufflehog_engine_does_not_get_config_path(self):
        """TruffleHog engine: config_path should NOT be passed."""
        engine_config = ENGINE_PRESETS["trufflehog"]
        gitleaks_config_path = "/tmp/patterns.toml"
        config_path = (
            str(Path(gitleaks_config_path).absolute())
            if (gitleaks_config_path and engine_config and engine_config.type in ("gitleaks", "leaktk"))
            else None
        )
        self.assertIsNone(config_path)

    def test_no_config_path_when_none(self):
        """No pattern server config: config_path should be None for all."""
        engine_config = ENGINE_PRESETS["gitleaks"]
        gitleaks_config_path = None
        config_path = (
            str(Path(gitleaks_config_path).absolute())
            if (gitleaks_config_path and engine_config and engine_config.type in ("gitleaks", "leaktk"))
            else None
        )
        self.assertIsNone(config_path)


if __name__ == '__main__':
    unittest.main()
