"""Tests for 'config show --summary' consolidation (Issue #1329)."""

import json
import sys
from io import StringIO
from unittest import mock

import pytest


class TestConfigShowSummary:
    """Test that 'config show --summary' routes to ConfigInspector."""

    def _run_cli(self, argv):
        """Run CLI main() with given argv, return (exit_code, stdout, stderr)."""
        from ai_guardian.cli import main

        old_argv = sys.argv
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = StringIO()
        sys.stderr = StringIO()
        try:
            sys.argv = ["ai-guardian"] + argv
            try:
                exit_code = main()
            except SystemExit as e:
                exit_code = e.code
            return exit_code, sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def test_summary_shows_all_features(self):
        output = self._run_cli(["config", "show", "--summary"])
        assert output[0] == 0
        stdout = output[1]
        assert "SSRF Protection Configuration" in stdout
        assert "Secret Redaction Configuration" in stdout
        assert "Unicode Attack Detection Configuration" in stdout
        assert "Config File Scanner Configuration" in stdout

    def test_summary_feature_ssrf(self):
        output = self._run_cli(["config", "show", "--summary", "--feature", "ssrf"])
        assert output[0] == 0
        stdout = output[1]
        assert "SSRF Protection Configuration" in stdout
        assert "Secret Redaction Configuration" not in stdout

    def test_summary_feature_secrets(self):
        output = self._run_cli(["config", "show", "--summary", "--feature", "secrets"])
        assert output[0] == 0
        stdout = output[1]
        assert "Secret Redaction Configuration" in stdout
        assert "SSRF Protection Configuration" not in stdout

    def test_summary_feature_unicode(self):
        output = self._run_cli(["config", "show", "--summary", "--feature", "unicode"])
        assert output[0] == 0
        stdout = output[1]
        assert "Unicode Attack Detection Configuration" in stdout
        assert "SSRF Protection Configuration" not in stdout

    def test_summary_feature_config_scanner(self):
        output = self._run_cli(
            ["config", "show", "--summary", "--feature", "config-scanner"]
        )
        assert output[0] == 0
        stdout = output[1]
        assert "Config File Scanner Configuration" in stdout
        assert "SSRF Protection Configuration" not in stdout

    def test_summary_json(self):
        output = self._run_cli(["config", "show", "--summary", "--json"])
        assert output[0] == 0
        data = json.loads(output[1])
        assert "ssrf_protection" in data
        assert "secret_redaction" in data
        assert "unicode_detection" in data
        assert "config_file_scanning" in data

    def test_summary_show_sources(self):
        output = self._run_cli(
            ["config", "show", "--summary", "--show-sources", "--feature", "ssrf"]
        )
        assert output[0] == 0
        stdout = output[1]
        assert "IMMUTABLE" in stdout or "DEFAULT" in stdout

    def test_summary_with_config_file(self, tmp_path):
        config_file = tmp_path / "test-config.json"
        config_file.write_text(json.dumps({"ssrf_protection": {"enabled": False}}))
        output = self._run_cli(
            [
                "config",
                "show",
                "--summary",
                "--feature",
                "ssrf",
                "--config",
                str(config_file),
            ]
        )
        assert output[0] == 0
        assert "DISABLED" in output[1]

    def test_summary_config_file_not_found(self):
        output = self._run_cli(
            ["config", "show", "--summary", "--config", "/nonexistent/file.json"]
        )
        assert output[0] == 1
        assert "not found" in output[2]


class TestConfigShowDefault:
    """Test that 'config show' without --summary still works as before."""

    def _run_cli(self, argv):
        from ai_guardian.cli import main

        old_argv = sys.argv
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = StringIO()
        sys.stderr = StringIO()
        try:
            sys.argv = ["ai-guardian"] + argv
            try:
                exit_code = main()
            except SystemExit as e:
                exit_code = e.code
            return exit_code, sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def test_default_shows_merged_config(self):
        output = self._run_cli(["config", "show"])
        assert output[0] == 0
        assert "AI GUARDIAN CONFIGURATION" in output[1]

    def test_default_json(self):
        output = self._run_cli(["config", "show", "--json"])
        assert output[0] == 0
        data = json.loads(output[1])
        assert isinstance(data, dict)

    def test_config_file_flag(self, tmp_path):
        config_file = tmp_path / "test-config.json"
        config_file.write_text(
            json.dumps(
                {"permissions": {"rules": [{"tool": "Bash", "action": "allow"}]}}
            )
        )
        output = self._run_cli(["config", "show", "--config", str(config_file)])
        assert output[0] == 0
        assert "AI GUARDIAN CONFIGURATION" in output[1]

    def test_feature_without_summary_warns(self):
        output = self._run_cli(["config", "show", "--feature", "ssrf"])
        stderr = output[2]
        assert "--feature and --show-sources only apply with --summary" in stderr


class TestShowConfigDeprecation:
    """Test that show-config emits deprecation warning."""

    def _run_cli(self, argv):
        from ai_guardian.cli import main

        old_argv = sys.argv
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = StringIO()
        sys.stderr = StringIO()
        try:
            sys.argv = ["ai-guardian"] + argv
            try:
                exit_code = main()
            except SystemExit as e:
                exit_code = e.code
            return exit_code, sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def test_show_config_prints_deprecation(self):
        output = self._run_cli(["show-config"])
        assert output[0] == 0
        assert "deprecated" in output[2].lower()
        assert "config show --summary" in output[2]

    def test_show_config_still_works(self):
        output = self._run_cli(["show-config"])
        assert output[0] == 0
        assert "SSRF Protection Configuration" in output[1]

    def test_show_config_json_still_works(self):
        output = self._run_cli(["show-config", "--json"])
        assert output[0] == 0
        data = json.loads(output[1])
        assert "ssrf_protection" in data
