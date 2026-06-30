"""Tests for base64 secret path false positive filter (Issue #1410)."""

from ai_guardian.patterns.validators import base64_not_file_path
from ai_guardian.scanners.toml_patterns import TomlPatternsScanner


class TestBase64NotFilePath:
    def test_unix_absolute_path_suppressed(self):
        assert not base64_not_file_path(
            "key /Users/dvernier/development/ai/aiguardian/some/path/to/config"
        )

    def test_unix_path_with_tilde_style(self):
        assert not base64_not_file_path(
            "key /home/user/projects/devflow/config/settings/default"
        )

    def test_windows_path_suppressed(self):
        assert not base64_not_file_path(
            "key C:\\Users\\dev\\projects\\something\\very\\long\\path\\here\\now"
        )

    def test_relative_path_suppressed(self):
        assert not base64_not_file_path(
            "key ./src/ai_guardian/patterns/data/secrets/toml/rules/config"
        )

    def test_dotdot_path_suppressed(self):
        assert not base64_not_file_path(
            "key ../some/other/project/with/many/nested/directories/here"
        )

    def test_real_base64_secret_passes(self):
        assert base64_not_file_path("key ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop")

    def test_real_base64_with_padding_passes(self):
        assert base64_not_file_path(
            "token=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop=="
        )

    def test_quoted_secret_passes(self):
        assert base64_not_file_path(
            'secret "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"'
        )

    def test_context_with_equals(self):
        assert not base64_not_file_path(
            "credential=/opt/application/config/keys/production/default/active"
        )

    def test_context_with_colon(self):
        assert not base64_not_file_path(
            "password: /var/lib/application/secrets/storage/path/default"
        )

    def test_empty_value_passes(self):
        assert base64_not_file_path("key ")

    def test_no_context_prefix_file_path(self):
        assert not base64_not_file_path(
            "/Users/dvernier/development/ai/aiguardian/some/path/to/config"
        )

    def test_no_context_prefix_base64(self):
        assert base64_not_file_path("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop")

    def test_case_insensitive_keyword(self):
        assert not base64_not_file_path(
            "KEY /Users/dvernier/development/ai/aiguardian/some/path/to/config"
        )


class TestBase64PathScannerIntegration:
    def test_file_path_not_flagged_as_secret(self):
        scanner = TomlPatternsScanner()
        content = "key /Users/dvernier/development/ai/aiguardian/some/path/to/config"
        findings = scanner.scan(content)
        base64_findings = [
            f for f in findings if f.rule_id == "base64-secret-with-context"
        ]
        assert len(base64_findings) == 0

    def test_real_base64_still_detected(self):
        scanner = TomlPatternsScanner()
        content = "key ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"
        findings = scanner.scan(content)
        base64_findings = [
            f for f in findings if f.rule_id == "base64-secret-with-context"
        ]
        assert len(base64_findings) == 1

    def test_path_with_key_keyword_in_output(self):
        scanner = TomlPatternsScanner()
        content = "key /Users/someone/projects/devflow/settings/configuration"
        findings = scanner.scan(content)
        base64_findings = [
            f for f in findings if f.rule_id == "base64-secret-with-context"
        ]
        assert len(base64_findings) == 0
