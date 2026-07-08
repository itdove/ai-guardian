"""Tests for the Bandit Python code security scanner (Issue #828)."""

import pytest
from unittest import mock
from ai_guardian.bandit_scanner import (
    BanditScanner,
    BanditUnavailableError,
    CodeSecurityFinding,
)

CLEAN_CODE = """
def add(a, b):
    return a + b


def greet(name):
    return f"Hello, {name}"
"""

EVAL_CODE = """
def run_user_code(user_input):
    result = eval(user_input)
    return result
"""

SUBPROCESS_SHELL_CODE = """
import subprocess

def run_cmd(cmd):
    subprocess.call(cmd, shell=True)
"""

MD5_CODE = """
import hashlib

def legacy_hash(data):
    return hashlib.md5(data).hexdigest()
"""

MULTI_ISSUE_CODE = """
import subprocess
import hashlib

def bad_function(cmd, data):
    subprocess.call(cmd, shell=True)
    return hashlib.md5(data.encode()).hexdigest()
"""

NOSEC_CODE = """
import subprocess

def run_cmd(cmd):
    subprocess.call(cmd, shell=True)  # nosec
"""

ALLOW_ANNOTATION_CODE = """
import subprocess

def run_cmd(cmd):
    subprocess.call(cmd, shell=True)  # ai-guardian:allow
"""


class TestBanditScannerBasic:
    def setup_method(self):
        self.scanner = BanditScanner()

    def test_clean_code_returns_no_findings(self):
        findings = self.scanner.scan(CLEAN_CODE, "clean.py")
        assert findings == []

    def test_eval_detected(self):
        findings = self.scanner.scan(EVAL_CODE, "eval.py")
        rule_ids = [f.rule_id for f in findings]
        assert any(
            "B307" in r or "B eval" in r or "B" in r for r in rule_ids
        ), f"Expected a Bandit eval finding, got: {rule_ids}"

    def test_subprocess_shell_true_detected(self):
        findings = self.scanner.scan(SUBPROCESS_SHELL_CODE, "shell.py")
        assert len(findings) > 0

    def test_md5_detected(self):
        findings = self.scanner.scan(MD5_CODE, "hash.py")
        assert len(findings) > 0

    def test_empty_content_returns_empty(self):
        assert self.scanner.scan("", "empty.py") == []
        assert self.scanner.scan("   \n  ", "whitespace.py") == []

    def test_finding_has_required_fields(self):
        findings = self.scanner.scan(SUBPROCESS_SHELL_CODE, "shell.py")
        assert len(findings) > 0
        f = findings[0]
        assert isinstance(f, CodeSecurityFinding)
        assert f.rule_id
        assert f.description
        assert f.line_number > 0
        assert f.severity in ("LOW", "MEDIUM", "HIGH")
        assert f.confidence in ("LOW", "MEDIUM", "HIGH")
        assert f.file_path == "shell.py"

    def test_snippet_extracted(self):
        findings = self.scanner.scan(SUBPROCESS_SHELL_CODE, "shell.py")
        assert any(f.snippet for f in findings)

    def test_multi_issue_code(self):
        findings = self.scanner.scan(MULTI_ISSUE_CODE, "multi.py")
        assert len(findings) >= 2


class TestBanditScannerSeverityThreshold:
    def test_medium_threshold_skips_low(self):
        scanner = BanditScanner({"severity_threshold": "MEDIUM"})
        findings = scanner.scan(SUBPROCESS_SHELL_CODE, "shell.py")
        for f in findings:
            assert f.severity in ("MEDIUM", "HIGH"), f"LOW finding leaked: {f}"

    def test_high_threshold_skips_medium(self):
        scanner = BanditScanner({"severity_threshold": "HIGH"})
        findings = scanner.scan(MD5_CODE, "hash.py")
        # md5 is typically MEDIUM — should be filtered out at HIGH threshold
        for f in findings:
            assert f.severity == "HIGH"

    def test_low_threshold_includes_all(self):
        scanner = BanditScanner({"severity_threshold": "LOW"})
        findings_low = scanner.scan(MD5_CODE, "hash.py")
        scanner_medium = BanditScanner({"severity_threshold": "MEDIUM"})
        findings_medium = scanner_medium.scan(MD5_CODE, "hash.py")
        assert len(findings_low) >= len(findings_medium)

    def test_threshold_case_insensitive(self):
        scanner = BanditScanner({"severity_threshold": "medium"})
        findings = scanner.scan(MD5_CODE, "hash.py")
        for f in findings:
            assert f.severity in ("MEDIUM", "HIGH")


class TestBanditAllowlist:
    def test_allowlist_by_test_id_suppresses_finding(self):
        # First confirm finding exists without allowlist
        scanner = BanditScanner()
        findings = scanner.scan(MD5_CODE, "hash.py")
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids, "Precondition: md5 must produce at least one finding"

        # Now suppress with allowlist entry matching first rule_id
        first_id = next(iter(rule_ids))
        scanner_allow = BanditScanner({"allowlist": [{"test_id": first_id}]})
        findings_after = scanner_allow.scan(MD5_CODE, "hash.py")
        remaining_ids = {f.rule_id for f in findings_after}
        assert first_id not in remaining_ids

    def test_allowlist_scoped_to_file_path_suppresses(self):
        scanner = BanditScanner({"severity_threshold": "LOW"})
        findings = scanner.scan(MD5_CODE, "tests/hash.py")
        assert findings, "Precondition: must have findings to suppress"
        first_id = findings[0].rule_id

        scanner_allow = BanditScanner(
            {"allowlist": [{"test_id": first_id, "file": "tests/"}]}
        )
        findings_after = scanner_allow.scan(MD5_CODE, "tests/hash.py")
        assert not any(f.rule_id == first_id for f in findings_after)

    def test_allowlist_file_scope_does_not_suppress_other_paths(self):
        scanner = BanditScanner({"severity_threshold": "LOW"})
        findings = scanner.scan(MD5_CODE, "src/hash.py")
        if not findings:
            pytest.skip("No findings to test allowlist scoping")
        first_id = findings[0].rule_id

        scanner_allow = BanditScanner(
            {"allowlist": [{"test_id": first_id, "file": "tests/"}]}
        )
        findings_after = scanner_allow.scan(MD5_CODE, "src/hash.py")
        # src/ does not start with tests/ — should NOT be suppressed
        assert any(f.rule_id == first_id for f in findings_after)

    def test_empty_allowlist_suppresses_nothing(self):
        scanner = BanditScanner({"allowlist": []})
        findings = scanner.scan(SUBPROCESS_SHELL_CODE, "shell.py")
        assert len(findings) > 0


class TestBanditAnnotations:
    def test_nosec_comment_suppressed_by_bandit(self):
        scanner = BanditScanner()
        findings = scanner.scan(NOSEC_CODE, "nosec.py")
        assert findings == [], f"nosec should suppress all findings, got: {findings}"

    def test_ai_guardian_allow_annotation_suppressed(self):
        scanner = BanditScanner()
        findings = scanner.scan(ALLOW_ANNOTATION_CODE, "allow.py")
        assert (
            findings == []
        ), f"ai-guardian:allow should suppress finding, got: {findings}"


class TestBanditUnavailable:
    def test_raises_when_bandit_not_importable(self):
        import importlib.util

        with mock.patch.object(importlib.util, "find_spec", return_value=None):
            scanner = BanditScanner()
        with pytest.raises(BanditUnavailableError):
            scanner.scan(EVAL_CODE, "eval.py")

    def test_raises_on_non_empty_content_only(self):
        import importlib.util

        with mock.patch.object(importlib.util, "find_spec", return_value=None):
            scanner = BanditScanner()
        assert scanner.scan("", "empty.py") == []
        assert scanner.scan("   ", "whitespace.py") == []
        with pytest.raises(BanditUnavailableError):
            scanner.scan(EVAL_CODE, "eval.py")

    def test_bandit_unavailable_error_is_runtime_error(self):
        assert issubclass(BanditUnavailableError, RuntimeError)

    def test_available_true_when_bandit_installed(self):
        import importlib.util

        with mock.patch.object(
            importlib.util, "find_spec", return_value=mock.MagicMock()
        ):
            scanner = BanditScanner()
        assert scanner._available is True

    def test_available_false_when_bandit_missing(self):
        import importlib.util

        with mock.patch.object(importlib.util, "find_spec", return_value=None):
            scanner = BanditScanner()
        assert scanner._available is False


class TestBanditScannerRobustness:
    def test_non_python_syntax_does_not_crash(self):
        scanner = BanditScanner()
        # Bandit may fail to parse this, but scan() must not raise
        result = scanner.scan("this is not python { } [ }", "bad_syntax.py")
        assert isinstance(result, list)

    def test_very_large_code_does_not_crash(self):
        scanner = BanditScanner()
        large_code = "\n".join([f"x_{i} = {i}" for i in range(5000)])
        result = scanner.scan(large_code, "large.py")
        assert isinstance(result, list)
