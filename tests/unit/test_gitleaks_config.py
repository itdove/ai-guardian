"""Tests for .gitleaks.toml allowlist support (Issue #488)."""

import os
import re
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from ai_guardian.scanners.gitleaks import (
    find_project_root,
    load_gitleaks_allowlist,
    should_skip_file,
    filter_findings,
    GitleaksAllowlist,
    RuleAllowlist,
    reset_cache,
)


@pytest.fixture(autouse=True)
def _clean_cache():
    """Reset module caches between tests."""
    reset_cache()
    yield
    reset_cache()


# ---------------------------------------------------------------------------
# find_project_root
# ---------------------------------------------------------------------------


class TestFindProjectRoot:
    def test_finds_git_root(self):
        with patch("ai_guardian.scanners.gitleaks.subprocess.check_output") as mock:
            mock.return_value = b"/home/user/project\n"
            root = find_project_root()
            assert root == Path("/home/user/project")

    def test_fallback_to_cwd_when_not_git_repo(self):
        import subprocess as sp

        with patch(
            "ai_guardian.scanners.gitleaks.subprocess.check_output",
            side_effect=sp.CalledProcessError(128, "git"),
        ):
            root = find_project_root()
            assert root == Path(os.getcwd())

    def test_fallback_to_cwd_when_git_not_installed(self):
        with patch(
            "ai_guardian.scanners.gitleaks.subprocess.check_output",
            side_effect=FileNotFoundError,
        ):
            root = find_project_root()
            assert root == Path(os.getcwd())

    def test_caches_result(self):
        with patch("ai_guardian.scanners.gitleaks.subprocess.check_output") as mock:
            mock.return_value = b"/cached/root\n"
            first = find_project_root()
            second = find_project_root()
            assert first == second
            assert mock.call_count == 1


# ---------------------------------------------------------------------------
# load_gitleaks_allowlist
# ---------------------------------------------------------------------------


class TestLoadGitleaksAllowlist:
    def test_returns_none_when_file_missing(self, tmp_path):
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is None

    def test_parses_global_paths(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text(textwrap.dedent("""\
            [allowlist]
                paths = ["tests/unit/test_foo.py", "tests/fixtures/**"]
        """))
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is not None
        assert len(result.paths) == 2
        assert "tests/unit/test_foo.py" in result.paths

    def test_parses_global_regexes(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text(textwrap.dedent("""\
            [allowlist]
                regexes = ["test_key_.*", "example_token_\\\\d+"]
        """))
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is not None
        assert len(result.regexes) == 2
        assert all(isinstance(r, re.Pattern) for r in result.regexes)

    def test_parses_global_stopwords(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text(textwrap.dedent("""\
            [allowlist]
                stopwords = ["test_value", "example", "fake"]
        """))
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is not None
        assert len(result.stopwords) == 3
        assert "test_value" in result.stopwords

    def test_short_stopwords_ignored(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text(textwrap.dedent("""\
            [allowlist]
                stopwords = ["ok", "a", "valid_word"]
        """))
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is not None
        assert len(result.stopwords) == 1
        assert result.stopwords[0] == "valid_word"

    def test_parses_per_rule_allowlist(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text(textwrap.dedent("""\
            [[rules]]
            id = "generic-api-key"
            description = "Generic API Key"
            [rules.allowlist]
                regexes = ["fake_key_.*"]
                paths = ["tests/**"]
                stopwords = ["test_only"]
        """))
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is not None
        assert "generic-api-key" in result.rule_allowlists
        ral = result.rule_allowlists["generic-api-key"]
        assert len(ral.regexes) == 1
        assert len(ral.paths) == 1
        assert len(ral.stopwords) == 1

    def test_rules_without_allowlist_ignored(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text(textwrap.dedent("""\
            [[rules]]
            id = "some-rule"
            description = "No allowlist here"
        """))
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is not None
        assert len(result.rule_allowlists) == 0

    def test_invalid_regex_skipped_gracefully(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text(textwrap.dedent("""\
            [allowlist]
                regexes = ["[invalid", "valid_pattern"]
        """))
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is not None
        assert len(result.regexes) == 1

    def test_dangerous_regex_blocked(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text(textwrap.dedent("""\
            [allowlist]
                regexes = [".*", "safe_pattern"]
        """))
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is not None
        assert len(result.regexes) == 1

    def test_empty_allowlist_section(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text("[allowlist]\n")
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is not None
        assert result.paths == []
        assert result.regexes == []
        assert result.stopwords == []

    def test_no_allowlist_section(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text("# empty config\n")
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is not None
        assert result.paths == []

    def test_caching_by_mtime(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text('[allowlist]\n    paths = ["a.py"]\n')
        first = load_gitleaks_allowlist(project_root=tmp_path)
        second = load_gitleaks_allowlist(project_root=tmp_path)
        assert first is second

    def test_cache_invalidation_on_mtime_change(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text('[allowlist]\n    paths = ["a.py"]\n')
        first = load_gitleaks_allowlist(project_root=tmp_path)
        # Touch file to change mtime
        import time

        time.sleep(0.05)
        toml_path.write_text('[allowlist]\n    paths = ["b.py"]\n')
        reset_cache()  # Clear project root cache
        second = load_gitleaks_allowlist(project_root=tmp_path)
        assert first is not second
        assert "b.py" in second.paths

    def test_handles_malformed_toml(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text("this is not valid [toml {{{")
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is None

    def test_paths_with_dotdot_blocked(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text(textwrap.dedent("""\
            [allowlist]
                paths = ["../escape.py", "safe/path.py"]
        """))
        result = load_gitleaks_allowlist(project_root=tmp_path)
        assert result is not None
        assert len(result.paths) == 1
        assert result.paths[0] == "safe/path.py"


# ---------------------------------------------------------------------------
# should_skip_file
# ---------------------------------------------------------------------------


class TestShouldSkipFile:
    def test_exact_path_match(self):
        al = GitleaksAllowlist(paths=["tests/unit/test_foo.py"])
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            with patch(
                "ai_guardian.scanners.gitleaks._normalize_path",
                return_value="tests/unit/test_foo.py",
            ):
                assert should_skip_file("/project/tests/unit/test_foo.py", al) is True

    def test_glob_pattern(self):
        al = GitleaksAllowlist(paths=["tests/fixtures/*"])
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            with patch(
                "ai_guardian.scanners.gitleaks._normalize_path",
                return_value="tests/fixtures/secrets.py",
            ):
                assert (
                    should_skip_file("/project/tests/fixtures/secrets.py", al) is True
                )

    def test_no_match(self):
        al = GitleaksAllowlist(paths=["tests/unit/test_foo.py"])
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            with patch(
                "ai_guardian.scanners.gitleaks._normalize_path",
                return_value="src/main.py",
            ):
                assert should_skip_file("/project/src/main.py", al) is False

    def test_empty_paths(self):
        al = GitleaksAllowlist(paths=[])
        assert should_skip_file("/any/path.py", al) is False

    def test_doublestar_pattern(self):
        al = GitleaksAllowlist(paths=["**/fixtures/**"])
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            with patch(
                "ai_guardian.scanners.gitleaks._normalize_path",
                return_value="tests/fixtures/data.json",
            ):
                assert should_skip_file("/project/tests/fixtures/data.json", al) is True


# ---------------------------------------------------------------------------
# filter_findings
# ---------------------------------------------------------------------------


class TestFilterFindings:
    def _make_finding(self, rule_id="generic-api-key", line_number=1, file="test.py"):
        return {"rule_id": rule_id, "line_number": line_number, "file": file}

    def test_suppresses_by_global_regex(self):
        al = GitleaksAllowlist(regexes=[re.compile(r"fake_key_\d+", re.IGNORECASE)])
        findings = [self._make_finding(line_number=1)]
        content_lines = ["token = fake_key_12345"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            result = filter_findings(findings, content_lines, None, al)
        assert len(result) == 0

    def test_suppresses_by_global_stopword(self):
        al = GitleaksAllowlist(stopwords=["fake_value"])
        findings = [self._make_finding(line_number=1)]
        content_lines = ["api_key = FAKE_VALUE_here"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            result = filter_findings(findings, content_lines, None, al)
        assert len(result) == 0

    def test_suppresses_by_global_path(self):
        al = GitleaksAllowlist(paths=["tests/*"])
        findings = [self._make_finding(line_number=1)]
        content_lines = ["secret = real_secret"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            with patch(
                "ai_guardian.scanners.gitleaks._normalize_path",
                return_value="tests/test_foo.py",
            ):
                result = filter_findings(
                    findings, content_lines, "/project/tests/test_foo.py", al
                )
        assert len(result) == 0

    def test_suppresses_by_per_rule_regex(self):
        ral = RuleAllowlist(regexes=[re.compile(r"test_token_.*", re.IGNORECASE)])
        al = GitleaksAllowlist(rule_allowlists={"generic-api-key": ral})
        findings = [self._make_finding(rule_id="generic-api-key", line_number=1)]
        content_lines = ["key = test_token_abc123"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            result = filter_findings(findings, content_lines, None, al)
        assert len(result) == 0

    def test_per_rule_does_not_affect_other_rules(self):
        ral = RuleAllowlist(regexes=[re.compile(r"test_token_.*", re.IGNORECASE)])
        al = GitleaksAllowlist(rule_allowlists={"generic-api-key": ral})
        findings = [self._make_finding(rule_id="aws-access-key", line_number=1)]
        content_lines = ["key = test_token_abc123"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            result = filter_findings(findings, content_lines, None, al)
        assert len(result) == 1

    def test_suppresses_by_per_rule_stopword(self):
        ral = RuleAllowlist(stopwords=["example"])
        al = GitleaksAllowlist(rule_allowlists={"generic-api-key": ral})
        findings = [self._make_finding(rule_id="generic-api-key", line_number=1)]
        content_lines = ["key = example_value"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            result = filter_findings(findings, content_lines, None, al)
        assert len(result) == 0

    def test_suppresses_by_per_rule_path(self):
        ral = RuleAllowlist(paths=["tests/fixtures/*"])
        al = GitleaksAllowlist(rule_allowlists={"generic-api-key": ral})
        findings = [self._make_finding(rule_id="generic-api-key", line_number=1)]
        content_lines = ["key = real_secret"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            with patch(
                "ai_guardian.scanners.gitleaks._normalize_path",
                return_value="tests/fixtures/data.py",
            ):
                result = filter_findings(
                    findings, content_lines, "/project/tests/fixtures/data.py", al
                )
        assert len(result) == 0

    def test_preserves_non_matching_findings(self):
        al = GitleaksAllowlist(regexes=[re.compile(r"fake_key_\d+", re.IGNORECASE)])
        findings = [self._make_finding(line_number=1)]
        content_lines = ["real_secret_value_here"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            result = filter_findings(findings, content_lines, None, al)
        assert len(result) == 1

    def test_empty_allowlist_preserves_all(self):
        al = GitleaksAllowlist()
        findings = [self._make_finding(line_number=1)]
        content_lines = ["secret = abc123"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            result = filter_findings(findings, content_lines, None, al)
        assert len(result) == 1

    def test_out_of_range_line_number_not_suppressed(self):
        al = GitleaksAllowlist(regexes=[re.compile(r"fake_key", re.IGNORECASE)])
        findings = [self._make_finding(line_number=99)]
        content_lines = ["fake_key = abc"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            result = filter_findings(findings, content_lines, None, al)
        assert len(result) == 1

    def test_zero_line_number_not_suppressed(self):
        al = GitleaksAllowlist(regexes=[re.compile(r"fake_key", re.IGNORECASE)])
        findings = [self._make_finding(line_number=0)]
        content_lines = ["fake_key = abc"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            result = filter_findings(findings, content_lines, None, al)
        assert len(result) == 1

    def test_multiple_findings_partial_suppression(self):
        al = GitleaksAllowlist(regexes=[re.compile(r"fake_key", re.IGNORECASE)])
        findings = [
            self._make_finding(rule_id="rule-a", line_number=1),
            self._make_finding(rule_id="rule-b", line_number=2),
        ]
        content_lines = ["fake_key = abc", "real_secret = xyz"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            result = filter_findings(findings, content_lines, None, al)
        assert len(result) == 1
        assert result[0]["rule_id"] == "rule-b"

    def test_no_file_path_skips_path_check(self):
        al = GitleaksAllowlist(paths=["tests/*"])
        findings = [self._make_finding(line_number=1)]
        content_lines = ["secret = abc"]
        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root",
            return_value=Path("/project"),
        ):
            result = filter_findings(findings, content_lines, None, al)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Integration: end-to-end with tmp .gitleaks.toml
# ---------------------------------------------------------------------------


class TestIntegrationParsing:
    """Full parsing round-trip with realistic TOML content."""

    def test_full_config_parsing(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text(textwrap.dedent("""\
            [allowlist]
                paths = [
                    "tests/unit/test_secret_redaction.py",
                    "tests/fixtures/**"
                ]
                regexes = ["test_api_key_.*"]
                stopwords = ["example_value", "placeholder"]

            [[rules]]
            id = "generic-api-key"
            description = "Generic API Key"
            [rules.allowlist]
                regexes = ["pk_test_.*"]
                stopwords = ["notsecret"]

            [[rules]]
            id = "aws-access-key"
            description = "AWS Access Key"
            [rules.allowlist]
                paths = ["deploy/test_config.py"]
        """))

        result = load_gitleaks_allowlist(project_root=tmp_path)

        assert result is not None
        assert len(result.paths) == 2
        assert len(result.regexes) == 1
        assert len(result.stopwords) == 2
        assert len(result.rule_allowlists) == 2
        assert "generic-api-key" in result.rule_allowlists
        assert "aws-access-key" in result.rule_allowlists

        api_ral = result.rule_allowlists["generic-api-key"]
        assert len(api_ral.regexes) == 1
        assert len(api_ral.stopwords) == 1

        aws_ral = result.rule_allowlists["aws-access-key"]
        assert len(aws_ral.paths) == 1

    def test_filter_with_parsed_config(self, tmp_path):
        toml_path = tmp_path / ".gitleaks.toml"
        toml_path.write_text(textwrap.dedent("""\
            [allowlist]
                regexes = ["test_api_key_.*"]
        """))
        al = load_gitleaks_allowlist(project_root=tmp_path)

        findings = [
            {"rule_id": "generic-api-key", "line_number": 1, "file": "src/app.py"},
            {"rule_id": "generic-api-key", "line_number": 2, "file": "src/app.py"},
        ]
        content_lines = [
            'token = "test_api_key_abc123"',
            'secret = "real_production_key_xyz"',
        ]

        with patch(
            "ai_guardian.scanners.gitleaks.find_project_root", return_value=tmp_path
        ):
            result = filter_findings(findings, content_lines, None, al)

        assert len(result) == 1
        assert result[0]["line_number"] == 2
