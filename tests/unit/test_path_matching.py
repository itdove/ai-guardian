"""Tests for path matching utilities (Issue #1093)."""

from ai_guardian.utils.path_matching import (
    matches_ignore_files,
)


class TestMatchesIgnoreFiles:

    def test_empty_list_returns_false(self):
        assert matches_ignore_files("/project/src/main.py", []) is False

    def test_none_file_path_returns_false(self):
        assert matches_ignore_files(None, ["*.py"]) is False

    def test_empty_file_path_returns_false(self):
        assert matches_ignore_files("", ["*.py"]) is False

    def test_simple_glob_matches_basename(self):
        assert (
            matches_ignore_files("/project/data/creds.fixture", ["*.fixture"]) is True
        )

    def test_leading_doublestar_pattern(self):
        assert (
            matches_ignore_files(
                "/project/tests/fixtures/creds.json",
                ["**/tests/fixtures/**"],
            )
            is True
        )

    def test_no_match_returns_false(self):
        assert (
            matches_ignore_files(
                "/project/src/main.py",
                ["**/tests/**", "*.fixture"],
            )
            is False
        )

    def test_path_match_pattern(self):
        assert (
            matches_ignore_files(
                "/project/.git/config",
                [".git/**"],
            )
            is True
        )

    def test_multiple_patterns_any_match(self):
        assert (
            matches_ignore_files(
                "/project/src/main.py",
                ["*.txt", "*.py"],
            )
            is True
        )

    def test_none_ignore_files_returns_false(self):
        assert matches_ignore_files("/project/src/main.py", None) is False
