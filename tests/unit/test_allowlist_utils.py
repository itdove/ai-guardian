"""Tests for shared allowlist_utils module (Issue #357)."""

import re
from datetime import datetime, timezone, timedelta

import pytest

from ai_guardian.allowlist_utils import (
    extract_pattern_string,
    is_allowlist_pattern_valid,
    validate_allowlist_patterns,
    filter_valid_patterns,
    compile_allowlist,
    check_allowlist,
)


class TestExtractPatternString:
    def test_simple_string(self):
        assert extract_pattern_string("test:.*") == "test:.*"

    def test_dict_with_pattern(self):
        entry = {"pattern": "debug:.*", "valid_until": "2099-12-31T23:59:59Z"}
        assert extract_pattern_string(entry) == "debug:.*"

    def test_dict_without_pattern_key(self):
        result = extract_pattern_string({"other": "value"})
        assert isinstance(result, str)

    def test_fallback_for_unknown_type(self):
        result = extract_pattern_string(42)
        assert result == "42"


class TestIsAllowlistPatternValid:
    def test_simple_string_never_expires(self):
        assert is_allowlist_pattern_valid("test:.*") is True

    def test_dict_with_future_valid_until(self):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        entry = {"pattern": "temp:.*", "valid_until": future}
        assert is_allowlist_pattern_valid(entry) is True

    def test_dict_with_past_valid_until(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        entry = {"pattern": "old:.*", "valid_until": past}
        assert is_allowlist_pattern_valid(entry) is False

    def test_dict_without_valid_until(self):
        entry = {"pattern": "permanent:.*"}
        assert is_allowlist_pattern_valid(entry) is True

    def test_dict_with_empty_valid_until(self):
        entry = {"pattern": "perm:.*", "valid_until": ""}
        assert is_allowlist_pattern_valid(entry) is True

    def test_unknown_type_treated_as_valid(self):
        assert is_allowlist_pattern_valid(42) is True


class TestValidateAllowlistPatterns:
    def test_blocks_catch_all_dot_star(self):
        result = validate_allowlist_patterns([".*"])
        assert result == []

    def test_blocks_catch_all_dot_plus(self):
        result = validate_allowlist_patterns([".+"])
        assert result == []

    def test_blocks_catch_all_bracket_star(self):
        result = validate_allowlist_patterns([r"[\s\S]*"])
        assert result == []

    def test_blocks_catch_all_bracket_plus(self):
        result = validate_allowlist_patterns([r"[\s\S]+"])
        assert result == []

    def test_allows_safe_patterns(self):
        patterns = [r"test:.*", r"@example\.com"]
        result = validate_allowlist_patterns(patterns)
        assert len(result) == 2

    def test_filters_mixed_safe_and_dangerous(self):
        patterns = [r"safe_pattern", ".*", r"another_safe"]
        result = validate_allowlist_patterns(patterns)
        assert len(result) == 2
        assert ".*" not in [extract_pattern_string(p) for p in result]

    def test_blocks_dict_with_dangerous_pattern(self):
        patterns = [{"pattern": ".*", "valid_until": "2099-01-01T00:00:00Z"}]
        result = validate_allowlist_patterns(patterns)
        assert result == []


class TestFilterValidPatterns:
    def test_keeps_simple_strings(self):
        patterns = ["pattern_a", "pattern_b"]
        result = filter_valid_patterns(patterns)
        assert len(result) == 2

    def test_removes_expired_entries(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        patterns = [
            "permanent",
            {"pattern": "expired:.*", "valid_until": past},
        ]
        result = filter_valid_patterns(patterns)
        assert len(result) == 1
        assert result[0] == "permanent"

    def test_keeps_active_entries(self):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        patterns = [
            {"pattern": "active:.*", "valid_until": future},
        ]
        result = filter_valid_patterns(patterns)
        assert len(result) == 1


class TestCompileAllowlist:
    def test_returns_compiled_patterns(self):
        patterns = [r"@example\.com", r"test_key_\d+"]
        result = compile_allowlist(patterns)
        assert len(result) == 2
        assert all(isinstance(p, re.Pattern) for p in result)

    def test_empty_list(self):
        result = compile_allowlist([])
        assert result == []

    def test_skips_dangerous_patterns(self):
        patterns = ["safe_pattern", ".*"]
        result = compile_allowlist(patterns)
        assert len(result) == 1

    def test_skips_expired_patterns(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        patterns = [
            "permanent",
            {"pattern": "expired:.*", "valid_until": past},
        ]
        result = compile_allowlist(patterns)
        assert len(result) == 1

    def test_handles_invalid_regex_gracefully(self):
        patterns = [r"valid_pattern", r"[invalid"]
        result = compile_allowlist(patterns)
        assert len(result) == 1


class TestCheckAllowlist:
    def test_matches_simple_pattern(self):
        compiled = compile_allowlist([r"@example\.com"])
        assert check_allowlist("user@example.com", compiled) is True

    def test_no_match(self):
        compiled = compile_allowlist([r"@example\.com"])
        assert check_allowlist("user@other.com", compiled) is False

    def test_empty_allowlist(self):
        assert check_allowlist("any text", []) is False

    def test_case_insensitive(self):
        compiled = compile_allowlist([r"@Example\.Com"])
        assert check_allowlist("user@example.com", compiled) is True

    def test_multiple_patterns(self):
        compiled = compile_allowlist([r"@example\.com", r"@anthropic\.com"])
        assert check_allowlist("user@anthropic.com", compiled) is True
        assert check_allowlist("user@example.com", compiled) is True
        assert check_allowlist("user@other.com", compiled) is False
