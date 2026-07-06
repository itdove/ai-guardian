"""Tests for bundled TOML pattern files.

Validates that all bundled TOML files parse correctly and contain
the expected number of compiled rules.
"""

import pytest

from ai_guardian.patterns import DATA_DIR
from ai_guardian.patterns.toml_parser import load_and_compile, load_toml_file

PATTERNS_DIR = DATA_DIR

EXPECTED_COUNTS = {
    "secrets.toml": 53,
    "pii.toml": 13,
    "prompt-injection.toml": 73,
    "unicode.toml": 107,
    "config-exfil.toml": 10,  # Updated for Issue #1100: added curl @file patterns
    "ssrf.toml": 24,
}


class TestBundledTomlFiles:

    @pytest.mark.parametrize("filename", list(EXPECTED_COUNTS.keys()))
    def test_file_exists(self, filename):
        path = PATTERNS_DIR / filename
        assert path.exists(), f"Missing bundled pattern file: {path}"

    @pytest.mark.parametrize("filename,expected", list(EXPECTED_COUNTS.items()))
    def test_rule_count_matches(self, filename, expected):
        path = PATTERNS_DIR / filename
        category = filename.replace(".toml", "").replace("-", "_")
        rules = load_and_compile(path, category)
        assert (
            len(rules) == expected
        ), f"{filename}: expected {expected} rules, got {len(rules)}"

    @pytest.mark.parametrize("filename", list(EXPECTED_COUNTS.keys()))
    def test_all_rules_have_ids(self, filename):
        path = PATTERNS_DIR / filename
        raw_rules = load_toml_file(path)
        for i, rule in enumerate(raw_rules):
            assert "id" in rule, f"{filename} rule {i}: missing 'id' field"
            assert rule["id"], f"{filename} rule {i}: empty 'id' field"

    @pytest.mark.parametrize("filename", list(EXPECTED_COUNTS.keys()))
    def test_all_rules_have_match_type(self, filename):
        path = PATTERNS_DIR / filename
        raw_rules = load_toml_file(path)
        for rule in raw_rules:
            assert (
                "match_type" in rule
            ), f"{filename} rule {rule.get('id', '?')}: missing 'match_type'"

    @pytest.mark.parametrize("filename", list(EXPECTED_COUNTS.keys()))
    def test_unique_ids(self, filename):
        path = PATTERNS_DIR / filename
        raw_rules = load_toml_file(path)
        ids = [r["id"] for r in raw_rules]
        dupes = [x for x in ids if ids.count(x) > 1]
        assert not dupes, f"{filename}: duplicate rule IDs: {set(dupes)}"

    def test_total_rule_count(self):
        total = 0
        for filename, expected in EXPECTED_COUNTS.items():
            path = PATTERNS_DIR / filename
            category = filename.replace(".toml", "").replace("-", "_")
            rules = load_and_compile(path, category)
            total += len(rules)
        assert total == sum(
            EXPECTED_COUNTS.values()
        ), f"Total rules mismatch: {total} != {sum(EXPECTED_COUNTS.values())}"

    def test_secrets_have_redaction_strategy(self):
        path = PATTERNS_DIR / "secrets.toml"
        rules = load_and_compile(path, "secrets")
        for rule in rules:
            assert (
                "redaction_strategy" in rule.metadata
            ), f"Secret rule {rule.id}: missing redaction_strategy"

    def test_pii_have_pii_type(self):
        path = PATTERNS_DIR / "pii.toml"
        rules = load_and_compile(path, "pii")
        for rule in rules:
            assert "pii_type" in rule.metadata, f"PII rule {rule.id}: missing pii_type"

    def test_prompt_injection_have_group(self):
        path = PATTERNS_DIR / "prompt-injection.toml"
        rules = load_and_compile(path, "prompt_injection")
        valid_groups = {"critical", "documentation", "jailbreak", "suspicious"}
        for rule in rules:
            assert "group" in rule.metadata, f"PI rule {rule.id}: missing group"
            assert (
                rule.metadata["group"] in valid_groups
            ), f"PI rule {rule.id}: invalid group '{rule.metadata['group']}'"

    def test_prompt_injection_group_counts(self):
        path = PATTERNS_DIR / "prompt-injection.toml"
        rules = load_and_compile(path, "prompt_injection")
        counts = {}
        for rule in rules:
            group = rule.metadata.get("group", "unknown")
            counts[group] = counts.get(group, 0) + 1
        assert counts.get("critical", 0) == 32
        assert counts.get("documentation", 0) == 20
        assert counts.get("jailbreak", 0) == 14
        assert counts.get("suspicious", 0) == 7
