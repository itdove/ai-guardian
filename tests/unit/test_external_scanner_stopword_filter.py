"""Tests for external scanner stopword/entropy filtering (Issue #1245)."""

import pytest

from ai_guardian.patterns.validators import (
    load_stopwords,
    filter_findings_by_stopwords_entropy,
    filter_findings_dicts_by_stopwords_entropy,
    shannon_entropy,
)
from ai_guardian.scanners.strategies import SecretMatch


def _make_secret_match(secret, rule_id="generic-api-key", category="secrets"):
    return SecretMatch(
        rule_id=rule_id,
        description="test",
        file="test.py",
        line_number=1,
        secret=secret,
        category=category,
    )


class TestLoadStopwords:
    def test_bundled_stopwords_loaded(self):
        words = load_stopwords()
        assert len(words) > 0
        assert "your_token" in words or "your" in words

    def test_user_config_merged(self):
        words = load_stopwords({"stopwords": ["CUSTOM_PLACEHOLDER"]})
        assert "custom_placeholder" in words
        assert len(words) > 1  # bundled words also present

    def test_deduplication(self):
        words = load_stopwords({"stopwords": ["example", "EXAMPLE"]})
        count = words.count("example")
        assert count == 1

    def test_short_words_excluded(self):
        words = load_stopwords({"stopwords": ["ab", "x"]})
        assert "ab" not in words
        assert "x" not in words

    def test_none_config(self):
        words = load_stopwords(None)
        assert len(words) > 0

    def test_empty_config(self):
        words = load_stopwords({})
        assert len(words) > 0  # bundled words still loaded


class TestFilterFindingsByStopwordsEntropy:
    def test_placeholder_filtered(self):
        secrets = [_make_secret_match("YOUR_TOKEN")]
        filtered, sw, ent = filter_findings_by_stopwords_entropy(
            secrets, load_stopwords(), 3.0)
        assert len(filtered) == 0
        assert sw == 1
        assert ent == 0

    def test_case_insensitive(self):
        secrets = [_make_secret_match("your_secret_key")]
        filtered, sw, ent = filter_findings_by_stopwords_entropy(
            secrets, load_stopwords(), 3.0)
        assert len(filtered) == 0
        assert sw == 1

    def test_low_entropy_filtered(self):
        secrets = [_make_secret_match("aaaaaaaaa")]
        filtered, sw, ent = filter_findings_by_stopwords_entropy(
            secrets, [], 3.0)
        assert len(filtered) == 0
        assert sw == 0
        assert ent == 1

    def test_real_secret_passes(self):
        secrets = [_make_secret_match("sk-abcDEF12345ghiJKL67890mnoPQR")]
        filtered, sw, ent = filter_findings_by_stopwords_entropy(
            secrets, load_stopwords(), 3.0)
        assert len(filtered) == 1

    def test_mixed_findings(self):
        secrets = [
            _make_secret_match("YOUR_TOKEN"),
            _make_secret_match("sk-abcDEF12345ghiJKL67890mnoPQR"),
        ]
        filtered, sw, ent = filter_findings_by_stopwords_entropy(
            secrets, load_stopwords(), 3.0)
        assert len(filtered) == 1
        assert filtered[0].secret == "sk-abcDEF12345ghiJKL67890mnoPQR"
        assert sw == 1

    def test_none_matched_text_passes(self):
        secrets = [_make_secret_match(None)]
        filtered, sw, ent = filter_findings_by_stopwords_entropy(
            secrets, load_stopwords(), 3.0)
        assert len(filtered) == 1

    def test_entropy_disabled_when_none(self):
        secrets = [_make_secret_match("aaaaaaaaa")]
        filtered, sw, ent = filter_findings_by_stopwords_entropy(
            secrets, [], None)
        assert len(filtered) == 1
        assert ent == 0

    def test_non_secrets_category_not_filtered(self):
        secrets = [_make_secret_match("YOUR_TOKEN", category="pii")]
        filtered, sw, ent = filter_findings_by_stopwords_entropy(
            secrets, load_stopwords(), 3.0)
        assert len(filtered) == 1

    def test_replace_me_filtered(self):
        secrets = [_make_secret_match("REPLACE_ME_WITH_TOKEN")]
        filtered, sw, ent = filter_findings_by_stopwords_entropy(
            secrets, load_stopwords(), 3.0)
        assert len(filtered) == 0

    def test_example_api_key_filtered(self):
        secrets = [_make_secret_match("AKIAIOSFODNN7EXAMPLE")]
        filtered, sw, ent = filter_findings_by_stopwords_entropy(
            secrets, load_stopwords(), 3.0)
        assert len(filtered) == 0


class TestFilterFindingsDictsByStopwordsEntropy:
    def test_placeholder_dict_filtered(self):
        findings = [{"matched_text": "YOUR_API_KEY", "rule_id": "generic-api-key"}]
        filtered, sw, ent = filter_findings_dicts_by_stopwords_entropy(
            findings, load_stopwords(), 3.0)
        assert len(filtered) == 0
        assert sw == 1

    def test_real_secret_dict_passes(self):
        findings = [{"matched_text": "ghp_xYz123AbCdEf456GhIjK", "rule_id": "github-pat"}]
        filtered, sw, ent = filter_findings_dicts_by_stopwords_entropy(
            findings, load_stopwords(), 3.0)
        assert len(filtered) == 1

    def test_low_entropy_dict_filtered(self):
        findings = [{"matched_text": "AAAAAAAAAA", "rule_id": "generic-api-key"}]
        filtered, sw, ent = filter_findings_dicts_by_stopwords_entropy(
            findings, [], 3.0)
        assert len(filtered) == 0
        assert ent == 1

    def test_missing_matched_text_passes(self):
        findings = [{"rule_id": "generic-api-key"}]
        filtered, sw, ent = filter_findings_dicts_by_stopwords_entropy(
            findings, load_stopwords(), 3.0)
        assert len(filtered) == 1

    def test_empty_matched_text_passes(self):
        findings = [{"matched_text": "", "rule_id": "generic-api-key"}]
        filtered, sw, ent = filter_findings_dicts_by_stopwords_entropy(
            findings, load_stopwords(), 3.0)
        assert len(filtered) == 1
