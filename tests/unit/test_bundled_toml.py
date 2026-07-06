"""Tests for bundled TOML pattern files.

Validates that all bundled TOML files parse correctly and contain
the expected number of compiled rules.
"""

import pytest

from ai_guardian.patterns import DATA_DIR
from ai_guardian.patterns.toml_parser import load_and_compile, load_toml_file

PATTERNS_DIR = DATA_DIR

EXPECTED_COUNTS = {
    "secrets.toml": 59,
    "pii.toml": 13,
    "prompt-injection.toml": 73,
    "unicode.toml": 107,
    "config-exfil.toml": 10,  # Updated for Issue #1100: added curl @file patterns
    "ssrf.toml": 22,
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


class TestNewSecretPatterns:
    """Detection tests for the 6 new AI/cloud credential patterns (Issue #1482)."""

    @pytest.fixture(scope="class")
    def secret_rules(self):
        path = PATTERNS_DIR / "secrets.toml"
        return {r.id: r for r in load_and_compile(path, "secrets")}

    # --- HuggingFace Access Token ---

    def test_huggingface_access_token_detected(self, secret_rules):
        rule = secret_rules["huggingface-access-token"]
        token = "hf_" + "A" * 34
        assert rule.compiled.search(f'token = "{token}"')

    def test_huggingface_access_token_no_false_positive_comment(self, secret_rules):
        rule = secret_rules["huggingface-access-token"]
        assert not rule.compiled.search("# hf_ refers to HuggingFace token format")

    def test_huggingface_access_token_no_false_positive_short(self, secret_rules):
        rule = secret_rules["huggingface-access-token"]
        assert not rule.compiled.search("hf_short")

    # --- HuggingFace Organization API Token ---

    def test_huggingface_org_token_detected(self, secret_rules):
        rule = secret_rules["huggingface-organization-api-token"]
        token = "api_org_" + "B" * 34
        assert rule.compiled.search(f'key = "{token}"')

    def test_huggingface_org_token_no_false_positive_comment(self, secret_rules):
        rule = secret_rules["huggingface-organization-api-token"]
        assert not rule.compiled.search("# api_org_ is the HuggingFace org prefix")

    # --- GitHub Fine-Grained PAT ---

    def test_github_fine_grained_pat_detected(self, secret_rules):
        rule = secret_rules["github-fine-grained-pat"]
        token = "github_pat_" + "A" * 82
        assert rule.compiled.search(f'GITHUB_TOKEN="{token}"')

    def test_github_fine_grained_pat_no_false_positive_short(self, secret_rules):
        rule = secret_rules["github-fine-grained-pat"]
        assert not rule.compiled.search("github_pat_tooshort")

    def test_github_fine_grained_pat_no_false_positive_comment(self, secret_rules):
        rule = secret_rules["github-fine-grained-pat"]
        assert not rule.compiled.search(
            "# github_pat_ is the new fine-grained PAT prefix"
        )

    # --- GitHub User-to-Server Token ---

    def test_github_user_token_detected(self, secret_rules):
        rule = secret_rules["github-user-token"]
        token = "ghu_" + "A" * 36
        assert rule.compiled.search(f'token = "{token}"')

    def test_github_user_token_no_false_positive_comment(self, secret_rules):
        rule = secret_rules["github-user-token"]
        assert not rule.compiled.search("# ghu_ prefix for GitHub user tokens")

    def test_github_user_token_no_false_positive_short(self, secret_rules):
        rule = secret_rules["github-user-token"]
        assert not rule.compiled.search("ghu_abc123")

    # --- AWS Amazon Bedrock API Key ---

    def test_aws_bedrock_api_key_detected(self, secret_rules):
        rule = secret_rules["aws-amazon-bedrock-api-key-long-lived"]
        token = "ABSK" + "A" * 109
        assert rule.compiled.search(f'key = "{token}"')

    def test_aws_bedrock_api_key_no_false_positive_short(self, secret_rules):
        rule = secret_rules["aws-amazon-bedrock-api-key-long-lived"]
        assert not rule.compiled.search("ABSK" + "A" * 10)

    def test_aws_bedrock_api_key_no_false_positive_comment(self, secret_rules):
        rule = secret_rules["aws-amazon-bedrock-api-key-long-lived"]
        assert not rule.compiled.search("# ABSK prefix for Bedrock long-lived keys")

    # --- Perplexity API Key ---

    def test_perplexity_api_key_detected(self, secret_rules):
        rule = secret_rules["perplexity-api-key"]
        token = "pplx-" + "a" * 48
        assert rule.compiled.search(f'PERPLEXITY_API_KEY="{token}"')

    def test_perplexity_api_key_no_false_positive_comment(self, secret_rules):
        rule = secret_rules["perplexity-api-key"]
        assert not rule.compiled.search("# pplx- is the Perplexity API key prefix")

    def test_perplexity_api_key_no_false_positive_short(self, secret_rules):
        rule = secret_rules["perplexity-api-key"]
        assert not rule.compiled.search("pplx-tooshort")
