"""
Tests for pattern_lister module (Issue #337).
"""

import json
from io import StringIO
from unittest import mock

import pytest

from ai_guardian.pattern_lister import (
    CATEGORY_ALIASES,
    BuiltInGroup,
    ConfigurableKey,
    PatternCategory,
    PatternLister,
)


class TestPatternLister:
    """Tests for PatternLister core functionality."""

    def test_get_categories_returns_all(self):
        lister = PatternLister()
        categories = lister.get_categories()

        config_keys = {cat.config_key for cat in categories}
        assert "prompt_injection" in config_keys
        assert "scan_pii" in config_keys
        assert "ssrf_protection" in config_keys
        assert "config_file_scanning" in config_keys
        assert "secret_redaction" in config_keys
        assert "violation_logging" in config_keys
        assert len(categories) == 6

    def test_get_categories_with_filter(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="prompt_injection")

        assert len(categories) == 1
        assert categories[0].config_key == "prompt_injection"

    def test_get_categories_with_alias(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="ssrf")

        assert len(categories) == 1
        assert categories[0].config_key == "ssrf_protection"

    def test_get_categories_unicode_alias(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="unicode")

        assert len(categories) == 1
        assert categories[0].config_key == "prompt_injection.unicode_detection"

    def test_get_categories_invalid_filter(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="nonexistent")

        assert categories == []

    def test_prompt_injection_built_in_counts(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="prompt_injection")
        cat = categories[0]

        assert cat.total_built_in >= 50
        group_names = {g.name for g in cat.built_in_groups}
        assert "CRITICAL_PATTERNS" in group_names
        assert "DOCUMENTATION_PATTERNS" in group_names
        assert "JAILBREAK_PATTERNS" in group_names
        assert "SUSPICIOUS_PATTERNS" in group_names

    def test_unicode_detection_built_in_counts(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="unicode")
        cat = categories[0]

        assert cat.total_built_in >= 90
        group_names = {g.name for g in cat.built_in_groups}
        assert "Zero-width chars" in group_names
        assert "Homoglyph patterns" in group_names

    def test_pii_built_in_counts(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="scan_pii")
        cat = categories[0]

        assert cat.total_built_in >= 7

    def test_ssrf_built_in_counts(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="ssrf")
        cat = categories[0]

        assert cat.total_built_in >= 20

    def test_config_scanning_built_in_counts(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="config_file_scanning")
        cat = categories[0]

        assert cat.total_built_in >= 8

    def test_secret_redaction_built_in_counts(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="secret_redaction")
        cat = categories[0]

        assert cat.total_built_in >= 35

    def test_configurable_keys_prompt_injection(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="prompt_injection")
        key_names = {k.name for k in categories[0].configurable_keys}

        assert "custom_patterns" in key_names
        assert "jailbreak_patterns" in key_names
        assert "allowlist_patterns" in key_names
        assert "ignore_files" in key_names
        assert "ignore_tools" in key_names
        assert "enabled" not in key_names
        assert "action" not in key_names
        assert "detector" not in key_names

    def test_configurable_keys_pii(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="scan_pii")
        key_names = {k.name for k in categories[0].configurable_keys}

        assert "pii_types" in key_names
        assert "ignore_files" in key_names

        pii_key = next(k for k in categories[0].configurable_keys if k.name == "pii_types")
        assert pii_key.enum_values is not None
        assert "ssn" in pii_key.enum_values
        assert "email" in pii_key.enum_values

    def test_configurable_keys_ssrf(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="ssrf")
        key_names = {k.name for k in categories[0].configurable_keys}

        assert "additional_blocked_ips" in key_names
        assert "additional_blocked_domains" in key_names
        assert "allowed_domains" in key_names
        assert "path_based_rules" in key_names
        assert "allow_localhost" not in key_names

    def test_configurable_keys_violation_logging(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="violation_logging")
        key_names = {k.name for k in categories[0].configurable_keys}

        assert "log_types" in key_names
        log_key = next(k for k in categories[0].configurable_keys if k.name == "log_types")
        assert log_key.enum_values is not None
        assert "prompt_injection" in log_key.enum_values

    def test_configurable_keys_with_user_config(self):
        config = {
            "prompt_injection": {
                "custom_patterns": [r"test\d+", r"example.*"],
                "ignore_files": ["*.md"],
            }
        }
        lister = PatternLister(config=config)
        categories = lister.get_categories(category_filter="prompt_injection")
        keys = {k.name: k for k in categories[0].configurable_keys}

        assert keys["custom_patterns"].current_count == 2
        assert keys["ignore_files"].current_count == 1

    def test_prompt_injection_has_unicode_subcategory(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="prompt_injection")
        cat = categories[0]

        assert len(cat.subcategories) == 1
        assert cat.subcategories[0].config_key == "prompt_injection.unicode_detection"

    def test_value_type_inference(self):
        lister = PatternLister()

        pi_cats = lister.get_categories(category_filter="prompt_injection")
        pi_keys = {k.name: k for k in pi_cats[0].configurable_keys}
        assert pi_keys["custom_patterns"].value_type == "regex list"
        assert pi_keys["ignore_files"].value_type == "glob list"
        assert pi_keys["ignore_tools"].value_type == "fnmatch list"

        ssrf_cats = lister.get_categories(category_filter="ssrf")
        ssrf_keys = {k.name: k for k in ssrf_cats[0].configurable_keys}
        assert ssrf_keys["additional_blocked_ips"].value_type == "CIDR list"
        assert ssrf_keys["path_based_rules"].value_type == "object list"

        pii_cats = lister.get_categories(category_filter="pii")
        pii_keys = {k.name: k for k in pii_cats[0].configurable_keys}
        assert pii_keys["pii_types"].value_type == "enum"

    def test_unicode_configurable_keys_are_bools(self):
        lister = PatternLister()
        categories = lister.get_categories(category_filter="unicode")
        for key in categories[0].configurable_keys:
            assert key.value_type == "bool"


class TestPatternListerOutput:
    """Tests for print output formatting."""

    def test_print_pattern_list_default(self, capsys):
        lister = PatternLister(config={})
        lister.print_pattern_list()
        output = capsys.readouterr().out

        assert "Detection Patterns:" in output
        assert "Prompt Injection" in output
        assert "PII Detection" in output
        assert "SSRF Protection" in output
        assert "Config File Scanning" in output
        assert "Secret Redaction" in output
        assert "Violation Logging" in output
        assert "Use --verbose" in output

    def test_print_pattern_list_verbose(self, capsys):
        lister = PatternLister(config={})
        lister.print_pattern_list(verbose=True)
        output = capsys.readouterr().out

        assert "CRITICAL_PATTERNS" in output
        assert "DOCUMENTATION_PATTERNS" in output
        assert "JAILBREAK_PATTERNS" in output
        assert "Zero-width chars" in output
        assert "Homoglyph patterns" in output
        assert "Use --verbose" not in output

    def test_print_pattern_list_filtered(self, capsys):
        lister = PatternLister(config={})
        lister.print_pattern_list(category="ssrf")
        output = capsys.readouterr().out

        assert "SSRF Protection" in output
        assert "Prompt Injection" not in output

    def test_print_pattern_list_unknown_category(self, capsys):
        lister = PatternLister(config={})
        lister.print_pattern_list(category="nonexistent")
        output = capsys.readouterr().out

        assert "No pattern category found" in output
        assert "Available categories:" in output
        assert "prompt_injection" in output

    def test_print_verbose_shows_enum_values(self, capsys):
        lister = PatternLister(config={})
        lister.print_pattern_list(verbose=True, category="scan_pii")
        output = capsys.readouterr().out

        assert "Values:" in output
        assert "ssn" in output
        assert "email" in output

    def test_print_shows_bool_current_value(self, capsys):
        lister = PatternLister(config={})
        lister.print_pattern_list(category="unicode")
        output = capsys.readouterr().out

        assert "(current: true)" in output


class TestPatternListerJson:
    """Tests for JSON output."""

    def test_get_pattern_list_json(self):
        lister = PatternLister(config={})
        result = json.loads(lister.get_pattern_list_json())

        assert "categories" in result
        assert len(result["categories"]) == 6

    def test_get_pattern_list_json_filtered(self):
        lister = PatternLister(config={})
        result = json.loads(lister.get_pattern_list_json(category="ssrf"))

        assert len(result["categories"]) == 1
        assert result["categories"][0]["config_key"] == "ssrf_protection"

    def test_json_structure(self):
        lister = PatternLister(config={})
        result = json.loads(lister.get_pattern_list_json(category="prompt_injection"))
        cat = result["categories"][0]

        assert "name" in cat
        assert "config_key" in cat
        assert "total_built_in" in cat
        assert "built_in_groups" in cat
        assert "configurable_keys" in cat
        assert "subcategories" in cat

    def test_json_built_in_groups(self):
        lister = PatternLister(config={})
        result = json.loads(lister.get_pattern_list_json(category="prompt_injection"))
        groups = result["categories"][0]["built_in_groups"]

        assert len(groups) >= 4
        for group in groups:
            assert "name" in group
            assert "count" in group
            assert isinstance(group["count"], int)

    def test_json_configurable_keys(self):
        lister = PatternLister(config={})
        result = json.loads(lister.get_pattern_list_json(category="scan_pii"))
        keys = result["categories"][0]["configurable_keys"]

        key_names = {k["name"] for k in keys}
        assert "pii_types" in key_names

        for key in keys:
            assert "name" in key
            assert "value_type" in key
            assert "current_count" in key

    def test_json_enum_values_present(self):
        lister = PatternLister(config={})
        result = json.loads(lister.get_pattern_list_json(category="scan_pii"))
        keys = result["categories"][0]["configurable_keys"]

        pii_key = next(k for k in keys if k["name"] == "pii_types")
        assert "enum_values" in pii_key
        assert "ssn" in pii_key["enum_values"]

    def test_json_subcategories(self):
        lister = PatternLister(config={})
        result = json.loads(lister.get_pattern_list_json(category="prompt_injection"))
        subs = result["categories"][0]["subcategories"]

        assert len(subs) == 1
        assert subs[0]["config_key"] == "prompt_injection.unicode_detection"
        assert subs[0]["total_built_in"] >= 90

    def test_json_with_user_config(self):
        config = {
            "prompt_injection": {
                "custom_patterns": [r"test\d+"],
                "jailbreak_patterns": [r"evil.*", r"bad\s+thing"],
            }
        }
        lister = PatternLister(config=config)
        result = json.loads(lister.get_pattern_list_json(category="prompt_injection"))
        keys = {k["name"]: k for k in result["categories"][0]["configurable_keys"]}

        assert keys["custom_patterns"]["current_count"] == 1
        assert keys["jailbreak_patterns"]["current_count"] == 2


class TestPatternCategory:
    """Tests for PatternCategory dataclass."""

    def test_total_built_in(self):
        cat = PatternCategory(
            name="Test",
            config_key="test",
            built_in_groups=[
                BuiltInGroup("A", 10),
                BuiltInGroup("B", 20),
                BuiltInGroup("C", 5),
            ],
        )
        assert cat.total_built_in == 35

    def test_total_built_in_empty(self):
        cat = PatternCategory(name="Test", config_key="test")
        assert cat.total_built_in == 0


class TestCategoryAliases:
    """Tests for category alias resolution."""

    def test_all_aliases_resolve(self):
        lister = PatternLister()
        all_cats = lister.get_categories()
        all_keys = set()
        for cat in all_cats:
            all_keys.add(cat.config_key)
            for sub in cat.subcategories:
                all_keys.add(sub.config_key)

        for alias, target in CATEGORY_ALIASES.items():
            assert target in all_keys, f"Alias '{alias}' -> '{target}' not in available categories"
