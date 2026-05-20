"""Tests for TomlPatternsScanner — Scanner SDK engine."""

import pytest

from ai_guardian.scanners.sdk import Scanner, Finding
from ai_guardian.scanners.toml_patterns import TomlPatternsScanner


class TestTomlPatternsScanner:

    def test_is_scanner_subclass(self):
        scanner = TomlPatternsScanner()
        assert isinstance(scanner, Scanner)

    def test_name_and_version(self):
        scanner = TomlPatternsScanner()
        assert scanner.name == "toml-patterns"
        assert scanner.version == "1.0.0"

    def test_scan_finds_api_key(self):
        scanner = TomlPatternsScanner()
        findings = scanner.scan("Config: sk-abcdefghijklmnopqrstuvwxyz")
        assert len(findings) >= 1
        assert any(f.rule_id == "openai-api-key" for f in findings)

    def test_scan_returns_finding_objects(self):
        scanner = TomlPatternsScanner()
        findings = scanner.scan("Token: ghp_abcdefghijklmnopqrstuvwxyz0123456789")  # notsecret
        for f in findings:
            assert isinstance(f, Finding)
            assert f.rule_id
            assert f.line_number >= 1
            assert f.matched_text
            assert f.severity == "warning"

    def test_scan_no_match(self):
        scanner = TomlPatternsScanner()
        findings = scanner.scan("Nothing sensitive here at all.")
        secret_findings = [f for f in findings if f.rule_id.startswith("openai") or f.rule_id.startswith("github")]
        assert len(secret_findings) == 0

    def test_scan_empty_content(self):
        scanner = TomlPatternsScanner()
        assert scanner.scan("") == []

    def test_has_rules_loaded(self):
        scanner = TomlPatternsScanner()
        assert scanner._cache.rule_count > 0

    def test_configure_additional_patterns(self):
        scanner = TomlPatternsScanner()
        initial_count = scanner._cache.rule_count
        scanner.configure({
            "additional_patterns": [
                {"id": "custom-1", "match_type": "regex", "regex": "custom-secret-[0-9]+"}
            ]
        })
        assert scanner._cache.rule_count == initial_count + 1


class TestTomlPatternsEngineBuilder:

    def test_select_toml_patterns_engine(self):
        from ai_guardian.scanners.engine_builder import _build_engine_config
        config = _build_engine_config("toml-patterns")
        assert config is not None
        assert config.type == "python"
        assert config.python_scanner is not None
        assert config.python_scanner.name == "toml-patterns"

    def test_select_toml_patterns_as_dict(self):
        from ai_guardian.scanners.engine_builder import _build_engine_config
        config = _build_engine_config({"type": "toml-patterns"})
        assert config is not None
        assert config.python_scanner.name == "toml-patterns"

    def test_select_engine_with_toml_patterns(self):
        from ai_guardian.scanners.engine_builder import select_engine
        config = select_engine(["toml-patterns"])
        assert config is not None
        assert config.python_scanner.name == "toml-patterns"
