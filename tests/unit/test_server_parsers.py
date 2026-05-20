"""Tests for pattern server response parsers."""

import pytest

from ai_guardian.patterns.server_parsers import (
    AIGuardianParser,
    GitleaksParser,
    get_parser,
    list_formats,
)


class TestAIGuardianParser:

    def test_parse_valid_rules(self):
        parser = AIGuardianParser()
        data = {
            "rules": [
                {"id": "r1", "match_type": "regex", "regex": "test"},
                {"id": "r2", "match_type": "literal", "source": "x", "target": "y"},
            ]
        }
        result = parser.parse(data)
        assert len(result) == 2
        assert result[0]["id"] == "r1"

    def test_parse_empty_rules(self):
        parser = AIGuardianParser()
        assert parser.parse({"rules": []}) == []

    def test_parse_missing_rules_key(self):
        parser = AIGuardianParser()
        assert parser.parse({"metadata": {}}) == []

    def test_parse_invalid_rules_type(self):
        parser = AIGuardianParser()
        assert parser.parse({"rules": "not a list"}) == []


class TestGitleaksParser:

    def test_parse_gitleaks_rules(self):
        parser = GitleaksParser()
        data = {
            "rules": [
                {
                    "id": "aws-access-key",
                    "description": "AWS Access Key",
                    "regex": r"AKIA[A-Z0-9]{16}",
                    "keywords": ["AKIA"],
                    "secretGroup": 0,
                },
                {
                    "id": "github-pat",
                    "description": "GitHub PAT",
                    "regex": r"ghp_[A-Za-z0-9]{36}",
                    "keywords": ["ghp_"],
                },
            ]
        }
        result = parser.parse(data)
        assert len(result) == 2
        assert result[0]["id"] == "aws-access-key"
        assert result[0]["match_type"] == "regex"
        assert result[0]["regex"] == r"AKIA[A-Z0-9]{16}"
        assert result[0]["redaction_strategy"] == "preserve_prefix_suffix"
        assert result[0]["keywords"] == ["AKIA"]
        assert result[0]["secretGroup"] == 0

    def test_parse_skips_empty_regex(self):
        parser = GitleaksParser()
        data = {
            "rules": [
                {"id": "empty", "description": "Empty regex", "regex": ""},
                {"id": "valid", "description": "Valid", "regex": "test"},
            ]
        }
        result = parser.parse(data)
        assert len(result) == 1
        assert result[0]["id"] == "valid"

    def test_parse_empty_rules(self):
        parser = GitleaksParser()
        assert parser.parse({"rules": []}) == []

    def test_format_name(self):
        assert GitleaksParser.format_name == "gitleaks"
        assert AIGuardianParser.format_name == "ai-guardian"


class TestParserRegistry:

    def test_get_known_parser(self):
        parser = get_parser("ai-guardian")
        assert isinstance(parser, AIGuardianParser)

    def test_get_gitleaks_parser(self):
        parser = get_parser("gitleaks")
        assert isinstance(parser, GitleaksParser)

    def test_get_unknown_parser(self):
        assert get_parser("unknown-format") is None

    def test_list_formats(self):
        formats = list_formats()
        assert "ai-guardian" in formats
        assert "gitleaks" in formats
