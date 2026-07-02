"""Unit tests for the offensive language scanner."""

import pytest

from ai_guardian.offensive_language import OffensiveLanguageScanner


def _scanner(categories=None, enabled=True):
    cfg = {
        "enabled": enabled,
        "action": "log",
        "categories": categories if categories is not None else ["profanity", "slurs"],
        "allowlist_patterns": [],
    }
    return OffensiveLanguageScanner(cfg)


class TestOffensiveLanguageScannerClean:
    def test_empty_string(self):
        scanner = _scanner()
        assert scanner.scan("") == []

    def test_clean_code(self):
        scanner = _scanner()
        findings = scanner.scan(
            "def calculate_total(price, quantity):\n    return price * quantity\n"
        )
        assert findings == []

    def test_clean_comment(self):
        scanner = _scanner()
        findings = scanner.scan("# This function validates user input\n")
        assert findings == []


class TestProfanityCategory:
    def test_detects_profanity_fword(self):
        scanner = _scanner(categories=["profanity"])
        # ai-guardian:begin-allow offensive_language
        findings = scanner.scan("# this fucking works")
        # ai-guardian:end-allow
        assert len(findings) >= 1
        assert any(f["category_tag"] == "profanity" for f in findings)

    def test_detects_profanity_case_insensitive(self):
        scanner = _scanner(categories=["profanity"])
        # ai-guardian:begin-allow offensive_language
        findings = scanner.scan("# SHIT happens")
        # ai-guardian:end-allow
        assert len(findings) >= 1

    def test_no_slurs_when_only_profanity_category(self):
        scanner = _scanner(categories=["profanity"])
        # ai-guardian:begin-allow offensive_language
        findings = scanner.scan("# moron")
        # ai-guardian:end-allow
        # moron is a slur — not loaded
        assert all(f["category_tag"] != "slurs" for f in findings)

    def test_line_number_tracked(self):
        scanner = _scanner(categories=["profanity"])
        # ai-guardian:begin-allow offensive_language
        text = "line one\nline two\n# crap happens here\nline four\n"
        # ai-guardian:end-allow
        findings = scanner.scan(text)
        assert len(findings) >= 1
        assert findings[0]["line_number"] == 3

    def test_column_tracked(self):
        scanner = _scanner(categories=["profanity"])
        # ai-guardian:begin-allow offensive_language
        text = "  # crap"
        # ai-guardian:end-allow
        findings = scanner.scan(text)
        assert len(findings) >= 1
        assert findings[0]["start_column"] >= 1


class TestSlursCategory:
    def test_detects_slur(self):
        scanner = _scanner(categories=["slurs"])
        # ai-guardian:begin-allow offensive_language
        findings = scanner.scan("# moron")
        # ai-guardian:end-allow
        assert len(findings) >= 1
        assert any(f["category_tag"] == "slurs" for f in findings)

    def test_no_profanity_when_only_slurs_category(self):
        scanner = _scanner(categories=["slurs"])
        # ai-guardian:begin-allow offensive_language
        findings = scanner.scan("# crap code")
        # ai-guardian:end-allow
        # crap is profanity — not loaded
        assert all(f["category_tag"] != "profanity" for f in findings)


class TestInclusiveLanguageCategory:
    def test_inclusive_off_by_default(self):
        scanner = _scanner(categories=["profanity", "slurs"])
        findings = scanner.scan("MASTER_KEY = 'abc'\nblacklist = []\n")
        assert all(f["category_tag"] != "inclusive_language" for f in findings)

    def test_inclusive_on_when_opted_in(self):
        scanner = _scanner(categories=["inclusive_language"])
        findings = scanner.scan("MASTER_KEY = 'abc'\nblacklist = []\n")
        assert len(findings) >= 1
        assert any(f["category_tag"] == "inclusive_language" for f in findings)

    def test_inclusive_has_suggestion(self):
        scanner = _scanner(categories=["inclusive_language"])
        findings = scanner.scan("blacklist = []\n")
        assert len(findings) >= 1
        match = next(
            (f for f in findings if "blacklist" in f.get("matched_text", "").lower()),
            None,
        )
        assert match is not None
        assert match.get("suggestion", "") != ""

    def test_sanity_check_detected(self):
        scanner = _scanner(categories=["inclusive_language"])
        findings = scanner.scan("# Run a sanity check on the output\n")
        assert any("sanity" in f.get("matched_text", "").lower() for f in findings)

    def test_dummy_variable_detected(self):
        scanner = _scanner(categories=["inclusive_language"])
        # dummy as standalone word (dummy_value doesn't match \bdummy\b — _ is a word char)
        findings = scanner.scan("x = dummy  # placeholder\n")
        assert any("dummy" in f.get("matched_text", "").lower() for f in findings)


class TestCategoryFiltering:
    def test_empty_categories_loads_nothing(self):
        scanner = _scanner(categories=[])
        # ai-guardian:begin-allow offensive_language
        findings = scanner.scan("# shit blacklist master")
        # ai-guardian:end-allow
        assert findings == []

    def test_multiple_categories(self):
        scanner = _scanner(categories=["profanity", "inclusive_language"])
        # ai-guardian:begin-allow offensive_language
        text = "# crap\nblacklist = []\n"
        # ai-guardian:end-allow
        findings = scanner.scan(text)
        categories_found = {f["category_tag"] for f in findings}
        assert "profanity" in categories_found
        assert "inclusive_language" in categories_found

    def test_finding_fields_present(self):
        scanner = _scanner(categories=["profanity"])
        # ai-guardian:begin-allow offensive_language
        findings = scanner.scan("# crap")
        # ai-guardian:end-allow
        assert len(findings) >= 1
        f = findings[0]
        assert "rule_id" in f
        assert "category_tag" in f
        assert "description" in f
        assert "suggestion" in f
        assert "matched_text" in f
        assert "line_number" in f
        assert "start_column" in f


class TestEdgeCases:
    def test_none_file_path(self):
        scanner = _scanner()
        # ai-guardian:begin-allow offensive_language
        findings = scanner.scan("# crap", file_path=None)
        # ai-guardian:end-allow
        assert len(findings) >= 1
        assert findings[0]["file_path"] is None

    def test_file_path_propagated(self):
        scanner = _scanner(categories=["profanity"])
        # ai-guardian:begin-allow offensive_language
        findings = scanner.scan("# crap", file_path="src/example.py")
        # ai-guardian:end-allow
        assert findings[0]["file_path"] == "src/example.py"

    def test_multiple_matches_on_same_line(self):
        scanner = _scanner(categories=["profanity"])
        # ai-guardian:begin-allow offensive_language
        text = "# crap crap crap"
        # ai-guardian:end-allow
        findings = scanner.scan(text)
        assert len(findings) >= 3


class TestIntegration:
    def test_disabled_scanner_returns_empty(self):
        """run_offensive_language_scan respects enabled=false."""
        from ai_guardian.hook_processing import run_offensive_language_scan

        config = {
            "enabled": False,
            "action": "log",
            "categories": ["profanity"],
            "ignore_files": [],
            "ignore_tools": [],
        }
        # ai-guardian:begin-allow offensive_language
        result = run_offensive_language_scan("# shit", config=config)
        # ai-guardian:end-allow
        assert result is None

    def test_enabled_scanner_detects(self):
        """run_offensive_language_scan detects when enabled=true."""
        from ai_guardian.hook_processing import run_offensive_language_scan

        config = {
            "enabled": True,
            "action": "log",
            "categories": ["profanity"],
            "ignore_files": [],
            "ignore_tools": [],
        }
        # ai-guardian:begin-allow offensive_language
        result = run_offensive_language_scan("# crap", config=config)
        # ai-guardian:end-allow
        assert result is not None
        assert result.detected is True
        assert result.violation_type == "offensive_language"

    def test_enabled_scanner_clean_content(self):
        """run_offensive_language_scan returns non-detected for clean content."""
        from ai_guardian.hook_processing import run_offensive_language_scan

        config = {
            "enabled": True,
            "action": "log",
            "categories": ["profanity"],
            "ignore_files": [],
            "ignore_tools": [],
        }
        result = run_offensive_language_scan(
            "def validate_user_input(value):\n    return len(value) > 0\n",
            config=config,
        )
        assert result is not None
        assert result.detected is False
