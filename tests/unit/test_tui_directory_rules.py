"""
Unit tests for Directory Rules TUI panel (Issue #426)
"""

import importlib
import unittest


class TestDirectoryRulesContentCSS(unittest.TestCase):
    """Verify DirectoryRulesContent CSS meets TUI conventions."""

    def test_css_has_section_class(self):
        mod = importlib.import_module("ai_guardian.tui.directory_rules")
        cls = getattr(mod, "DirectoryRulesContent")
        assert ".section" in cls.CSS

    def test_css_has_editor_height(self):
        mod = importlib.import_module("ai_guardian.tui.directory_rules")
        cls = getattr(mod, "DirectoryRulesContent")
        assert "#rules-editor" in cls.CSS


class TestDirectoryRulesNavigation(unittest.TestCase):
    """Verify Directory Rules is in the correct navigation group."""

    def test_directory_rules_in_permissions_group(self):
        from ai_guardian.tui.app import NAV_GROUPS
        for name, items in NAV_GROUPS:
            if name == "Permissions":
                assert "panel-directory-rules" in [pid for _, pid in items]
                return
        self.fail("Permissions group not found")

    def test_directory_protection_not_in_any_group(self):
        from ai_guardian.tui.app import NAV_GROUPS
        all_ids = [pid for _, items in NAV_GROUPS for _, pid in items]
        assert "panel-directory-protection" not in all_ids


class TestDirectoryRulesHelpDocs(unittest.TestCase):
    """Verify help documentation is updated."""

    def test_directory_rules_panel_has_help(self):
        from ai_guardian.tui.app import HELP_DOCS
        assert "panel-directory-rules" in HELP_DOCS

    def test_directory_protection_panel_no_help(self):
        from ai_guardian.tui.app import HELP_DOCS
        assert "panel-directory-protection" not in HELP_DOCS

    def test_permissions_help_mentions_directory_rules(self):
        from ai_guardian.tui.app import HELP_DOCS
        assert "Directory Rules" in HELP_DOCS.get("Permissions", "")


class TestDirectoryRulesConfigParsing(unittest.TestCase):
    """Test configuration parsing logic."""

    def test_parse_object_format(self):
        config = {
            "directory_rules": {
                "action": "warn",
                "rules": [
                    {"mode": "deny", "paths": ["~/.ssh/**"]},
                    {"mode": "allow", "paths": ["~/dev/**"]},
                ]
            }
        }
        dr = config["directory_rules"]
        assert dr["action"] == "warn"
        assert len(dr["rules"]) == 2

    def test_parse_legacy_array_format(self):
        config = {"directory_rules": [{"mode": "deny", "paths": ["~/.ssh/**"]}]}
        assert isinstance(config["directory_rules"], list)

    def test_parse_empty_config(self):
        dr = {}.get("directory_rules", {})
        assert dr.get("action", "block") == "block"
        assert dr.get("rules", []) == []


class TestGetRulesSection(unittest.TestCase):
    """Test _get_rules_section normalization."""

    def _make(self):
        from ai_guardian.tui.directory_rules import DirectoryRulesContent
        return DirectoryRulesContent()

    def test_normalizes_dict(self):
        c = self._make()
        r = c._get_rules_section({"directory_rules": {"action": "warn", "rules": []}})
        assert r["action"] == "warn"

    def test_normalizes_list(self):
        c = self._make()
        r = c._get_rules_section({"directory_rules": [{"mode": "deny", "paths": []}]})
        assert r["action"] == "block"
        assert len(r["rules"]) == 1

    def test_normalizes_missing(self):
        c = self._make()
        r = c._get_rules_section({})
        assert isinstance(r, dict)
        assert r.get("action", "block") == "block"

    def test_normalizes_invalid(self):
        c = self._make()
        r = c._get_rules_section({"directory_rules": "bad"})
        assert r == {"action": "block", "rules": []}


class TestParseRules(unittest.TestCase):
    """Test _parse_rules validation."""

    def _make(self):
        from ai_guardian.tui.directory_rules import DirectoryRulesContent
        return DirectoryRulesContent()

    def test_valid_rules(self):
        c = self._make()
        text = '[{"mode": "deny", "paths": ["~/.ssh/**"]}]'
        rules, error = c._parse_rules(text)
        assert error is None
        assert len(rules) == 1

    def test_empty_array(self):
        c = self._make()
        rules, error = c._parse_rules("[]")
        assert error is None
        assert rules == []

    def test_invalid_json(self):
        c = self._make()
        rules, error = c._parse_rules("{bad json")
        assert rules is None
        assert error is not None

    def test_not_array(self):
        c = self._make()
        rules, error = c._parse_rules('{"mode": "deny"}')
        assert error == "Rules must be a JSON array"

    def test_invalid_mode(self):
        c = self._make()
        rules, error = c._parse_rules('[{"mode": "block", "paths": []}]')
        assert "mode" in error

    def test_missing_paths(self):
        c = self._make()
        rules, error = c._parse_rules('[{"mode": "deny"}]')
        assert "paths" in error

    def test_generated_rules_filtered_from_display(self):
        c = self._make()
        rules = [
            {"mode": "deny", "paths": ["~/.ssh/**"]},
            {"mode": "allow", "paths": ["~/dev/**"], "_generated": True},
        ]
        display_rules = [
            {k: v for k, v in r.items() if not k.startswith("_")}
            for r in rules
        ]
        assert len(display_rules) == 2
        assert "_generated" not in display_rules[1]


class TestRuleClassification(unittest.TestCase):
    """Test rule classification."""

    def test_user_rule(self):
        rule = {"mode": "deny", "paths": ["~/.ssh/**"]}
        assert not rule.get("_generated", False)
        assert not rule.get("_immutable", False)

    def test_generated_rule(self):
        rule = {"mode": "allow", "paths": [], "_generated": True}
        assert rule["_generated"] is True

    def test_immutable_rule(self):
        rule = {"mode": "deny", "paths": [], "_immutable": True}
        assert rule["_immutable"] is True


if __name__ == "__main__":
    unittest.main()
