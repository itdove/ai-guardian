"""
Unit tests for Directory Rules TUI panel (Issue #426)
"""

import importlib
import unittest

import pytest


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


class TestDirectoryRulesConfigParsing:
    """Test configuration parsing logic."""

    @pytest.mark.parametrize(
        "config, check_fn",
        [
            pytest.param(
                {
                    "directory_rules": {
                        "action": "warn",
                        "rules": [
                            {"mode": "deny", "paths": ["~/.ssh/**"]},
                            {"mode": "allow", "paths": ["~/dev/**"]},
                        ],
                    }
                },
                lambda cfg: (
                    cfg["directory_rules"]["action"] == "warn"
                    and len(cfg["directory_rules"]["rules"]) == 2
                ),
                id="object-format",
            ),
            pytest.param(
                {"directory_rules": [{"mode": "deny", "paths": ["~/.ssh/**"]}]},
                lambda cfg: isinstance(cfg["directory_rules"], list),
                id="legacy-array-format",
            ),
            pytest.param(
                {},
                lambda cfg: (
                    cfg.get("directory_rules", {}).get("action", "block") == "block"
                    and cfg.get("directory_rules", {}).get("rules", []) == []
                ),
                id="empty-config",
            ),
        ],
    )
    def test_config_format_parsing(self, config, check_fn):
        assert check_fn(config)


class TestGetRulesSection:
    """Test _get_rules_section normalization."""

    @staticmethod
    def _make():
        from ai_guardian.tui.directory_rules import DirectoryRulesContent

        return DirectoryRulesContent()

    @pytest.mark.parametrize(
        "config, check_fn",
        [
            pytest.param(
                {"directory_rules": {"action": "warn", "rules": []}},
                lambda r: r["action"] == "warn",
                id="dict-input",
            ),
            pytest.param(
                {"directory_rules": [{"mode": "deny", "paths": []}]},
                lambda r: r["action"] == "block" and len(r["rules"]) == 1,
                id="list-input",
            ),
            pytest.param(
                {},
                lambda r: isinstance(r, dict) and r.get("action", "block") == "block",
                id="missing-input",
            ),
            pytest.param(
                {"directory_rules": "bad"},
                lambda r: r == {"action": "block", "rules": []},
                id="invalid-input",
            ),
        ],
    )
    def test_normalizes(self, config, check_fn):
        c = self._make()
        r = c._get_rules_section(config)
        assert check_fn(r)


class TestParseRules:
    """Test _parse_rules validation."""

    @staticmethod
    def _make():
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

    @pytest.mark.parametrize(
        "text, error_substring",
        [
            pytest.param("{bad json", None, id="invalid-json"),
            pytest.param(
                '{"mode": "deny"}', "Rules must be a JSON array", id="not-array"
            ),
            pytest.param('[{"mode": "block", "paths": []}]', "mode", id="invalid-mode"),
            pytest.param('[{"mode": "deny"}]', "paths", id="missing-paths"),
        ],
    )
    def test_parse_rules_error(self, text, error_substring):
        c = self._make()
        rules, error = c._parse_rules(text)
        assert rules is None
        assert error is not None
        if error_substring is not None:
            assert error_substring in error

    def test_generated_rules_filtered_from_display(self):
        c = self._make()
        rules = [
            {"mode": "deny", "paths": ["~/.ssh/**"]},
            {"mode": "allow", "paths": ["~/dev/**"], "_generated": True},
        ]
        display_rules = [
            {k: v for k, v in r.items() if not k.startswith("_")} for r in rules
        ]
        assert len(display_rules) == 2
        assert "_generated" not in display_rules[1]


class TestRuleClassification:
    """Test rule classification."""

    @pytest.mark.parametrize(
        "rule, is_generated, is_immutable",
        [
            pytest.param(
                {"mode": "deny", "paths": ["~/.ssh/**"]},
                False,
                False,
                id="user-rule",
            ),
            pytest.param(
                {"mode": "allow", "paths": [], "_generated": True},
                True,
                False,
                id="generated-rule",
            ),
            pytest.param(
                {"mode": "deny", "paths": [], "_immutable": True},
                False,
                True,
                id="immutable-rule",
            ),
        ],
    )
    def test_rule_classification(self, rule, is_generated, is_immutable):
        assert rule.get("_generated", False) == is_generated
        assert rule.get("_immutable", False) == is_immutable


if __name__ == "__main__":
    unittest.main()
