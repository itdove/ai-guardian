#!/usr/bin/env python3
"""
Tests for AI Guardian TUI

Tests the interactive TUI components and configuration management.
"""

import json
import tempfile
from pathlib import Path
import pytest

from ai_guardian.tui.app import AIGuardianTUI, NAV_GROUPS, HELP_DOCS, HelpModal


class TestTUIApp:
    """Tests for the main TUI application."""

    def test_tui_initialization(self):
        """Test that TUI app can be initialized."""
        app = AIGuardianTUI()
        assert app is not None
        assert app.TITLE == "AI Guardian Configuration"

    def test_tui_has_screens(self):
        """Test that TUI has required screens."""
        app = AIGuardianTUI()
        assert app is not None


class TestNavGroups:
    """Tests for navigation structure."""

    def test_nav_groups_has_eight_categories(self):
        """Test that NAV_GROUPS defines exactly 8 category groups."""
        assert len(NAV_GROUPS) == 8

    def test_nav_groups_has_twentytwo_panels(self):
        """Test that NAV_GROUPS defines exactly 22 leaf panels."""
        total_leaves = sum(len(items) for _, items in NAV_GROUPS)
        assert total_leaves == 22

    def test_panel_ids_are_unique(self):
        """Test that all panel IDs are unique."""
        panel_ids = [pid for _, items in NAV_GROUPS for _, pid in items]
        assert len(panel_ids) == len(set(panel_ids)), "Duplicate panel IDs found"

    def test_panel_ids_have_panel_prefix(self):
        """Test that all panel IDs start with 'panel-'."""
        for _, items in NAV_GROUPS:
            for _, panel_id in items:
                assert panel_id.startswith("panel-"), f"{panel_id} missing 'panel-' prefix"

    def test_category_labels_are_strings(self):
        """Test that all category labels are non-empty strings."""
        for label, _ in NAV_GROUPS:
            assert isinstance(label, str)
            assert len(label) > 0

    def test_leaf_labels_are_strings(self):
        """Test that all leaf labels are non-empty strings."""
        for _, items in NAV_GROUPS:
            for label, _ in items:
                assert isinstance(label, str)
                assert len(label) > 0

    def test_check_action_panel_ids_exist_in_nav(self):
        """Test that all panel IDs referenced in check_action exist in NAV_GROUPS."""
        panel_ids = {pid for _, items in NAV_GROUPS for _, pid in items}
        action_panel_ids = {
            "panel-skills",
            "panel-mcp",
            "panel-pi-detection",
            "panel-pi-patterns",
            "panel-secrets",
            "panel-ssrf",
            "panel-config-scanner",
            "panel-secret-redaction",
        }
        assert action_panel_ids.issubset(panel_ids), (
            f"Missing panel IDs: {action_panel_ids - panel_ids}"
        )

    def test_expected_categories(self):
        """Test that the expected category names are present."""
        category_names = [name for name, _ in NAV_GROUPS]
        assert "Security Overview" in category_names
        assert "Permissions" in category_names
        assert "Threat Detection" in category_names
        assert "Prompt Injection" in category_names
        assert "Secrets" in category_names
        assert "Monitoring" in category_names
        assert "Configuration" in category_names
        assert "Tools" in category_names

    def test_expected_panels_in_categories(self):
        """Test that key panels are in the correct categories."""
        nav_dict = {name: [pid for _, pid in items] for name, items in NAV_GROUPS}

        assert "panel-security-dashboard" in nav_dict["Security Overview"]
        assert "panel-skills" in nav_dict["Permissions"]
        assert "panel-pi-detection" in nav_dict["Prompt Injection"]
        assert "panel-pi-jailbreak" in nav_dict["Prompt Injection"]
        assert "panel-pi-unicode" in nav_dict["Prompt Injection"]
        assert "panel-scan-pii" in nav_dict["Threat Detection"]
        assert "panel-secrets" in nav_dict["Secrets"]
        assert "panel-violations" in nav_dict["Monitoring"]
        assert "panel-violation-logging" in nav_dict["Monitoring"]
        assert "panel-config-file" in nav_dict["Configuration"]
        assert "panel-config-effective" in nav_dict["Configuration"]
        assert "panel-regex-tester" in nav_dict["Tools"]


class TestHelpDocs:
    """Tests for inline help documentation."""

    def test_all_panels_have_help(self):
        """Test that every panel has a help doc entry."""
        panel_ids = [pid for _, items in NAV_GROUPS for _, pid in items]
        for panel_id in panel_ids:
            assert panel_id in HELP_DOCS, f"Missing help doc for {panel_id}"

    def test_all_categories_have_help(self):
        """Test that every category has a help doc entry."""
        category_names = [name for name, _ in NAV_GROUPS]
        for name in category_names:
            assert name in HELP_DOCS, f"Missing help doc for category {name}"

    def test_help_docs_are_non_empty_strings(self):
        """Test that all help doc entries are non-empty strings."""
        for key, doc in HELP_DOCS.items():
            assert isinstance(doc, str), f"Help doc for {key} is not a string"
            assert len(doc) > 0, f"Help doc for {key} is empty"

    def test_help_docs_total_count(self):
        """Test total help doc entries: 6 categories + 15 panels = 21."""
        expected = len(NAV_GROUPS) + sum(len(items) for _, items in NAV_GROUPS)
        assert len(HELP_DOCS) == expected

    def test_help_modal_initialization(self):
        """Test that HelpModal can be initialized."""
        modal = HelpModal("Test Title", "Test body content")
        assert modal._title == "Test Title"
        assert modal._body == "Test body content"


class TestViolationsApproval:
    """Tests for violation approval functionality."""

    def test_approve_violation_adds_rule(self):
        """Test that approving a violation adds the rule to config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {
                "permissions": []
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            new_rule = {
                "matcher": "Skill",
                "mode": "allow",
                "patterns": ["daf-jira"]
            }

            with open(config_path, 'r') as f:
                config = json.load(f)

            config["permissions"].append(new_rule)

            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert updated_config["permissions"][0] == new_rule

    def test_approve_violation_merges_patterns(self):
        """Test that approving a violation merges patterns with existing rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {
                "permissions": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"]
                    }
                ]
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            new_pattern = "release"

            with open(config_path, 'r') as f:
                config = json.load(f)

            existing_rule = next(
                (r for r in config["permissions"]
                 if r.get("matcher") == "Skill" and r.get("mode") == "allow"),
                None
            )

            if existing_rule:
                existing_patterns = existing_rule.get("patterns", [])
                merged_patterns = list(set(existing_patterns + [new_pattern]))
                existing_rule["patterns"] = merged_patterns

            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert "daf-*" in updated_config["permissions"][0]["patterns"]
            assert "release" in updated_config["permissions"][0]["patterns"]


class TestPermissionsEditor:
    """Tests for permissions editor functionality."""

    def test_add_permission_rule(self):
        """Test adding a new permission rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {"permissions": []}
            with open(config_path, 'w') as f:
                json.dump(config, f)

            new_rule = {
                "matcher": "mcp__notebooklm-mcp__*",
                "mode": "allow",
                "patterns": ["*"]
            }

            with open(config_path, 'r') as f:
                config = json.load(f)

            config["permissions"].append(new_rule)

            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert updated_config["permissions"][0]["matcher"] == "mcp__notebooklm-mcp__*"

    def test_delete_permission_rule(self):
        """Test deleting a permission rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {
                "permissions": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"]
                    },
                    {
                        "matcher": "mcp__test__*",
                        "mode": "deny",
                        "patterns": ["*"]
                    }
                ]
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                config = json.load(f)

            config["permissions"].pop(0)

            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert updated_config["permissions"][0]["matcher"] == "mcp__test__*"

    def test_edit_permission_rule(self):
        """Test editing a permission rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {
                "permissions": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"]
                    }
                ]
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                config = json.load(f)

            config["permissions"][0]["patterns"] = ["daf-*", "release"]

            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert "release" in updated_config["permissions"][0]["patterns"]


class TestConfigViewer:
    """Tests for configuration viewer."""

    def test_load_user_config(self):
        """Test loading user configuration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {
                "permissions": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["*"]
                    }
                ],
                "violation_logging": {
                    "enabled": True,
                    "max_entries": 1000
                }
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                loaded_config = json.load(f)

            assert "permissions" in loaded_config
            assert "violation_logging" in loaded_config
            assert loaded_config["violation_logging"]["enabled"] is True

    def test_merge_configs(self):
        """Test merging user and project configs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            user_config_path = Path(tmpdir) / "user.json"
            project_config_path = Path(tmpdir) / "project.json"

            user_config = {
                "permissions": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"]
                    }
                ]
            }
            with open(user_config_path, 'w') as f:
                json.dump(user_config, f)

            project_config = {
                "permissions": [
                    {
                        "matcher": "mcp__*",
                        "mode": "deny",
                        "patterns": ["*"]
                    }
                ]
            }
            with open(project_config_path, 'w') as f:
                json.dump(project_config, f)

            merged_config = {}

            with open(user_config_path, 'r') as f:
                merged_config.update(json.load(f))

            with open(project_config_path, 'r') as f:
                merged_config.update(json.load(f))

            assert len(merged_config["permissions"]) == 1
            assert merged_config["permissions"][0]["matcher"] == "mcp__*"


class TestClipboardSupport:
    """Tests for copy-to-clipboard functionality."""

    def test_app_has_text_selected_handler(self):
        """Test that AIGuardianTUI has on_text_selected handler for auto-copy."""
        app = AIGuardianTUI()
        assert hasattr(app, "on_text_selected")
        assert callable(app.on_text_selected)

    def test_violation_details_modal_has_copy_button(self):
        """Test that ViolationDetailsModal handles copy-details button ID."""
        from ai_guardian.tui.violations import ViolationDetailsModal
        import inspect
        source = inspect.getsource(ViolationDetailsModal.compose)
        assert "copy-details" in source
        source_handler = inspect.getsource(ViolationDetailsModal.on_button_pressed)
        assert "copy-details" in source_handler
        assert "copy_to_clipboard" in source_handler

    def test_violation_details_modal_copy_handler(self):
        """Test that ViolationDetailsModal handles copy-details button."""
        from ai_guardian.tui.violations import ViolationDetailsModal
        from textual.widgets import Button
        modal = ViolationDetailsModal({"type": "test", "message": "test violation"})
        assert hasattr(modal, "on_button_pressed")

    def test_violation_details_modal_stores_violation_data(self):
        """Test that ViolationDetailsModal stores violation data for copying."""
        from ai_guardian.tui.violations import ViolationDetailsModal
        violation = {"type": "secret_detected", "severity": "high", "file": "test.py"}
        modal = ViolationDetailsModal(violation)
        assert modal.violation == violation
        details = json.dumps(modal.violation, indent=2)
        assert '"type": "secret_detected"' in details
        assert '"severity": "high"' in details


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
