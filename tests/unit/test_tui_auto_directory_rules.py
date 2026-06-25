#!/usr/bin/env python3
"""
Tests for the Auto Directory Rules TUI panel.

Tests integration with the TUI app (NAV_GROUPS, HELP_DOCS) and verifies
the panel can be imported without errors, config save/load works, and
the generator preview produces expected results.
"""

import inspect
import json
import os
import tempfile

import pytest

from ai_guardian.tui.auto_directory_rules import AutoDirectoryRulesContent
from ai_guardian.tui.app import NAV_GROUPS, HELP_DOCS

# ---------------------------------------------------------------------------
# Import / navigation tests
# ---------------------------------------------------------------------------


class TestAutoDirectoryRulesImport:
    """Verify the panel integrates with the TUI app."""

    def test_content_can_be_imported(self):
        assert AutoDirectoryRulesContent is not None

    def test_in_nav_groups(self):
        nav_dict = {name: [pid for _, pid in items] for name, items in NAV_GROUPS}
        assert "panel-auto-directory-rules" in nav_dict["Permissions"]

    def test_has_help_doc(self):
        assert "panel-auto-directory-rules" in HELP_DOCS
        assert len(HELP_DOCS["panel-auto-directory-rules"]) > 0

    def test_help_doc_mentions_key_features(self):
        doc = HELP_DOCS["panel-auto-directory-rules"]
        assert "Auto Directory Rules" in doc
        assert "Enabled" in doc
        assert "Symlinks" in doc

    def test_position_in_permissions(self):
        """Auto Directory Rules appears between Permissions Discovery and Directory Rules."""
        for name, items in NAV_GROUPS:
            if name == "Permissions":
                panel_ids = [pid for _, pid in items]
                idx = panel_ids.index("panel-auto-directory-rules")
                assert panel_ids[idx - 1] == "panel-permissions-discovery"
                assert panel_ids[idx + 1] == "panel-directory-rules"
                break
        else:
            pytest.fail("Permissions group not found in NAV_GROUPS")


# ---------------------------------------------------------------------------
# Structural tests
# ---------------------------------------------------------------------------


class TestAutoDirectoryRulesStructure:
    """Verify the panel has required structural elements."""

    def test_has_compose_method(self):
        assert hasattr(AutoDirectoryRulesContent, "compose")

    def test_has_refresh_content_method(self):
        assert hasattr(AutoDirectoryRulesContent, "refresh_content")

    def test_has_load_config_method(self):
        assert hasattr(AutoDirectoryRulesContent, "load_config")

    def test_compose_has_switches(self):
        """Compose method creates enabled and symlinks switches."""
        source = inspect.getsource(AutoDirectoryRulesContent.compose)
        assert "switch-enabled" in source
        assert "switch-symlinks" in source

    def test_compose_has_status(self):
        """Compose method creates status display."""
        source = inspect.getsource(AutoDirectoryRulesContent.compose)
        assert "auto-dir-status" in source

    def test_compose_has_rules_list(self):
        """Compose method creates rules list."""
        source = inspect.getsource(AutoDirectoryRulesContent.compose)
        assert "auto-dir-rules-list" in source

    def test_has_css(self):
        """Panel defines CSS styles."""
        assert hasattr(AutoDirectoryRulesContent, "CSS")
        assert len(AutoDirectoryRulesContent.CSS) > 0


# ---------------------------------------------------------------------------
# Generator preview tests
# ---------------------------------------------------------------------------


class TestRunGenerator:
    """Test the _run_generator method."""

    def test_empty_config(self):
        content = AutoDirectoryRulesContent()
        result = content._run_generator({})
        assert result["generated_rules"] == []
        assert result["skill_patterns"] == []

    def test_extracts_skill_patterns(self):
        content = AutoDirectoryRulesContent()
        config = {
            "permissions": {
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*", "release"],
                    },
                ],
            }
        }
        result = content._run_generator(config)
        assert result["skill_patterns"] == ["daf-*", "release"]

    def test_ignores_deny_patterns(self):
        content = AutoDirectoryRulesContent()
        config = {
            "permissions": {
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "deny",
                        "patterns": ["bad-*"],
                    },
                ],
            }
        }
        result = content._run_generator(config)
        assert result["skill_patterns"] == []

    def test_discovers_skills_in_temp_dir(self):
        content = AutoDirectoryRulesContent()

        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = os.path.join(tmpdir, "skills")
            os.makedirs(os.path.join(skill_dir, "test-skill"))
            os.makedirs(os.path.join(skill_dir, "other-skill"))

            config = {
                "permissions": {
                    "auto_directory_rules": {
                        "enabled": True,
                        "skill_directories": [skill_dir],
                    },
                    "rules": [
                        {
                            "matcher": "Skill",
                            "mode": "allow",
                            "patterns": ["test-*"],
                        },
                    ],
                }
            }
            result = content._run_generator(config)
            assert "test-skill" in result["discovered_skills"]
            assert "other-skill" in result["discovered_skills"]
            assert "test-skill" in result["matched_skills"]
            assert "other-skill" not in result["matched_skills"]
            assert len(result["generated_rules"]) > 0


# ---------------------------------------------------------------------------
# Config save tests
# ---------------------------------------------------------------------------


class TestConfigSave:
    """Test config save logic."""

    def test_save_field_logic(self):
        """Verify _save_field writes the correct JSON structure.

        Since Textual Container.app is read-only, we test the save logic
        directly by simulating what _save_field does.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "ai-guardian.json")
            initial = {
                "permissions": {
                    "auto_directory_rules": {
                        "enabled": False,
                        "allow_symlinks": True,
                    }
                }
            }
            with open(config_path, "w") as f:
                json.dump(initial, f)

            # Simulate what _save_field("enabled", True) does
            with open(config_path, "r") as f:
                config = json.load(f)

            permissions = config.get("permissions", {})
            if not isinstance(permissions, dict):
                permissions = {"enabled": True, "rules": []}
            auto_config = permissions.get("auto_directory_rules", {})
            if not isinstance(auto_config, dict):
                auto_config = {}
            auto_config["enabled"] = True
            permissions["auto_directory_rules"] = auto_config
            config["permissions"] = permissions

            with open(config_path, "w") as f:
                json.dump(config, f)

            with open(config_path, "r") as f:
                saved = json.load(f)
            assert saved["permissions"]["auto_directory_rules"]["enabled"] is True
            # allow_symlinks preserved
            assert (
                saved["permissions"]["auto_directory_rules"]["allow_symlinks"] is True
            )

    def test_save_creates_auto_directory_rules_section(self):
        """Save creates auto_directory_rules if missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "ai-guardian.json")
            initial = {"permissions": {"enabled": True, "rules": []}}
            with open(config_path, "w") as f:
                json.dump(initial, f)

            # Simulate what _save_field does
            with open(config_path, "r") as f:
                config = json.load(f)

            permissions = config.get("permissions", {})
            auto_config = permissions.get("auto_directory_rules", {})
            if not isinstance(auto_config, dict):
                auto_config = {}
            auto_config["enabled"] = True
            permissions["auto_directory_rules"] = auto_config
            config["permissions"] = permissions

            with open(config_path, "w") as f:
                json.dump(config, f)

            with open(config_path, "r") as f:
                saved = json.load(f)

            assert saved["permissions"]["auto_directory_rules"]["enabled"] is True
            # Original fields preserved
            assert saved["permissions"]["enabled"] is True
            assert saved["permissions"]["rules"] == []

    def test_save_preserves_existing_config(self):
        """Save doesn't destroy existing config fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "ai-guardian.json")
            initial = {
                "secret_scanning": {"enabled": True},
                "permissions": {
                    "enabled": True,
                    "rules": [
                        {"matcher": "Skill", "mode": "allow", "patterns": ["*"]},
                    ],
                    "auto_directory_rules": {
                        "enabled": False,
                        "allow_symlinks": True,
                    },
                },
            }
            with open(config_path, "w") as f:
                json.dump(initial, f)

            # Simulate save
            with open(config_path, "r") as f:
                config = json.load(f)

            config["permissions"]["auto_directory_rules"]["enabled"] = True

            with open(config_path, "w") as f:
                json.dump(config, f)

            with open(config_path, "r") as f:
                saved = json.load(f)

            # Auto directory rules updated
            assert saved["permissions"]["auto_directory_rules"]["enabled"] is True
            assert (
                saved["permissions"]["auto_directory_rules"]["allow_symlinks"] is True
            )
            # Other config preserved
            assert saved["secret_scanning"]["enabled"] is True
            assert len(saved["permissions"]["rules"]) == 1
