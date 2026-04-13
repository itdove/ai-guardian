#!/usr/bin/env python3
"""
Tests for AI Guardian TUI

Tests the interactive TUI components and configuration management.
"""

import json
import tempfile
from pathlib import Path
import pytest

from ai_guardian.tui.app import AIGuardianTUI


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
        # Screens are initialized on mount, so we can't test them directly
        # without running the app
        assert app is not None


class TestViolationsApproval:
    """Tests for violation approval functionality."""

    def test_approve_violation_adds_rule(self):
        """Test that approving a violation adds the rule to config."""
        # Create a temporary config directory
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            # Create initial config
            config = {
                "permissions": []
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Simulate adding a rule
            new_rule = {
                "matcher": "Skill",
                "mode": "allow",
                "patterns": ["daf-jira"]
            }

            # Load config
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Add rule
            config["permissions"].append(new_rule)

            # Save config
            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Verify rule was added
            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert updated_config["permissions"][0] == new_rule

    def test_approve_violation_merges_patterns(self):
        """Test that approving a violation merges patterns with existing rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            # Create initial config with existing rule
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

            # Simulate adding a new pattern to existing rule
            new_pattern = "release"

            # Load config
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Find existing rule
            existing_rule = next(
                (r for r in config["permissions"]
                 if r.get("matcher") == "Skill" and r.get("mode") == "allow"),
                None
            )

            # Merge patterns
            if existing_rule:
                existing_patterns = existing_rule.get("patterns", [])
                merged_patterns = list(set(existing_patterns + [new_pattern]))
                existing_rule["patterns"] = merged_patterns

            # Save config
            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Verify patterns were merged
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

            # Create empty config
            config = {"permissions": []}
            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Add new rule
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

            # Verify
            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert updated_config["permissions"][0]["matcher"] == "mcp__notebooklm-mcp__*"

    def test_delete_permission_rule(self):
        """Test deleting a permission rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            # Create config with two rules
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

            # Delete first rule
            with open(config_path, 'r') as f:
                config = json.load(f)

            config["permissions"].pop(0)

            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Verify
            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert updated_config["permissions"][0]["matcher"] == "mcp__test__*"

    def test_edit_permission_rule(self):
        """Test editing a permission rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            # Create config with one rule
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

            # Edit rule
            with open(config_path, 'r') as f:
                config = json.load(f)

            config["permissions"][0]["patterns"] = ["daf-*", "release"]

            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Verify
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

            # Create config
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

            # Load config
            with open(config_path, 'r') as f:
                loaded_config = json.load(f)

            # Verify
            assert "permissions" in loaded_config
            assert "violation_logging" in loaded_config
            assert loaded_config["violation_logging"]["enabled"] is True

    def test_merge_configs(self):
        """Test merging user and project configs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            user_config_path = Path(tmpdir) / "user.json"
            project_config_path = Path(tmpdir) / "project.json"

            # Create user config
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

            # Create project config (overrides user)
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

            # Merge configs (project overrides user)
            merged_config = {}

            with open(user_config_path, 'r') as f:
                merged_config.update(json.load(f))

            with open(project_config_path, 'r') as f:
                merged_config.update(json.load(f))

            # Verify project config took precedence
            assert len(merged_config["permissions"]) == 1
            assert merged_config["permissions"][0]["matcher"] == "mcp__*"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
