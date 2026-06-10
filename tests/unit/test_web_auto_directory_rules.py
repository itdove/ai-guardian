"""Tests for Web Console Auto Directory Rules page."""

import inspect
import json
import os
import tempfile
from unittest import mock

import pytest

pytest.importorskip("nicegui", reason="NiceGUI requires Python >= 3.10")


# ---------------------------------------------------------------------------
# Import / existence tests
# ---------------------------------------------------------------------------

class TestPageImport:
    """Verify the page module imports and exposes its create function."""

    def test_auto_directory_rules_page_exists(self):
        from ai_guardian.web.pages.auto_directory_rules import (
            create_auto_directory_rules_page,
        )
        assert callable(create_auto_directory_rules_page)

    def test_run_generator_helper_exists(self):
        from ai_guardian.web.pages.auto_directory_rules import _run_generator
        assert callable(_run_generator)


# ---------------------------------------------------------------------------
# Route / sidebar consistency
# ---------------------------------------------------------------------------

class TestRouteSidebarConsistency:
    """Verify the auto-directory-rules route is registered."""

    def test_route_registered_in_app(self):
        """Check that app.py registers the auto-directory-rules route."""
        from ai_guardian.web.app import WebConsole

        source = inspect.getsource(WebConsole._register_pages)
        assert "/auto-directory-rules" in source

    def test_route_in_sidebar(self):
        """Check that NAV_GROUPS includes the route."""
        from ai_guardian.web.components.header import NAV_GROUPS

        all_suffixes = [s for _, items in NAV_GROUPS for _, s in items]
        assert "/auto-directory-rules" in all_suffixes

    def test_sidebar_label(self):
        """Check the sidebar uses the correct label."""
        from ai_guardian.web.components.header import NAV_GROUPS

        all_labels = [lbl for _, items in NAV_GROUPS for lbl, _ in items]
        assert "Auto Directory Rules" in all_labels

    def test_sidebar_position(self):
        """Auto Directory Rules appears between Permissions Discovery and Directory Rules."""
        from ai_guardian.web.components.header import NAV_GROUPS

        flat = [(lbl, suffix) for _, items in NAV_GROUPS for lbl, suffix in items]
        suffixes = [s for _, s in flat]

        auto_idx = suffixes.index("/auto-directory-rules")
        perms_idx = suffixes.index("/permissions-discovery")
        dir_idx = suffixes.index("/directory-rules")

        assert perms_idx < auto_idx < dir_idx


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestRunGenerator:
    """Test the _run_generator helper function."""

    def test_empty_config_returns_empty(self):
        from ai_guardian.web.pages.auto_directory_rules import _run_generator

        result = _run_generator({})
        assert result["generated_rules"] == []
        assert result["skill_patterns"] == []
        assert result["error"] is None

    def test_disabled_with_isolated_dirs_returns_empty_rules(self):
        """When disabled, preview still extracts patterns but no rules are
        generated because _run_generator calls individual pipeline steps
        which discover real skills on the host.  Use explicit empty dir."""
        from ai_guardian.web.pages.auto_directory_rules import _run_generator

        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "permissions": {
                    "auto_directory_rules": {
                        "enabled": False,
                        "skill_directories": [tmpdir],
                    },
                    "rules": [
                        {"matcher": "Skill", "mode": "allow", "patterns": ["*"]},
                    ],
                }
            }
            result = _run_generator(config)
            assert result["generated_rules"] == []
            # Patterns are still extracted even when disabled
            assert result["skill_patterns"] == ["*"]
            assert result["error"] is None

    def test_no_skill_patterns_returns_empty(self):
        from ai_guardian.web.pages.auto_directory_rules import _run_generator

        config = {
            "permissions": {
                "auto_directory_rules": {"enabled": True},
                "rules": [
                    {"matcher": "Bash", "mode": "allow", "patterns": ["*"]},
                ],
            }
        }
        result = _run_generator(config)
        assert result["generated_rules"] == []
        assert result["skill_patterns"] == []
        assert result["error"] is None

    def test_extracts_skill_patterns(self):
        from ai_guardian.web.pages.auto_directory_rules import _run_generator

        config = {
            "permissions": {
                "auto_directory_rules": {"enabled": False},
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*", "release"],
                    },
                    {
                        "matcher": "Skill",
                        "mode": "deny",
                        "patterns": ["bad-*"],
                    },
                ],
            }
        }
        result = _run_generator(config)
        # Only allow patterns, not deny
        assert result["skill_patterns"] == ["daf-*", "release"]
        assert result["error"] is None

    def test_handles_missing_permissions(self):
        from ai_guardian.web.pages.auto_directory_rules import _run_generator

        result = _run_generator({"some_other_key": True})
        assert result["generated_rules"] == []
        assert result["skill_patterns"] == []
        assert result["error"] is None

    def test_discovers_skills_in_temp_dir(self):
        """Integration test: create temp skill dirs and verify discovery."""
        from ai_guardian.web.pages.auto_directory_rules import _run_generator

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake skill directories
            skill_dir = os.path.join(tmpdir, "skills")
            os.makedirs(os.path.join(skill_dir, "my-skill"))
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
                            "patterns": ["my-*"],
                        },
                    ],
                }
            }
            result = _run_generator(config)
            assert "my-skill" in result["discovered_skills"]
            assert "other-skill" in result["discovered_skills"]
            assert "my-skill" in result["matched_skills"]
            assert "other-skill" not in result["matched_skills"]
            assert len(result["generated_rules"]) > 0
            assert result["error"] is None

    def test_error_handling_invalid_permissions(self):
        """Generator handles invalid config gracefully (no crash)."""
        from ai_guardian.web.pages.auto_directory_rules import _run_generator

        # Passing garbage config should not raise
        result = _run_generator({"permissions": "invalid"})
        assert isinstance(result, dict)
        assert "generated_rules" in result
        # Should have an error message since "invalid" is not a dict
        assert result["error"] is not None or result["generated_rules"] == []

    def test_error_handling_import_error(self):
        """Generator returns error info when DirectoryRuleGenerator is unavailable."""
        from ai_guardian.web.pages.auto_directory_rules import _run_generator

        with mock.patch.dict(
            "sys.modules",
            {"ai_guardian.directory_rule_generator": None},
        ):
            result = _run_generator({"permissions": {"auto_directory_rules": {"enabled": True}}})
            assert isinstance(result, dict)
            assert result["error"] is not None or result["generated_rules"] == []
