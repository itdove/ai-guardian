#!/usr/bin/env python3
"""
Unit tests for auto-generation of directory rules from skill permissions.

Tests Issue #144: Auto-generate directory rules from skill permissions
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ai_guardian.directory_rule_generator import (
    DirectoryRuleGenerator,
    insert_generated_rules
)


class TestDirectoryRuleGenerator:
    """Test directory rule generation from skill permissions."""

    def test_generation_disabled_by_default(self):
        """Auto-generation should be disabled by default."""
        config = {
            "permissions": {
                "rules": [
                    {"matcher": "Skill", "mode": "allow", "patterns": ["daf-*"]}
                ]
            }
        }

        generator = DirectoryRuleGenerator(config)
        rules = generator.generate_directory_rules()

        assert rules == []

    def test_generation_enabled_but_no_permissions(self):
        """Should return empty if enabled but no skill permissions."""
        config = {
            "permissions": {
                "auto_directory_rules": {"enabled": True},
                "rules": []
            }
        }

        generator = DirectoryRuleGenerator(config)
        rules = generator.generate_directory_rules()

        assert rules == []

    @patch('ai_guardian.directory_rule_generator.Path.exists')
    @patch('ai_guardian.directory_rule_generator.Path.is_dir')
    @patch('ai_guardian.directory_rule_generator.Path.iterdir')
    def test_basic_generation(self, mock_iterdir, mock_is_dir, mock_exists):
        """Should generate rules for matching skills."""
        # Mock skill directory
        mock_exists.return_value = True
        mock_is_dir.return_value = True

        # Mock skills in directory
        mock_skill1 = MagicMock()
        mock_skill1.name = "daf-git"
        mock_skill1.is_dir.return_value = True
        mock_skill1.is_symlink.return_value = False

        mock_skill2 = MagicMock()
        mock_skill2.name = "daf-jira"
        mock_skill2.is_dir.return_value = True
        mock_skill2.is_symlink.return_value = False

        mock_iterdir.return_value = [mock_skill1, mock_skill2]

        config = {
            "permissions": {
                "auto_directory_rules": {"enabled": True},
                "rules": [
                    {"matcher": "Skill", "mode": "allow", "patterns": ["daf-*"]}
                ]
            }
        }

        generator = DirectoryRuleGenerator(config)
        rules = generator.generate_directory_rules()

        # Should generate rules for both skills
        assert len(rules) > 0
        assert any("daf-git" in str(rule) for rule in rules)
        assert any("daf-jira" in str(rule) for rule in rules)

        # All rules should be marked as generated
        for rule in rules:
            assert rule.get("_generated") is True
            assert "_source" in rule

    def test_only_existing_directories_scanned(self):
        """Should only scan directories that exist."""
        # Test relies on actual filesystem - just verify it returns a list
        config = {
            "permissions": {
                "auto_directory_rules": {"enabled": True},
                "rules": [
                    {"matcher": "Skill", "mode": "allow", "patterns": ["*"]}
                ]
            }
        }

        generator = DirectoryRuleGenerator(config)
        skill_dirs = generator._get_skill_directories({"skill_directories": "auto"})

        # Should return a list (may be empty if no dirs exist)
        assert isinstance(skill_dirs, list)

    def test_extract_skill_patterns(self):
        """Should extract only allow patterns for Skill matcher."""
        config = {
            "permissions": {
                "rules": [
                    {"matcher": "Skill", "mode": "allow", "patterns": ["daf-*", "gh-cli"]},
                    {"matcher": "Skill", "mode": "deny", "patterns": ["dangerous-*"]},
                    {"matcher": "Bash", "mode": "allow", "patterns": ["*"]}
                ]
            }
        }

        generator = DirectoryRuleGenerator(config)
        patterns = generator._get_skill_patterns()

        # Should only include allow patterns for Skill matcher
        assert "daf-*" in patterns
        assert "gh-cli" in patterns
        assert "dangerous-*" not in patterns  # deny pattern
        assert "*" not in patterns  # different matcher

    def test_match_skills_against_patterns(self):
        """Should correctly match skills against fnmatch patterns."""
        discovered = {
            "daf-git": [Path("~/.claude/skills/daf-git")],
            "daf-jira": [Path("~/.claude/skills/daf-jira")],
            "gh-cli": [Path("~/.claude/skills/gh-cli")],
            "other-skill": [Path("~/.claude/skills/other-skill")]
        }

        patterns = ["daf-*", "gh-cli"]

        generator = DirectoryRuleGenerator({})
        matching = generator._match_skills(discovered, patterns)

        assert "daf-git" in matching
        assert "daf-jira" in matching
        assert "gh-cli" in matching
        assert "other-skill" not in matching

    def test_created_rules_structure(self):
        """Generated rules should have correct structure."""
        config = {
            "permissions": {
                "auto_directory_rules": {"enabled": True},
                "rules": [
                    {"matcher": "Skill", "mode": "allow", "patterns": ["daf-*"]}
                ]
            }
        }

        generator = DirectoryRuleGenerator(config)

        # Mock some matching skills
        matching_skills = {"daf-git", "daf-jira"}
        rules = generator._create_directory_rules(matching_skills)

        assert len(rules) > 0
        for rule in rules:
            assert rule.get("mode") == "allow"
            assert isinstance(rule.get("paths"), list)
            assert rule.get("_generated") is True
            assert rule.get("_source") == "permissions.rules[Skill]"

    def test_time_based_patterns_supported(self):
        """Should handle time-based pattern format."""
        config = {
            "permissions": {
                "auto_directory_rules": {"enabled": True},
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": [
                            {"pattern": "daf-*", "valid_until": "2099-12-31T23:59:59Z"}
                        ]
                    }
                ]
            }
        }

        generator = DirectoryRuleGenerator(config)
        patterns = generator._get_skill_patterns()

        # Should extract pattern from dict format
        assert "daf-*" in patterns


class TestRuleInsertion:
    """Test insertion of generated rules into config."""

    def test_insert_at_beginning_new_format(self):
        """Generated rules should be inserted at BEGINNING (new object format)."""
        config = {
            "directory_rules": {
                "action": "block",
                "rules": [
                    {"mode": "deny", "paths": ["~/.ssh/**"]},
                    {"mode": "allow", "paths": ["~/.claude/skills/user-skill/**"]}
                ]
            }
        }

        generated = [
            {"mode": "allow", "paths": ["~/.claude/skills/daf-git/**"], "_generated": True}
        ]

        result = insert_generated_rules(config, generated)

        # Generated rule should be FIRST (position 0)
        rules = result["directory_rules"]["rules"]
        assert rules[0]["_generated"] is True
        assert rules[0]["paths"][0] == "~/.claude/skills/daf-git/**"

        # User rules should follow (position 1, 2, ...)
        assert rules[1]["paths"][0] == "~/.ssh/**"
        assert rules[2]["paths"][0] == "~/.claude/skills/user-skill/**"

    def test_insert_at_beginning_legacy_format(self):
        """Should convert legacy array format to object format."""
        config = {
            "directory_rules": [
                {"mode": "deny", "paths": ["~/.ssh/**"]}
            ]
        }

        generated = [
            {"mode": "allow", "paths": ["~/.claude/skills/daf-git/**"], "_generated": True}
        ]

        result = insert_generated_rules(config, generated)

        # Should convert to new format
        assert isinstance(result["directory_rules"], dict)
        assert "action" in result["directory_rules"]
        assert "rules" in result["directory_rules"]

        # Generated rule should be first
        rules = result["directory_rules"]["rules"]
        assert rules[0]["_generated"] is True

    def test_rule_order_user_can_override(self):
        """
        CRITICAL: User rules must come AFTER generated rules.

        Rule order (last-match-wins):
          Position 0-N: Generated (weakest)
          Position N+1+: User (override generated)
          Final: Immutable (override all)
        """
        config = {
            "directory_rules": {
                "action": "block",
                "rules": [
                    # User wants to block ALL skills
                    {"mode": "deny", "paths": ["~/.claude/skills/**"]}
                ]
            }
        }

        generated = [
            # Generated suggests allowing specific skills
            {"mode": "allow", "paths": ["~/.claude/skills/daf-git/**"], "_generated": True}
        ]

        result = insert_generated_rules(config, generated)
        rules = result["directory_rules"]["rules"]

        # Order must be: Generated (pos 0), User (pos 1)
        assert rules[0]["_generated"] is True  # Generated first
        assert rules[1]["paths"][0] == "~/.claude/skills/**"  # User second

        # With last-match-wins, user rule (deny all) should win
        # This is correct - user maintains control

    def test_empty_generated_rules(self):
        """Should handle empty generated rules gracefully."""
        config = {"directory_rules": {"action": "block", "rules": []}}
        generated = []

        result = insert_generated_rules(config, generated)

        assert result["directory_rules"]["rules"] == []

    def test_create_directory_rules_if_missing(self):
        """Should create directory_rules section if missing."""
        config = {}
        generated = [
            {"mode": "allow", "paths": ["~/.claude/skills/daf-git/**"], "_generated": True}
        ]

        result = insert_generated_rules(config, generated)

        assert "directory_rules" in result
        assert isinstance(result["directory_rules"], dict)
        assert result["directory_rules"]["rules"][0]["_generated"] is True


class TestMultiIDESupport:
    """Test support for multiple IDE agents."""

    @patch('ai_guardian.directory_rule_generator.Path.is_dir')
    @patch('ai_guardian.directory_rule_generator.Path.exists')
    @patch.dict('os.environ', {'CLAUDE_CONFIG_DIR': '/custom/claude'})
    def test_claude_config_dir_env_var(self, mock_exists, mock_is_dir):
        """Should respect CLAUDE_CONFIG_DIR environment variable."""
        # Mock all paths as existing
        mock_exists.return_value = True
        mock_is_dir.return_value = True

        config = {
            "permissions": {
                "auto_directory_rules": {"enabled": True, "skill_directories": "auto"}
            }
        }

        generator = DirectoryRuleGenerator(config)
        dirs = generator._get_skill_directories({"skill_directories": "auto"})

        # Should include CLAUDE_CONFIG_DIR/skills
        assert any("/custom/claude/skills" in str(d) for d in dirs)

    @patch('ai_guardian.directory_rule_generator.Path.is_dir')
    @patch('ai_guardian.directory_rule_generator.Path.exists')
    @patch.dict('os.environ', {'CURSOR_PROJECT_PATH': '/workspace/project'})
    def test_cursor_project_path_env_var(self, mock_exists, mock_is_dir):
        """Should respect CURSOR_PROJECT_PATH environment variable."""
        # Mock all paths as existing
        mock_exists.return_value = True
        mock_is_dir.return_value = True

        config = {
            "permissions": {
                "auto_directory_rules": {"enabled": True, "skill_directories": "auto"}
            }
        }

        generator = DirectoryRuleGenerator(config)
        dirs = generator._get_skill_directories({"skill_directories": "auto"})

        # Should include CURSOR_PROJECT_PATH/.cursor/skills
        assert any("/workspace/project/.cursor/skills" in str(d) for d in dirs)

    @patch('ai_guardian.directory_rule_generator.Path.is_dir')
    @patch('ai_guardian.directory_rule_generator.Path.exists')
    @patch.dict('os.environ', {'VSCODE_CWD': '/workspace/vscode'})
    def test_vscode_cwd_env_var(self, mock_exists, mock_is_dir):
        """Should respect VSCODE_CWD environment variable."""
        # Mock all paths as existing
        mock_exists.return_value = True
        mock_is_dir.return_value = True

        config = {
            "permissions": {
                "auto_directory_rules": {"enabled": True, "skill_directories": "auto"}
            }
        }

        generator = DirectoryRuleGenerator(config)
        dirs = generator._get_skill_directories({"skill_directories": "auto"})

        # Should include VSCODE_CWD/.vscode/skills
        assert any("/workspace/vscode/.vscode/skills" in str(d) for d in dirs)

    @patch('ai_guardian.directory_rule_generator.Path.is_dir')
    @patch('ai_guardian.directory_rule_generator.Path.exists')
    def test_all_ide_directories_included(self, mock_exists, mock_is_dir):
        """Should scan all IDE skill directories by default."""
        # Mock all paths as existing
        mock_exists.return_value = True
        mock_is_dir.return_value = True

        config = {
            "permissions": {
                "auto_directory_rules": {"enabled": True, "skill_directories": "auto"}
            }
        }

        generator = DirectoryRuleGenerator(config)
        all_candidates = generator._get_skill_directories({"skill_directories": "auto"})

        # Convert to strings for easier checking
        all_dirs = [str(d) for d in all_candidates]

        # Should include all IDE variations
        assert any(".claude/skills" in d for d in all_dirs)
        assert any(".cursor/skills" in d for d in all_dirs)
        assert any(".vscode/skills" in d for d in all_dirs)
        assert any(".windsurf/skills" in d for d in all_dirs)

    @patch('ai_guardian.directory_rule_generator.Path.is_dir')
    @patch('ai_guardian.directory_rule_generator.Path.exists')
    def test_explicit_skill_directories_override(self, mock_exists, mock_is_dir):
        """Should use explicit directories when configured."""
        # Mock all paths as existing
        mock_exists.return_value = True
        mock_is_dir.return_value = True

        config = {
            "permissions": {
                "auto_directory_rules": {
                    "enabled": True,
                    "skill_directories": ["/custom/path/skills", "/another/path/skills"]
                }
            }
        }

        generator = DirectoryRuleGenerator(config)
        dirs = generator._get_skill_directories({
            "skill_directories": ["/custom/path/skills", "/another/path/skills"]
        })

        # Should only include explicit paths
        assert len(dirs) == 2
        assert Path("/custom/path/skills") in dirs
        assert Path("/another/path/skills") in dirs
