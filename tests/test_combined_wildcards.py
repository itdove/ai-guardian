"""
Unit tests for combined wildcard patterns (issue #102)

Tests directory_rules with patterns like:
- daf-*/** (single-level + recursive wildcard)
- ~/projects/*/src/** (multiple wildcards)
"""

import os
import tempfile
import unittest
from pathlib import Path
from ai_guardian import check_directory_denied


class CombinedWildcardsTest(unittest.TestCase):
    """Test combined wildcard patterns (e.g., daf-*/**, */src/**)"""

    def test_single_level_plus_recursive_wildcard(self):
        """Pattern like daf-*/** should match daf-git/**, daf-jira/**, etc."""
        home = os.path.expanduser("~")
        skills_dir = os.path.join(home, ".claude", "skills")

        config = {
            "directory_rules": [
                {"mode": "deny", "paths": [f"{skills_dir}/**"]},
                # Allow all daf-* skills with combined wildcard
                {"mode": "allow", "paths": [f"{skills_dir}/daf-*/**"]}
            ]
        }

        # Should match daf-git skill
        daf_git_file = os.path.join(skills_dir, "daf-git", "SKILL.md")
        is_denied, _, _ = check_directory_denied(daf_git_file, config)
        self.assertFalse(is_denied, f"daf-*/** pattern should match {daf_git_file}")

        # Should match daf-jira skill
        daf_jira_file = os.path.join(skills_dir, "daf-jira", "config.json")
        is_denied, _, _ = check_directory_denied(daf_jira_file, config)
        self.assertFalse(is_denied, f"daf-*/** pattern should match {daf_jira_file}")

        # Should match nested files
        daf_nested = os.path.join(skills_dir, "daf-config", "subdir", "file.txt")
        is_denied, _, _ = check_directory_denied(daf_nested, config)
        self.assertFalse(is_denied, f"daf-*/** pattern should match nested files")

        # Should NOT match non-daf skills
        other_skill = os.path.join(skills_dir, "code-review", "SKILL.md")
        is_denied, _, _ = check_directory_denied(other_skill, config)
        self.assertTrue(is_denied, "daf-*/** pattern should NOT match non-daf skills")

    def test_multiple_wildcards_in_path(self):
        """Pattern like ~/projects/*/src/** should match any project's src dir"""
        home = os.path.expanduser("~")
        projects_dir = os.path.join(home, "projects")

        config = {
            "directory_rules": [
                # Deny all projects first
                {"mode": "deny", "paths": [f"{projects_dir}/**"]},
                # Then allow only src directories (last rule wins)
                {"mode": "allow", "paths": [f"{projects_dir}/*/src/**"]}
            ]
        }

        # Should match different projects' src directories
        project1_file = os.path.join(projects_dir, "myapp", "src", "main.py")
        is_denied, _, _ = check_directory_denied(project1_file, config)
        self.assertFalse(is_denied, f"*/src/** should match {project1_file}")

        project2_file = os.path.join(projects_dir, "backend", "src", "api", "handler.go")
        is_denied, _, _ = check_directory_denied(project2_file, config)
        self.assertFalse(is_denied, f"*/src/** should match {project2_file}")

        # Should NOT match non-src directories
        tests_file = os.path.join(projects_dir, "myapp", "tests", "test.py")
        is_denied, _, _ = check_directory_denied(tests_file, config)
        self.assertTrue(is_denied, "*/src/** should NOT match tests directory")

    def test_real_world_skill_allowlist(self):
        """Real-world scenario: Allow daf-* skills using single pattern instead of listing all"""
        home = os.path.expanduser("~")
        skills_dir = os.path.join(home, ".claude", "skills")

        # Before fix: Users had to list each daf skill explicitly
        # After fix: One pattern covers all daf-* skills
        config = {
            "directory_rules": [
                {"mode": "deny", "paths": [f"{skills_dir}/**"]},
                {"mode": "allow", "paths": [f"{skills_dir}/daf-*/**"]}
            ]
        }

        # Test all common daf skills
        daf_skills = [
            "daf-git/SKILL.md",
            "daf-jira/SKILL.md",
            "daf-config/SKILL.md",
            "daf-active/SKILL.md",
            "daf-status/helpers/util.py",
            "daf-workflow/docs/guide.md"
        ]

        for skill_path in daf_skills:
            full_path = os.path.join(skills_dir, skill_path)
            is_denied, _, _ = check_directory_denied(full_path, config)
            self.assertFalse(is_denied, f"daf-*/** should allow {skill_path}")

        # Non-daf skills should be denied
        non_daf_skills = [
            "code-review/SKILL.md",
            "release/SKILL.md",
            "custom-skill/file.txt"
        ]

        for skill_path in non_daf_skills:
            full_path = os.path.join(skills_dir, skill_path)
            is_denied, _, _ = check_directory_denied(full_path, config)
            self.assertTrue(is_denied, f"daf-*/** should NOT allow {skill_path}")

    def test_tilde_with_combined_wildcards(self):
        """Tilde expansion should work with combined wildcards"""
        home = os.path.expanduser("~")

        config = {
            "directory_rules": [
                {"mode": "deny", "paths": ["~/.claude/skills/**"]},
                {"mode": "allow", "paths": ["~/.claude/skills/daf-*/**"]}
            ]
        }

        # Should allow daf-* skills
        test_file = os.path.join(home, ".claude", "skills", "daf-git", "SKILL.md")
        is_denied, _, _ = check_directory_denied(test_file, config)
        self.assertFalse(is_denied, "Tilde should expand correctly with combined wildcards")

        # Should deny non-daf skills
        other_file = os.path.join(home, ".claude", "skills", "other-skill", "file.md")
        is_denied, _, _ = check_directory_denied(other_file, config)
        self.assertTrue(is_denied, "Non-daf skills should be denied")


if __name__ == "__main__":
    unittest.main()
