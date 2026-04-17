"""
Unit tests for order-based directory_rules system

Tests:
- Order-based precedence (last match wins)
- Allow/deny combinations
- Interaction with .ai-read-deny markers
- Backward compatibility with directory_exclusions
- Wildcard patterns (**, *)
"""

import os
import tempfile
import unittest
from pathlib import Path
from ai_guardian import check_directory_denied


class DirectoryRulesOrderTest(unittest.TestCase):
    """Test order-based rule precedence"""

    def test_last_rule_wins_deny_then_allow(self):
        """Last matching rule should win: deny all, then allow specific"""
        config = {
            "directory_rules": [
                {"mode": "deny", "paths": ["/tmp/skills"]},
                {"mode": "allow", "paths": ["/tmp/skills/approved"]}
            ]
        }

        # Denied by first rule
        is_denied, _ = check_directory_denied("/tmp/skills/blocked/file.txt", config)
        self.assertTrue(is_denied, "Should be denied by first rule")

        # Allowed by second rule (overrides first)
        is_denied, _ = check_directory_denied("/tmp/skills/approved/file.txt", config)
        self.assertFalse(is_denied, "Should be allowed by second rule")

    def test_last_rule_wins_allow_then_deny(self):
        """Last matching rule should win: allow all, then deny specific"""
        config = {
            "directory_rules": [
                {"mode": "allow", "paths": ["/tmp/projects"]},
                {"mode": "deny", "paths": ["/tmp/projects/secret"]}
            ]
        }

        # Allowed by first rule
        is_denied, _ = check_directory_denied("/tmp/projects/public/file.txt", config)
        self.assertFalse(is_denied, "Should be allowed by first rule")

        # Denied by second rule (overrides first)
        is_denied, _ = check_directory_denied("/tmp/projects/secret/file.txt", config)
        self.assertTrue(is_denied, "Should be denied by second rule")

    def test_multiple_rules_last_match_wins(self):
        """With multiple matching rules, last one wins"""
        config = {
            "directory_rules": [
                {"mode": "deny", "paths": ["/tmp"]},
                {"mode": "allow", "paths": ["/tmp/allow"]},
                {"mode": "deny", "paths": ["/tmp/allow/deny-again"]}
            ]
        }

        # Denied by first rule
        is_denied, _ = check_directory_denied("/tmp/blocked/file.txt", config)
        self.assertTrue(is_denied)

        # Allowed by second rule
        is_denied, _ = check_directory_denied("/tmp/allow/file.txt", config)
        self.assertFalse(is_denied)

        # Denied by third rule (overrides second)
        is_denied, _ = check_directory_denied("/tmp/allow/deny-again/file.txt", config)
        self.assertTrue(is_denied)


class DirectoryRulesWithMarkersTest(unittest.TestCase):
    """Test interaction with .ai-read-deny markers"""

    def test_allow_rule_overrides_deny_marker(self):
        """Allow rule should override .ai-read-deny marker"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create .ai-read-deny marker
            deny_marker = Path(tmpdir) / ".ai-read-deny"
            deny_marker.touch()

            # Create test file
            test_file = Path(tmpdir) / "test.txt"
            test_file.touch()

            # Without rule: should be denied
            is_denied, _ = check_directory_denied(str(test_file), {})
            self.assertTrue(is_denied, "Should be denied by .ai-read-deny marker")

            # With allow rule: should be allowed (rule overrides marker)
            config = {
                "directory_rules": [
                    {"mode": "allow", "paths": [tmpdir]}
                ]
            }
            is_denied, _ = check_directory_denied(str(test_file), config)
            self.assertFalse(is_denied, "Allow rule should override .ai-read-deny marker")

    def test_deny_marker_without_allow_rule(self):
        """Without allow rule, .ai-read-deny marker should block"""
        with tempfile.TemporaryDirectory() as tmpdir:
            deny_marker = Path(tmpdir) / ".ai-read-deny"
            deny_marker.touch()
            test_file = Path(tmpdir) / "test.txt"
            test_file.touch()

            config = {
                "directory_rules": [
                    {"mode": "deny", "paths": ["/other/path"]}
                ]
            }

            is_denied, _ = check_directory_denied(str(test_file), config)
            self.assertTrue(is_denied, ".ai-read-deny should block when no allow rule matches")

    def test_deny_rule_without_marker(self):
        """Deny rule should block even without .ai-read-deny marker"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # No .ai-read-deny marker
            test_file = Path(tmpdir) / "test.txt"
            test_file.touch()

            config = {
                "directory_rules": [
                    {"mode": "deny", "paths": [tmpdir]}
                ]
            }

            is_denied, _ = check_directory_denied(str(test_file), config)
            self.assertTrue(is_denied, "Deny rule should block even without marker")


class DirectoryRulesWildcardsTest(unittest.TestCase):
    """Test wildcard pattern matching"""

    def test_recursive_wildcard(self):
        """** should match all subdirectories recursively"""
        config = {
            "directory_rules": [
                {"mode": "deny", "paths": ["/tmp/skills/**"]}
            ]
        }

        # Should match at any depth
        is_denied, _ = check_directory_denied("/tmp/skills/file.txt", config)
        self.assertTrue(is_denied)

        is_denied, _ = check_directory_denied("/tmp/skills/sub/file.txt", config)
        self.assertTrue(is_denied)

        is_denied, _ = check_directory_denied("/tmp/skills/sub/deep/file.txt", config)
        self.assertTrue(is_denied)

        # Should not match outside directory
        is_denied, _ = check_directory_denied("/tmp/other/file.txt", config)
        self.assertFalse(is_denied)

    def test_tilde_expansion(self):
        """~ should expand to home directory"""
        home = os.path.expanduser("~")
        config = {
            "directory_rules": [
                {"mode": "deny", "paths": ["~/.claude/skills/**"]}
            ]
        }

        # Should expand ~ and match
        test_path = os.path.join(home, ".claude", "skills", "test.txt")
        is_denied, _ = check_directory_denied(test_path, config)
        self.assertTrue(is_denied, "~ should expand to home directory")


class BackwardCompatibilityTest(unittest.TestCase):
    """Test backward compatibility with directory_exclusions"""

    def test_directory_exclusions_converted_to_allow_rules(self):
        """directory_exclusions should be converted to allow rules"""
        with tempfile.TemporaryDirectory() as tmpdir:
            deny_marker = Path(tmpdir) / ".ai-read-deny"
            deny_marker.touch()
            test_file = Path(tmpdir) / "test.txt"
            test_file.touch()

            # Old format
            config = {
                "directory_exclusions": {
                    "enabled": True,
                    "paths": [tmpdir]
                }
            }

            is_denied, _ = check_directory_denied(str(test_file), config)
            self.assertFalse(is_denied, "directory_exclusions should work as allow rules")

    def test_exclusions_have_lower_priority_than_explicit_rules(self):
        """directory_exclusions should have lower priority than directory_rules"""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.touch()

            # Exclusions say allow, but explicit rule says deny
            config = {
                "directory_exclusions": {
                    "enabled": True,
                    "paths": [tmpdir]
                },
                "directory_rules": [
                    {"mode": "deny", "paths": [tmpdir]}
                ]
            }

            is_denied, _ = check_directory_denied(str(test_file), config)
            self.assertTrue(is_denied, "Explicit deny rule should override backward compat allow")


class SkillAllowlistExampleTest(unittest.TestCase):
    """Test real-world enterprise skill allowlist scenario"""

    def test_enterprise_skill_allowlist(self):
        """Example: Block all skills except approved ones"""
        home = os.path.expanduser("~")
        skills_dir = os.path.join(home, ".claude", "skills")

        config = {
            "directory_rules": [
                # First: deny all skills
                {"mode": "deny", "paths": [f"{skills_dir}/**"]},
                # Then: allow approved skills (wins because it's last)
                {"mode": "allow", "paths": [
                    f"{skills_dir}/bugfix-workflow/**",
                    f"{skills_dir}/code-review/**",
                    f"{skills_dir}/epic-breakdown-workflow/**"
                ]}
            ]
        }

        # Approved skill: allowed
        approved = os.path.join(skills_dir, "bugfix-workflow", "SKILL.md")
        is_denied, _ = check_directory_denied(approved, config)
        self.assertFalse(is_denied, "Approved skill should be allowed")

        # Unapproved skill: denied
        unapproved = os.path.join(skills_dir, "database-migration", "SKILL.md")
        is_denied, _ = check_directory_denied(unapproved, config)
        self.assertTrue(is_denied, "Unapproved skill should be denied")


if __name__ == "__main__":
    unittest.main()
