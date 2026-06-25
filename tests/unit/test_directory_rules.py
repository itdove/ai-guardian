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
import shutil
import tempfile
import unittest
from pathlib import Path

import pytest

from ai_guardian import check_directory_denied


@pytest.mark.parametrize(
    "rules, path, expected_denied",
    [
        # deny-then-allow: path matched only by deny rule
        pytest.param(
            [
                {"mode": "deny", "paths": ["/tmp/skills"]},
                {"mode": "allow", "paths": ["/tmp/skills/approved"]},
            ],
            "/tmp/skills/blocked/file.txt",
            True,
            id="deny-then-allow--denied-by-first-rule",
        ),
        # deny-then-allow: path matched by later allow rule (overrides)
        pytest.param(
            [
                {"mode": "deny", "paths": ["/tmp/skills"]},
                {"mode": "allow", "paths": ["/tmp/skills/approved"]},
            ],
            "/tmp/skills/approved/file.txt",
            False,
            id="deny-then-allow--allowed-by-second-rule",
        ),
        # allow-then-deny: path matched only by allow rule
        pytest.param(
            [
                {"mode": "allow", "paths": ["/tmp/projects"]},
                {"mode": "deny", "paths": ["/tmp/projects/secret"]},
            ],
            "/tmp/projects/public/file.txt",
            False,
            id="allow-then-deny--allowed-by-first-rule",
        ),
        # allow-then-deny: path matched by later deny rule (overrides)
        pytest.param(
            [
                {"mode": "allow", "paths": ["/tmp/projects"]},
                {"mode": "deny", "paths": ["/tmp/projects/secret"]},
            ],
            "/tmp/projects/secret/file.txt",
            True,
            id="allow-then-deny--denied-by-second-rule",
        ),
        # three rules: path matched only by first deny
        pytest.param(
            [
                {"mode": "deny", "paths": ["/tmp"]},
                {"mode": "allow", "paths": ["/tmp/allow"]},
                {"mode": "deny", "paths": ["/tmp/allow/deny-again"]},
            ],
            "/tmp/blocked/file.txt",
            True,
            id="three-rules--denied-by-first-rule",
        ),
        # three rules: path matched by second allow (overrides first deny)
        pytest.param(
            [
                {"mode": "deny", "paths": ["/tmp"]},
                {"mode": "allow", "paths": ["/tmp/allow"]},
                {"mode": "deny", "paths": ["/tmp/allow/deny-again"]},
            ],
            "/tmp/allow/file.txt",
            False,
            id="three-rules--allowed-by-second-rule",
        ),
        # three rules: path matched by third deny (overrides second allow)
        pytest.param(
            [
                {"mode": "deny", "paths": ["/tmp"]},
                {"mode": "allow", "paths": ["/tmp/allow"]},
                {"mode": "deny", "paths": ["/tmp/allow/deny-again"]},
            ],
            "/tmp/allow/deny-again/file.txt",
            True,
            id="three-rules--denied-by-third-rule",
        ),
    ],
)
def test_last_rule_wins_precedence(rules, path, expected_denied):
    """Last matching rule should win in order-based precedence."""
    config = {"directory_rules": rules}
    is_denied, _, _, _ = check_directory_denied(path, config)
    assert is_denied == expected_denied


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
            is_denied, _, _, _ = check_directory_denied(str(test_file), {})
            self.assertTrue(is_denied, "Should be denied by .ai-read-deny marker")

            # With allow rule: should be allowed (rule overrides marker)
            config = {"directory_rules": [{"mode": "allow", "paths": [tmpdir]}]}
            is_denied, _, _, _ = check_directory_denied(str(test_file), config)
            self.assertFalse(
                is_denied, "Allow rule should override .ai-read-deny marker"
            )

    def test_deny_marker_without_allow_rule(self):
        """Without allow rule, .ai-read-deny marker should block"""
        with tempfile.TemporaryDirectory() as tmpdir:
            deny_marker = Path(tmpdir) / ".ai-read-deny"
            deny_marker.touch()
            test_file = Path(tmpdir) / "test.txt"
            test_file.touch()

            config = {"directory_rules": [{"mode": "deny", "paths": ["/other/path"]}]}

            is_denied, _, _, _ = check_directory_denied(str(test_file), config)
            self.assertTrue(
                is_denied, ".ai-read-deny should block when no allow rule matches"
            )

    def test_deny_rule_without_marker(self):
        """Deny rule should block even without .ai-read-deny marker"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # No .ai-read-deny marker
            test_file = Path(tmpdir) / "test.txt"
            test_file.touch()

            config = {"directory_rules": [{"mode": "deny", "paths": [tmpdir]}]}

            is_denied, _, _, _ = check_directory_denied(str(test_file), config)
            self.assertTrue(is_denied, "Deny rule should block even without marker")


class DirectoryRulesWildcardsTest(unittest.TestCase):
    """Test wildcard pattern matching"""

    def test_recursive_wildcard(self):
        """** should match all subdirectories recursively"""
        config = {"directory_rules": [{"mode": "deny", "paths": ["/tmp/skills/**"]}]}

        # Should match at any depth
        is_denied, _, _, _ = check_directory_denied("/tmp/skills/file.txt", config)
        self.assertTrue(is_denied)

        is_denied, _, _, _ = check_directory_denied("/tmp/skills/sub/file.txt", config)
        self.assertTrue(is_denied)

        is_denied, _, _, _ = check_directory_denied(
            "/tmp/skills/sub/deep/file.txt", config
        )
        self.assertTrue(is_denied)

        # Should not match outside directory
        is_denied, _, _, _ = check_directory_denied("/tmp/other/file.txt", config)
        self.assertFalse(is_denied)

    def test_tilde_expansion(self):
        """~ should expand to home directory"""
        home = os.path.expanduser("~")
        config = {
            "directory_rules": [{"mode": "deny", "paths": ["~/.claude/skills/**"]}]
        }

        # Should expand ~ and match
        test_path = os.path.join(home, ".claude", "skills", "test.txt")
        is_denied, _, _, _ = check_directory_denied(test_path, config)
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
            config = {"directory_exclusions": {"enabled": True, "paths": [tmpdir]}}

            is_denied, _, _, _ = check_directory_denied(str(test_file), config)
            self.assertFalse(
                is_denied, "directory_exclusions should work as allow rules"
            )

    def test_exclusions_have_lower_priority_than_explicit_rules(self):
        """directory_exclusions should have lower priority than directory_rules"""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.touch()

            # Exclusions say allow, but explicit rule says deny
            config = {
                "directory_exclusions": {"enabled": True, "paths": [tmpdir]},
                "directory_rules": [{"mode": "deny", "paths": [tmpdir]}],
            }

            is_denied, _, _, _ = check_directory_denied(str(test_file), config)
            self.assertTrue(
                is_denied, "Explicit deny rule should override backward compat allow"
            )


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
                {
                    "mode": "allow",
                    "paths": [
                        f"{skills_dir}/bugfix-workflow/**",
                        f"{skills_dir}/code-review/**",
                        f"{skills_dir}/epic-breakdown-workflow/**",
                    ],
                },
            ]
        }

        # Approved skill: allowed
        approved = os.path.join(skills_dir, "bugfix-workflow", "SKILL.md")
        is_denied, _, _, _ = check_directory_denied(approved, config)
        self.assertFalse(is_denied, "Approved skill should be allowed")

        # Unapproved skill: denied
        unapproved = os.path.join(skills_dir, "database-migration", "SKILL.md")
        is_denied, _, _, _ = check_directory_denied(unapproved, config)
        self.assertTrue(is_denied, "Unapproved skill should be denied")


# --- Merged from test_directory_blocking.py ---


def test_directory_blocking():
    """Test that .ai-read-deny marker blocks access to directory and subdirectories"""
    test_dir = tempfile.mkdtemp(prefix="ai_deny_test_")

    try:
        allowed_dir = os.path.join(test_dir, "allowed_dir")
        denied_dir = os.path.join(test_dir, "denied_dir")
        denied_subdir = os.path.join(denied_dir, "subdir")

        os.makedirs(allowed_dir)
        os.makedirs(denied_subdir)

        allowed_file = os.path.join(allowed_dir, "allowed_file.txt")
        blocked_file = os.path.join(denied_dir, "blocked_file.txt")
        deeply_blocked_file = os.path.join(denied_subdir, "deeply_blocked_file.txt")

        with open(allowed_file, "w") as f:
            f.write("This file should be accessible")
        with open(blocked_file, "w") as f:
            f.write("This file should be blocked")
        with open(deeply_blocked_file, "w") as f:
            f.write("This nested file should also be blocked")

        deny_marker = os.path.join(denied_dir, ".ai-read-deny")
        with open(deny_marker, "w") as f:
            f.write("")

        test_config = {"directory_rules": {"action": "block", "rules": []}}

        is_denied, denied_path, _, _ = check_directory_denied(allowed_file, test_config)
        assert not is_denied, "Allowed file was blocked"
        assert denied_path is None, "Allowed file has denied path"

        is_denied, denied_path, _, _ = check_directory_denied(blocked_file, test_config)
        assert is_denied, "Denied file was not blocked"
        assert denied_path == os.path.realpath(denied_dir)

        is_denied, denied_path, _, _ = check_directory_denied(
            deeply_blocked_file, test_config
        )
        assert is_denied, "Nested file in denied directory was not blocked"
        assert denied_path == os.path.realpath(denied_dir)

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


# --- Merged from test_directory_rules_log_mode_bug.py ---


class DirectoryRulesLogModeBugTest(unittest.TestCase):
    """Test for bug #93: action=log ignored when .ai-read-deny marker present"""

    def test_marker_with_global_log_action_no_matching_rule(self):
        """
        Bug: When .ai-read-deny marker exists but no rule matches,
        global action="warn" should still apply (allow with warning).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            marker = os.path.join(tmpdir, ".ai-read-deny")
            Path(marker).touch()
            test_file = os.path.join(tmpdir, "test.txt")
            Path(test_file).touch()

            config = {
                "directory_rules": {
                    "action": "warn",
                    "rules": [{"mode": "deny", "paths": ["/some/other/path"]}],
                }
            }

            is_denied, denied_dir, warn_msg, _ = check_directory_denied(
                test_file, config
            )
            self.assertFalse(
                is_denied,
                "Warn mode should allow access even with .ai-read-deny marker",
            )
            self.assertIsNone(denied_dir, "Should not be denied when action=warn")
            self.assertIsNotNone(warn_msg, "Should return warning message in warn mode")
            self.assertIn("warn mode", warn_msg.lower())

    def test_marker_with_global_log_action_empty_rules(self):
        """Bug: With action="warn" and no rules, marker should warn not block."""
        with tempfile.TemporaryDirectory() as tmpdir:
            marker = os.path.join(tmpdir, ".ai-read-deny")
            Path(marker).touch()
            test_file = os.path.join(tmpdir, "test.txt")
            Path(test_file).touch()

            config = {"directory_rules": {"action": "warn", "rules": []}}

            is_denied, denied_dir, warn_msg, _ = check_directory_denied(
                test_file, config
            )
            self.assertFalse(is_denied, "Warn mode should allow access")
            self.assertIsNone(denied_dir)
            self.assertIsNotNone(warn_msg, "Should return warning message in warn mode")

    def test_marker_with_global_block_action_no_matching_rule(self):
        """Control test: action="block" with .ai-read-deny should block."""
        with tempfile.TemporaryDirectory() as tmpdir:
            marker = os.path.join(tmpdir, ".ai-read-deny")
            Path(marker).touch()
            test_file = os.path.join(tmpdir, "test.txt")
            Path(test_file).touch()

            config = {"directory_rules": {"action": "block", "rules": []}}

            is_denied, denied_dir, warn_msg, _ = check_directory_denied(
                test_file, config
            )
            self.assertTrue(
                is_denied, "Block mode should deny access with .ai-read-deny marker"
            )
            self.assertIsNotNone(denied_dir)
            self.assertIsNone(warn_msg)


# --- Merged from test_directory_exclusions.py ---


class DirectoryExclusionsTest(unittest.TestCase):
    """Tests for legacy directory_exclusions feature (backward compatibility)."""

    def test_basic_exclusion(self):
        """Excluded dir, no .ai-read-deny"""
        test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")
        try:
            allowed_dir = os.path.join(test_dir, "workspace")
            os.makedirs(allowed_dir)
            allowed_file = os.path.join(allowed_dir, "file.txt")
            with open(allowed_file, "w") as f:
                f.write("test content")
            config = {
                "directory_exclusions": {"enabled": True, "paths": [test_dir + "/**"]}
            }
            is_denied, denied_dir, _, _ = check_directory_denied(allowed_file, config)
            self.assertFalse(is_denied, "Excluded directory should allow access")
            self.assertIsNone(denied_dir)
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_ai_read_deny_overrides_exclusion(self):
        """directory_exclusions (allow rules) override .ai-read-deny (v1.6.0+)"""
        test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")
        try:
            excluded_dir = os.path.join(test_dir, "workspace")
            os.makedirs(excluded_dir)
            deny_marker = os.path.join(excluded_dir, ".ai-read-deny")
            with open(deny_marker, "w") as f:
                f.write("")
            blocked_file = os.path.join(excluded_dir, "file.txt")
            with open(blocked_file, "w") as f:
                f.write("secret content")
            config = {
                "directory_exclusions": {"enabled": True, "paths": [test_dir + "/**"]}
            }
            is_denied, _, _, _ = check_directory_denied(blocked_file, config)
            self.assertFalse(
                is_denied, "directory_exclusions should override .ai-read-deny"
            )
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_subdirectory_deny_in_excluded_parent(self):
        """Parent exclusion overrides subdirectory .ai-read-deny (v1.6.0+)"""
        test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")
        try:
            excluded_dir = os.path.join(test_dir, "workspace")
            secrets_dir = os.path.join(excluded_dir, "secrets")
            os.makedirs(secrets_dir)
            deny_marker = os.path.join(secrets_dir, ".ai-read-deny")
            with open(deny_marker, "w") as f:
                f.write("")
            allowed_file = os.path.join(excluded_dir, "public.txt")
            blocked_file = os.path.join(secrets_dir, "secret.txt")
            with open(allowed_file, "w") as f:
                f.write("public content")
            with open(blocked_file, "w") as f:
                f.write("secret content")
            config = {
                "directory_exclusions": {
                    "enabled": True,
                    "paths": [excluded_dir + "/**"],
                }
            }
            is_denied, _, _, _ = check_directory_denied(allowed_file, config)
            self.assertFalse(is_denied)
            is_denied, _, _, _ = check_directory_denied(blocked_file, config)
            self.assertFalse(
                is_denied, "Parent exclusion should override subdirectory .ai-read-deny"
            )
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_tilde_expansion(self):
        """Tilde expansion in exclusion paths"""
        home_dir = os.path.expanduser("~")
        test_dir = os.path.join(home_dir, ".ai_exclusion_test_tilde")
        os.makedirs(test_dir, exist_ok=True)
        try:
            test_file = os.path.join(test_dir, "file.txt")
            with open(test_file, "w") as f:
                f.write("test content")
            config = {
                "directory_exclusions": {
                    "enabled": True,
                    "paths": ["~/.ai_exclusion_test_tilde/**"],
                }
            }
            is_denied, _, _, _ = check_directory_denied(test_file, config)
            self.assertFalse(is_denied, "Tilde expansion should work")
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_wildcard_matching(self):
        """Wildcard matching (**, *)"""
        test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")
        try:
            deep_dir = os.path.join(test_dir, "repos", "public", "proj1", "src")
            os.makedirs(deep_dir)
            deep_file = os.path.join(deep_dir, "file.txt")
            with open(deep_file, "w") as f:
                f.write("test content")
            config = {
                "directory_exclusions": {
                    "enabled": True,
                    "paths": [os.path.join(test_dir, "repos", "**")],
                }
            }
            is_denied, _, _, _ = check_directory_denied(deep_file, config)
            self.assertFalse(is_denied, "** should match recursively")
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_exclusion_disabled(self):
        """Exclusions don't apply when enabled: false"""
        test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")
        try:
            test_file = os.path.join(test_dir, "file.txt")
            with open(test_file, "w") as f:
                f.write("test content")
            config = {
                "directory_exclusions": {"enabled": False, "paths": [test_dir + "/**"]}
            }
            is_denied, _, _, _ = check_directory_denied(test_file, config)
            self.assertFalse(is_denied, "Should allow (no marker, exclusions disabled)")
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_missing_exclusion_config(self):
        """Backward compatibility when directory_exclusions is missing"""
        test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")
        try:
            test_file = os.path.join(test_dir, "file.txt")
            with open(test_file, "w") as f:
                f.write("test content")
            config = {"permissions": []}
            is_denied, _, _, _ = check_directory_denied(test_file, config)
            self.assertFalse(is_denied, "Should allow (no marker, no exclusions)")
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_invalid_paths(self):
        """Invalid paths fail-safe (don't cause errors)"""
        test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")
        try:
            test_file = os.path.join(test_dir, "file.txt")
            with open(test_file, "w") as f:
                f.write("test content")
            config = {
                "directory_exclusions": {
                    "enabled": True,
                    "paths": ["/nonexistent/path/**", 123, None, test_dir + "/**"],
                }
            }
            is_denied, _, _, _ = check_directory_denied(test_file, config)
            self.assertFalse(is_denied, "Should apply valid path despite invalid ones")
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_absolute_paths(self):
        """Absolute path matching"""
        test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")
        try:
            test_file = os.path.join(test_dir, "file.txt")
            with open(test_file, "w") as f:
                f.write("test content")
            config = {"directory_exclusions": {"enabled": True, "paths": [test_dir]}}
            is_denied, _, _, _ = check_directory_denied(test_file, config)
            self.assertFalse(is_denied, "Absolute path should work")
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_no_config(self):
        """None config doesn't cause errors"""
        test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")
        try:
            test_file = os.path.join(test_dir, "file.txt")
            with open(test_file, "w") as f:
                f.write("test content")
            is_denied, _, _, _ = check_directory_denied(test_file, None)
            self.assertFalse(is_denied, "Should allow (no marker, no config)")
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
