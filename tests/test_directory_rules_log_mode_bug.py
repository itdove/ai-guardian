"""
Test for issue #93: Directory rules ignore action=log setting and block instead

This test reproduces the bug where .ai-read-deny markers block access
even when directory_rules has action: "log" and no specific rule matches the path.
"""

import os
import tempfile
import unittest
from pathlib import Path
from ai_guardian import check_directory_denied


class DirectoryRulesLogModeBugTest(unittest.TestCase):
    """Test for bug #93: action=log ignored when .ai-read-deny marker present"""

    def test_marker_with_global_log_action_no_matching_rule(self):
        """
        Bug: When .ai-read-deny marker exists but no rule matches,
        global action="log" should still apply (allow with warning).

        Config: action="log" globally, but rules don't match this path
        Expected: Allow access with warning
        Actual (before fix): Blocks access
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create .ai-read-deny marker
            marker = os.path.join(tmpdir, ".ai-read-deny")
            Path(marker).touch()

            test_file = os.path.join(tmpdir, "test.txt")
            Path(test_file).touch()

            # Global action is "log", but no rule matches this path
            config = {
                "directory_rules": {
                    "action": "log",
                    "rules": [
                        {
                            "mode": "deny",
                            "paths": ["/some/other/path"]  # Doesn't match tmpdir
                        }
                    ]
                }
            }

            is_denied, denied_dir, warn_msg = check_directory_denied(test_file, config)

            # Should be allowed with warning (bug: currently blocks)
            self.assertFalse(is_denied, "Log mode should allow access even with .ai-read-deny marker")
            self.assertIsNone(denied_dir, "Should not be denied when action=log")
            self.assertIsNotNone(warn_msg, "Should return warning message in log mode")
            self.assertIn("log mode", warn_msg.lower())

    def test_marker_with_global_log_action_empty_rules(self):
        """
        Bug: When .ai-read-deny marker exists with no rules defined,
        global action="log" should apply (allow with warning).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create .ai-read-deny marker
            marker = os.path.join(tmpdir, ".ai-read-deny")
            Path(marker).touch()

            test_file = os.path.join(tmpdir, "test.txt")
            Path(test_file).touch()

            # Global action is "log", no rules defined
            config = {
                "directory_rules": {
                    "action": "log",
                    "rules": []
                }
            }

            is_denied, denied_dir, warn_msg = check_directory_denied(test_file, config)

            # Should be allowed with warning
            self.assertFalse(is_denied, "Log mode should allow access")
            self.assertIsNone(denied_dir)
            self.assertIsNotNone(warn_msg, "Should return warning message in log mode")

    def test_marker_with_global_block_action_no_matching_rule(self):
        """
        Control test: With action="block" (default), .ai-read-deny should block.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create .ai-read-deny marker
            marker = os.path.join(tmpdir, ".ai-read-deny")
            Path(marker).touch()

            test_file = os.path.join(tmpdir, "test.txt")
            Path(test_file).touch()

            # Global action is "block" (default)
            config = {
                "directory_rules": {
                    "action": "block",
                    "rules": []
                }
            }

            is_denied, denied_dir, warn_msg = check_directory_denied(test_file, config)

            # Should be blocked
            self.assertTrue(is_denied, "Block mode should deny access with .ai-read-deny marker")
            self.assertIsNotNone(denied_dir)
            self.assertIsNone(warn_msg)


if __name__ == "__main__":
    unittest.main()
