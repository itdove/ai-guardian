#!/usr/bin/env python3
"""
Test case for Bash tool output scanning in PostToolUse hook.

Tests that ai-guardian properly scans Bash tool stdout/stderr output,
preventing bypass via Bash commands instead of Read tool.
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_guardian import extract_tool_result


class TestBashToolOutputScanning(unittest.TestCase):
    """
    Test that extract_tool_result() properly extracts Bash tool output
    from stdout/stderr fields, not just output/content/result fields.
    """

    def test_bash_stdout_extracted(self):
        """Test that Bash stdout is extracted for scanning."""
        hook_data = {
            "tool_name": "Bash",
            "tool_response": {
                "stdout": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n",
                "stderr": "",
                "exit_code": 0
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertEqual(tool_name, "Bash")
        self.assertIsNotNone(output)
        self.assertIn("AKIAIOSFODNN7EXAMPLE", output)

    def test_bash_stderr_extracted(self):
        """Test that Bash stderr is extracted for scanning."""
        hook_data = {
            "tool_name": "Bash",
            "tool_response": {
                "stdout": "",
                "stderr": "Error: Connection failed with token abc123secret\n",
                "exit_code": 1
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertEqual(tool_name, "Bash")
        self.assertIsNotNone(output)
        self.assertIn("abc123secret", output)

    def test_bash_stdout_and_stderr_combined(self):
        """Test that both stdout and stderr are combined when both present."""
        hook_data = {
            "tool_name": "Bash",
            "tool_response": {
                "stdout": "Output line 1\n",
                "stderr": "Warning: sensitive data\n",
                "exit_code": 0
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertEqual(tool_name, "Bash")
        self.assertIsNotNone(output)
        # Both streams should be in output
        self.assertIn("Output line 1", output)
        self.assertIn("sensitive data", output)

    def test_read_tool_output_field(self):
        """Test that Read tool output field still works (regression test)."""
        hook_data = {
            "tool_name": "Read",
            "tool_response": {
                "output": "File contents with secret: xyz789\n"
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertEqual(tool_name, "Read")
        self.assertIsNotNone(output)
        self.assertIn("xyz789", output)

    def test_read_tool_content_field(self):
        """Test that Read tool content field still works."""
        hook_data = {
            "tool_name": "Read",
            "tool_response": {
                "content": "File contents with password=secret123\n"
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertEqual(tool_name, "Read")
        self.assertIsNotNone(output)
        self.assertIn("password=secret123", output)

    def test_bash_empty_output(self):
        """Test that empty Bash output returns None."""
        hook_data = {
            "tool_name": "Bash",
            "tool_response": {
                "stdout": "",
                "stderr": "",
                "exit_code": 0
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertEqual(tool_name, "Bash")
        self.assertIsNone(output)

    def test_bash_output_field_precedence(self):
        """Test that explicit 'output' field takes precedence over stdout/stderr."""
        hook_data = {
            "tool_name": "Bash",
            "tool_response": {
                "output": "Explicit output field",
                "stdout": "stdout content",
                "stderr": "stderr content",
                "exit_code": 0
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertEqual(tool_name, "Bash")
        # output field should take precedence
        self.assertEqual(output, "Explicit output field")

    def test_state_modifying_tool_skipped(self):
        """Test that Write/Edit tools are still skipped (regression test)."""
        hook_data = {
            "tool_name": "Write",
            "tool_response": {
                "success": True,
                "file_path": "/tmp/test.txt"
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertEqual(tool_name, "Write")
        self.assertIsNone(output)  # Write output should not be scanned


class TestBashRealWorldScenarios(unittest.TestCase):
    """
    Test real-world scenarios where Bash tool might leak sensitive data.
    """

    def test_cat_command_with_secret(self):
        """Test that cat command output is scanned."""
        # Simulates: Bash(command="cat ~/.aws/credentials")
        hook_data = {
            "tool_name": "Bash",
            "tool_response": {
                "stdout": "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
                "stderr": "",
                "exit_code": 0
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertIsNotNone(output)
        self.assertIn("AKIAIOSFODNN7EXAMPLE", output)
        self.assertIn("wJalrXUtnFEMI", output)

    def test_grep_command_finds_password(self):
        """Test that grep output exposing secrets is scanned."""
        # Simulates: Bash(command="grep -r 'password' /etc")
        hook_data = {
            "tool_name": "Bash",
            "tool_response": {
                "stdout": "/etc/config.yml:database_password: SuperSecret123!\n",
                "stderr": "",
                "exit_code": 0
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertIsNotNone(output)
        self.assertIn("SuperSecret123!", output)

    def test_env_command_leaks_tokens(self):
        """Test that env command output is scanned."""
        # Simulates: Bash(command="env | grep TOKEN")
        hook_data = {
            "tool_name": "Bash",
            "tool_response": {
                "stdout": "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\nAPI_TOKEN=sk-proj-abc123\n",  # gitleaks:allow
                "stderr": "",
                "exit_code": 0
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertIsNotNone(output)
        self.assertIn("ghp_1234567890", output)
        self.assertIn("sk-proj-abc123", output)

    def test_command_with_error_message_leak(self):
        """Test that error messages in stderr are also scanned."""
        # Simulates: Bash(command="curl https://api.example.com")
        hook_data = {
            "tool_name": "Bash",
            "tool_response": {
                "stdout": "",
                "stderr": "curl: (7) Failed to connect to api.example.com:443\nUsing token: Bearer sk-secret-token-here\n",
                "exit_code": 7
            }
        }

        output, tool_name = extract_tool_result(hook_data)

        self.assertIsNotNone(output)
        self.assertIn("sk-secret-token-here", output)


if __name__ == '__main__':
    unittest.main()
