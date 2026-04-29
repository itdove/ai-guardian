"""Tests for configuration file error handling."""
import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

# Import from parent directory
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from ai_guardian import _load_config_file


class TestConfigErrorHandling(unittest.TestCase):
    """Test configuration error handling and user-friendly messages."""

    def test_malformed_json_returns_error_message(self):
        """Test that malformed JSON returns a user-friendly error message."""
        malformed_json = """{
  "permissions": [
    {
      "matcher": "Skill",
      "action": "warn"
      "patterns": ["test"]
    }
  ]
}"""

        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".ai-guardian.json"
            config_file.write_text(malformed_json)

            # Mock get_config_dir to return a non-existent path
            # This forces _load_config_file to use the project local config
            with patch('ai_guardian.get_config_dir') as mock_get_config_dir:
                mock_get_config_dir.return_value = Path("/nonexistent/path")

                # Change to tmpdir so project local config is found
                import os
                old_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    config, error = _load_config_file()

                    # Should return None config and error message
                    self.assertIsNone(config)
                    self.assertIsNotNone(error)
                    self.assertIn("Configuration Error", error)
                    self.assertIn("JSON Error", error)
                    self.assertIn(str(config_file), error)
                    self.assertIn("line", error.lower())
                    self.assertIn("column", error.lower())
                finally:
                    os.chdir(old_cwd)

    def test_valid_json_returns_config(self):
        """Test that valid JSON returns config without error."""
        valid_json = """{
  "permissions": [
    {
      "matcher": "Skill",
      "action": "warn",
      "patterns": ["test"]
    }
  ]
}"""

        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".ai-guardian.json"
            config_file.write_text(valid_json)

            with patch('ai_guardian.get_config_dir') as mock_get_config_dir:
                mock_get_config_dir.return_value = Path("/nonexistent/path")

                import os
                old_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    config, error = _load_config_file()

                    # Should return config without error
                    self.assertIsNotNone(config)
                    self.assertIsNone(error)
                    self.assertIn("permissions", config)
                finally:
                    os.chdir(old_cwd)

    def test_no_config_file_returns_none(self):
        """Test that missing config file returns None without error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('ai_guardian.get_config_dir') as mock_get_config_dir:
                mock_get_config_dir.return_value = Path("/nonexistent/path")

                import os
                old_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    config, error = _load_config_file()

                    # Should return None for both (no config is not an error)
                    self.assertIsNone(config)
                    self.assertIsNone(error)
                finally:
                    os.chdir(old_cwd)

    def test_unreadable_file_returns_error(self):
        """Test that unreadable config file returns error message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".ai-guardian.json"
            config_file.write_text('{"test": "data"}')

            # Make file unreadable
            import os
            os.chmod(config_file, 0o000)

            with patch('ai_guardian.get_config_dir') as mock_get_config_dir:
                mock_get_config_dir.return_value = Path("/nonexistent/path")

                old_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    config, error = _load_config_file()

                    # Should return None config and error message
                    self.assertIsNone(config)
                    self.assertIsNotNone(error)
                    self.assertIn("Configuration Error", error)
                finally:
                    os.chdir(old_cwd)
                    # Restore permissions for cleanup
                    os.chmod(config_file, 0o644)

    def test_malformed_json_prints_to_stderr(self):
        """Test that malformed JSON error is printed to stderr."""
        malformed_json = """{
  "permissions": [
    {
      "matcher": "Skill",
      "action": "warn"
      "patterns": ["test"]
    }
  ]
}"""

        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".ai-guardian.json"
            config_file.write_text(malformed_json)

            with patch('ai_guardian.get_config_dir') as mock_get_config_dir:
                mock_get_config_dir.return_value = Path("/nonexistent/path")

                import os
                old_cwd = os.getcwd()
                old_stderr = sys.stderr
                try:
                    os.chdir(tmpdir)
                    # Capture stderr
                    captured_stderr = StringIO()
                    sys.stderr = captured_stderr

                    config, error = _load_config_file()

                    # Restore stderr
                    sys.stderr = old_stderr
                    stderr_output = captured_stderr.getvalue()

                    # Should return error message
                    self.assertIsNone(config)
                    self.assertIsNotNone(error)

                    # Should print to stderr
                    self.assertIn("Configuration Error", stderr_output)
                    self.assertIn("JSON Error", stderr_output)
                    self.assertIn(str(config_file), stderr_output)
                    self.assertIn("line", stderr_output.lower())
                    self.assertIn("column", stderr_output.lower())
                finally:
                    os.chdir(old_cwd)
                    sys.stderr = old_stderr


    def test_json_error_with_format_response_blocking(self):
        """Test that JSON errors are included when blocking operations."""
        from ai_guardian import format_response, IDEType

        warning_msg = "⚠️  Configuration Error: Failed to parse config\nJSON Error: missing comma"
        error_msg = "🚨 BLOCKED: Secret detected"

        # Test Claude Code with prompt hook (blocking)
        result = format_response(
            IDEType.CLAUDE_CODE,
            has_secrets=True,
            error_message=error_msg,
            hook_event="prompt",
            warning_message=warning_msg
        )

        # Should include both warning and error
        output = json.loads(result["output"])
        self.assertIn(warning_msg, output["reason"])
        self.assertIn(error_msg, output["reason"])
        # Warning should appear before error
        self.assertTrue(output["reason"].index(warning_msg) < output["reason"].index(error_msg))

    def test_json_error_with_format_response_log_mode(self):
        """Test that JSON errors are shown in log mode (no blocking)."""
        from ai_guardian import format_response, IDEType

        warning_msg = "⚠️  Configuration Error: Failed to parse config\nJSON Error: missing comma"

        # Test Claude Code with prompt hook (log mode)
        result = format_response(
            IDEType.CLAUDE_CODE,
            has_secrets=False,
            hook_event="prompt",
            warning_message=warning_msg
        )

        # Should include warning in systemMessage
        output = json.loads(result["output"])
        self.assertIn("systemMessage", output)
        self.assertIn(warning_msg, output["systemMessage"])


if __name__ == '__main__':
    unittest.main()
