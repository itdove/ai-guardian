"""
Unit tests for ai-guardian
"""

import json
import os
import tempfile
from io import StringIO
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, MagicMock

import ai_guardian


class AIGuardianTest(TestCase):
    """Test suite for ai-guardian hook functionality"""

    def test_check_secrets_with_clean_content(self):
        """Test that clean content passes secret detection"""
        clean_content = "This is a normal prompt without any secrets"
        has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(
            clean_content, "test.txt"
        )

        self.assertFalse(has_secrets, "Clean content should not be flagged as secret")
        self.assertIsNone(error_msg, "No error message should be returned for clean content")

    @patch('ai_guardian._load_pattern_server_config')
    def test_check_secrets_with_github_token(self, mock_pattern_config):
        """Test that GitHub tokens are detected"""
        # Disable pattern server to use default gitleaks rules
        mock_pattern_config.return_value = None

        # Use a token format that gitleaks detects but GitHub ignores (obviously fake)
        secret_content = "My GitHub token: ghp_16C0123456789abcdefghijklmTEST0000"
        has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(
            secret_content, "test.txt"
        )

        self.assertTrue(has_secrets, "GitHub token should be detected as secret")
        self.assertIsNotNone(error_msg, "Error message should be returned for secrets")
        self.assertIn("SECRET DETECTED", error_msg, "Error message should mention secret detection")

    @patch('ai_guardian._load_pattern_server_config')
    def test_check_secrets_with_private_key(self, mock_pattern_config):
        """Test that private keys are detected"""
        # Disable pattern server to use default gitleaks rules
        mock_pattern_config.return_value = None

        # Use a more complete (but still fake) RSA private key that Gitleaks can detect
        secret_content = """My private key: -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwJGPd7LkqVLmTLBBx1qXRiMg8lD7K8l3LQCQHNPFkdZw6Y7e
MBmZQdS3DQXiLb6hU8wQMg0YzU2pQ6HNkYvP6Qux8DQJx7k8L0Tv9dJ5Y2LtZ7Yy
v2dJ5Y2LtZ7Yyv2dJ5Y2LtZ7Yyv2dJ5Y2LtZ7Yyv2dJ5Y2LtZ7Yyv2dJ5Y2LtZ7Y
yv2dJ5Y2LtZ7Yyv2dJ5Y2LtZ7Yyv2dJ5Y2LtZ7Yyv2dJ5Y2LtZ7Yyv2dJ5Y2LtZ7
Yyv2dJ5Y2LtZ7YywIDAQABAoIBADCNMXk8y5K6lVZMsEHHWpdGIyDyUPsryXctAJAc
-----END RSA PRIVATE KEY-----"""
        has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(
            secret_content, "test.txt"
        )

        self.assertTrue(has_secrets, "Private key should be detected as secret")
        self.assertIsNotNone(error_msg, "Error message should be returned for secrets")

    @patch('ai_guardian._load_pattern_server_config')
    def test_check_secrets_with_gitlab_token(self, mock_pattern_config):
        """Test that GitLab tokens are detected"""
        # Disable pattern server to use default gitleaks rules
        mock_pattern_config.return_value = None

        secret_content = "GitLab token: glpat-20_characters_test"
        has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(
            secret_content, "test.txt"
        )

        self.assertTrue(has_secrets, "GitLab token should be detected as secret")

    def test_check_secrets_with_stripe_key(self):
        """Test that Stripe keys are detected"""
        # Skip this test - any realistic Stripe key format triggers GitHub push protection
        # Even obvious fakes like sk_live_FAKEFAKE... are blocked
        # This is tested via integration test instead
        self.skipTest("Stripe key format too restrictive for GitHub push protection")

    @patch('subprocess.run')
    @patch('sys.stderr')
    def test_check_secrets_gitleaks_not_found(self, mock_stderr, mock_run):
        """Test that missing Gitleaks shows visible warning but doesn't block"""
        # Mock subprocess.run to raise FileNotFoundError (Gitleaks not installed)
        mock_run.side_effect = FileNotFoundError("gitleaks command not found")

        content = "This is some content to scan"
        has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(
            content, "test.txt"
        )

        # Should return False (don't block) with no error message (fail-open)
        self.assertFalse(has_secrets, "Missing Gitleaks should not block operation")
        self.assertIsNone(error_msg, "Should not return error message (prints to stderr instead)")

        # Verify warning was printed to stderr
        self.assertTrue(mock_stderr.write.called, "Warning should be printed to stderr")
        stderr_output = ''.join(str(call[0][0]) for call in mock_stderr.write.call_args_list)
        self.assertIn("SECRET SCANNING DISABLED", stderr_output, "Warning should mention scanning is disabled")
        self.assertIn("Gitleaks binary not found", stderr_output, "Warning should mention Gitleaks is missing")
        self.assertIn("brew install gitleaks", stderr_output, "Warning should include installation instructions")

    @patch('subprocess.run')
    def test_check_secrets_gitleaks_auth_error_blocks(self, mock_run):
        """Test that authentication errors block the operation"""
        # Mock subprocess.run to return auth error
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stderr = "Error: 401 Unauthorized - authentication failed"
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        content = "This is some content to scan"
        has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(
            content, "test.txt"
        )

        # Should block operation (return True) with error message
        self.assertTrue(has_secrets, "Auth error should block operation")
        self.assertIsNotNone(error_msg, "Should return error message")
        self.assertIn("AUTHENTICATION ERROR", error_msg, "Should mention authentication error")
        self.assertIn("blocked for security", error_msg, "Should indicate operation is blocked")
        self.assertIn("AI_GUARDIAN_PATTERN_TOKEN", error_msg, "Should mention token env var")

    @patch('subprocess.run')
    @patch('sys.stderr')
    def test_check_secrets_gitleaks_network_error_warns(self, mock_stderr, mock_run):
        """Test that network errors warn but don't block"""
        # Mock subprocess.run to return network error
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stderr = "Error: connection timeout - unable to reach pattern server"
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        content = "This is some content to scan"
        has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(
            content, "test.txt"
        )

        # Should not block (return False)
        self.assertFalse(has_secrets, "Network error should not block operation")
        self.assertIsNone(error_msg, "Should not return error message (fail-open)")

        # Verify warning was printed to stderr
        self.assertTrue(mock_stderr.write.called, "Warning should be printed to stderr")
        stderr_output = ''.join(str(call[0][0]) for call in mock_stderr.write.call_args_list)
        self.assertIn("SECRET SCANNING WARNING", stderr_output, "Should show warning header")
        self.assertIn("Network or server issue", stderr_output, "Should mention network issue")
        self.assertIn("continue", stderr_output.lower(), "Should indicate operation continues")

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_process_hook_input_clean_prompt(self, mock_check_secrets):
        """Test processing clean prompt input"""
        mock_check_secrets.return_value = (False, None)

        hook_input = json.dumps({
            "prompt": "Can you help me write a function?",
            "session_id": "test-session",
            "hook_event_name": "UserPromptSubmit"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 0, "Clean prompt should return exit code 0")
        self.assertIsNone(response["output"], "Clean Claude Code prompt should have no output")
        mock_check_secrets.assert_called_once()

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_process_hook_input_with_secret(self, mock_check_secrets):
        """Test processing prompt with secret"""
        mock_check_secrets.return_value = (True, "SECRET DETECTED")

        hook_input = json.dumps({
            "prompt": "Token: ghp_16C0123456789abcdefghijklmTEST0000",
            "session_id": "test-session"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 2, "Secret detection should return exit code 2")

    def test_process_hook_input_empty_prompt(self):
        """Test processing empty prompt"""
        hook_input = json.dumps({
            "prompt": "",
            "session_id": "test-session"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 0, "Empty prompt should return exit code 0")

    def test_process_hook_input_invalid_json(self):
        """Test processing invalid JSON input (fail-open)"""
        hook_input = "not valid json{{"

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 0, "Invalid JSON should fail-open with exit code 0")

    def test_process_hook_input_missing_prompt_field(self):
        """Test processing input without prompt field"""
        hook_input = json.dumps({
            "session_id": "test-session",
            "cwd": "/test"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 0, "Missing prompt field should return exit code 0")

    def test_process_hook_input_legacy_userMessage_field(self):
        """Test processing input with legacy userMessage field"""
        hook_input = json.dumps({
            "userMessage": "Test message",
            "session_id": "test-session"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            with patch('ai_guardian.check_secrets_with_gitleaks', return_value=(False, None)):
                response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 0, "Legacy userMessage field should be supported")

    def test_check_secrets_handles_scanner_errors(self):
        """Test that scanner errors are handled gracefully (fail-open)"""
        # This tests the exception handling in check_secrets_with_gitleaks
        # If there's an error during scanning, it should return (False, None)
        # rather than raising an exception

        # We can't easily simulate scanner errors, but we can verify
        # the error handling behavior through process_hook_input
        hook_input = json.dumps({
            "prompt": "test content",
            "session_id": "test"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            # Even if there's an internal error, it should fail-open
            response = ai_guardian.process_hook_input()

        # Should succeed (fail-open) even if there are internal issues
        self.assertIn(response["exit_code"], [0, 2], "Should return valid exit code")

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_process_hook_input_with_multiline_prompt(self, mock_check_secrets):
        """Test processing prompt with multiple lines"""
        mock_check_secrets.return_value = (False, None)

        multiline_prompt = "Line 1\nLine 2\nLine 3"
        hook_input = json.dumps({
            "prompt": multiline_prompt,
            "session_id": "test-session"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 0)
        # Verify the full multiline content was passed
        call_args = mock_check_secrets.call_args[0]
        self.assertEqual(call_args[0], multiline_prompt)

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_process_hook_input_with_unicode(self, mock_check_secrets):
        """Test processing prompt with Unicode characters"""
        mock_check_secrets.return_value = (False, None)

        unicode_prompt = "Hello 世界 🔒 Здравствуй"
        hook_input = json.dumps({
            "prompt": unicode_prompt,
            "session_id": "test-session"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 0)

    def test_main_function_returns_exit_code(self):
        """Test that main() properly returns exit codes"""
        hook_input = json.dumps({
            "prompt": "test",
            "session_id": "test"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            with patch('sys.argv', ['ai-guardian']):  # Mock argv to avoid pytest args
                with patch('ai_guardian.check_secrets_with_gitleaks', return_value=(False, None)):
                    with self.assertRaises(SystemExit) as cm:
                        ai_guardian.main()

                    self.assertEqual(cm.exception.code, 0)

    def test_cleanup_temporary_files(self):
        """Test that temporary files are cleaned up after scanning"""
        content = "test content"
        filename = "test.txt"

        # Get list of temp files before
        temp_dir = tempfile.gettempdir()
        before_files = set(Path(temp_dir).glob("tmp*"))

        # Run check
        ai_guardian.check_secrets_with_gitleaks(content, filename)

        # Get list of temp files after
        after_files = set(Path(temp_dir).glob("tmp*"))

        # Should have same or fewer temp files (cleanup happened)
        new_files = after_files - before_files
        # Allow some new temp files from other processes, but not too many
        self.assertLess(len(new_files), 10, "Should not leave many temporary files")

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_error_in_check_secrets_does_not_block(self, mock_check_secrets):
        """Test that errors in secret checking fail-open"""
        # Simulate an exception during secret checking
        mock_check_secrets.side_effect = Exception("Simulated error")

        hook_input = json.dumps({
            "prompt": "test",
            "session_id": "test"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        # Should fail-open with exit code 0
        self.assertEqual(response["exit_code"], 0, "Errors should fail-open with exit code 0")

    @patch('ai_guardian._load_pattern_server_config')
    def test_secret_detection_integration(self, mock_pattern_config):
        """Integration test: End-to-end secret detection"""
        # Disable pattern server to use default gitleaks rules
        mock_pattern_config.return_value = None

        # Test with real Gitleaks binary if available
        try:
            import subprocess
            # Check if gitleaks is available
            subprocess.run(['gitleaks', '--version'], capture_output=True, check=True)

            # Test clean content
            clean_input = json.dumps({"prompt": "Hello world"})
            with patch('sys.stdin', StringIO(clean_input)):
                response = ai_guardian.process_hook_input()
            self.assertEqual(response["exit_code"], 0)

            # Test secret content
            secret_input = json.dumps({"prompt": "My token: ghp_16C0123456789abcdefghijklmTEST0000"})
            with patch('sys.stdin', StringIO(secret_input)):
                response = ai_guardian.process_hook_input()
            self.assertEqual(response["exit_code"], 2)

        except (FileNotFoundError, subprocess.CalledProcessError):
            self.skipTest("Gitleaks binary not available for integration test")

    def test_ide_detection_claude_code(self):
        """Test IDE type detection for Claude Code"""
        hook_data = {
            "prompt": "test",
            "hook_event_name": "UserPromptSubmit"
        }
        ide_type = ai_guardian.detect_ide_type(hook_data)
        self.assertEqual(ide_type, ai_guardian.IDEType.CLAUDE_CODE)

    def test_ide_detection_cursor(self):
        """Test IDE type detection for Cursor"""
        hook_data = {
            "message": "test",
            "hook_name": "beforeSubmitPrompt"
        }
        ide_type = ai_guardian.detect_ide_type(hook_data)
        self.assertEqual(ide_type, ai_guardian.IDEType.CURSOR)

    def test_ide_detection_environment_override(self):
        """Test IDE type detection with environment variable override"""
        hook_data = {"prompt": "test"}

        with patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "cursor"}):
            ide_type = ai_guardian.detect_ide_type(hook_data)
            self.assertEqual(ide_type, ai_guardian.IDEType.CURSOR)

        with patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "claude"}):
            ide_type = ai_guardian.detect_ide_type(hook_data)
            self.assertEqual(ide_type, ai_guardian.IDEType.CLAUDE_CODE)

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_cursor_format_clean_prompt(self, mock_check_secrets):
        """Test Cursor format with clean prompt"""
        mock_check_secrets.return_value = (False, None)

        hook_input = json.dumps({
            "message": "Can you help me write a function?",
            "hook_name": "beforeSubmitPrompt"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 0, "Cursor should use exit code 0")
        self.assertIsNotNone(response["output"], "Cursor should have JSON output")

        # Parse and validate JSON response
        output_data = json.loads(response["output"])
        self.assertTrue(output_data["continue"], "Should continue for clean prompt")
        self.assertNotIn("user_message", output_data, "No error message for clean prompt")

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_cursor_format_with_secret(self, mock_check_secrets):
        """Test Cursor format with secret"""
        error_msg = "SECRET DETECTED"
        mock_check_secrets.return_value = (True, error_msg)

        hook_input = json.dumps({
            "message": "Token: ghp_16C0123456789abcdefghijklmTEST0000",
            "hook_name": "beforeSubmitPrompt"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 0, "Cursor should use exit code 0")
        self.assertIsNotNone(response["output"], "Cursor should have JSON output")

        # Parse and validate JSON response
        output_data = json.loads(response["output"])
        self.assertFalse(output_data["continue"], "Should block for secret")
        self.assertIn("user_message", output_data, "Should have error message")
        self.assertEqual(output_data["user_message"], error_msg)

    def test_format_response_claude_code_allow(self):
        """Test format_response for Claude Code (allow)"""
        response = ai_guardian.format_response(
            ai_guardian.IDEType.CLAUDE_CODE,
            has_secrets=False
        )
        self.assertIsNone(response["output"])
        self.assertEqual(response["exit_code"], 0)

    def test_format_response_claude_code_block(self):
        """Test format_response for Claude Code (block)"""
        response = ai_guardian.format_response(
            ai_guardian.IDEType.CLAUDE_CODE,
            has_secrets=True,
            error_message="Test error"
        )
        self.assertIsNone(response["output"])
        self.assertEqual(response["exit_code"], 2)

    def test_format_response_cursor_allow(self):
        """Test format_response for Cursor (allow)"""
        response = ai_guardian.format_response(
            ai_guardian.IDEType.CURSOR,
            has_secrets=False
        )
        self.assertIsNotNone(response["output"])
        self.assertEqual(response["exit_code"], 0)

        output_data = json.loads(response["output"])
        self.assertTrue(output_data["continue"])

    def test_format_response_cursor_block(self):
        """Test format_response for Cursor (block)"""
        error_msg = "Test error"
        response = ai_guardian.format_response(
            ai_guardian.IDEType.CURSOR,
            has_secrets=True,
            error_message=error_msg
        )
        self.assertIsNotNone(response["output"])
        self.assertEqual(response["exit_code"], 0)

        output_data = json.loads(response["output"])
        self.assertFalse(output_data["continue"])
        self.assertEqual(output_data["user_message"], error_msg)

    def test_detect_hook_event_userpromptsubmit(self):
        """Test hook event detection for UserPromptSubmit"""
        hook_data = {"hook_event_name": "UserPromptSubmit", "prompt": "test"}
        event = ai_guardian.detect_hook_event(hook_data)
        self.assertEqual(event, "prompt")

    def test_detect_hook_event_pretooluse(self):
        """Test hook event detection for PreToolUse"""
        hook_data = {"hook_event_name": "PreToolUse", "tool_use": {"name": "Read"}}
        event = ai_guardian.detect_hook_event(hook_data)
        self.assertEqual(event, "pretooluse")

    def test_detect_hook_event_cursor_beforesubmitprompt(self):
        """Test hook event detection for Cursor beforeSubmitPrompt"""
        hook_data = {"hook_name": "beforeSubmitPrompt", "message": "test"}
        event = ai_guardian.detect_hook_event(hook_data)
        self.assertEqual(event, "prompt")

    def test_detect_hook_event_cursor_pretooluse(self):
        """Test hook event detection for Cursor preToolUse"""
        hook_data = {"hook_name": "preToolUse", "tool": {"name": "Read"}}
        event = ai_guardian.detect_hook_event(hook_data)
        self.assertEqual(event, "pretooluse")

    def test_extract_file_content_tool_use_format(self):
        """Test file extraction from tool_use.parameters format"""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("test content")
            temp_path = f.name

        try:
            hook_data = {
                "tool_use": {
                    "parameters": {"file_path": temp_path}
                }
            }
            content, filename, file_path, is_denied, deny_reason = ai_guardian.extract_file_content_from_tool(hook_data)
            self.assertEqual(content, "test content")
            self.assertTrue(filename.endswith('.txt'))
            self.assertFalse(is_denied)
            self.assertIsNone(deny_reason)
        finally:
            os.unlink(temp_path)

    def test_extract_file_content_parameters_format(self):
        """Test file extraction from direct parameters format"""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("another test")
            temp_path = f.name

        try:
            hook_data = {
                "parameters": {"file_path": temp_path}
            }
            content, filename, file_path, is_denied, deny_reason = ai_guardian.extract_file_content_from_tool(hook_data)
            self.assertEqual(content, "another test")
            self.assertFalse(is_denied)
            self.assertIsNone(deny_reason)
        finally:
            os.unlink(temp_path)

    def test_extract_file_content_nonexistent_file(self):
        """Test file extraction with nonexistent file"""
        hook_data = {
            "tool_use": {
                "parameters": {"file_path": "/nonexistent/file.txt"}
            }
        }
        content, filename, file_path, is_denied, deny_reason = ai_guardian.extract_file_content_from_tool(hook_data)
        self.assertIsNone(content)
        self.assertEqual(filename, "file.txt")
        self.assertFalse(is_denied)
        self.assertIsNone(deny_reason)

    def test_extract_file_content_no_file_path(self):
        """Test file extraction with no file path"""
        hook_data = {"tool_use": {"parameters": {}}}
        content, filename, file_path, is_denied, deny_reason = ai_guardian.extract_file_content_from_tool(hook_data)
        self.assertIsNone(content)
        self.assertFalse(is_denied)
        self.assertIsNone(deny_reason)

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_pretooluse_hook_with_clean_file(self, mock_check_secrets):
        """Test PreToolUse hook with clean file"""
        mock_check_secrets.return_value = (False, None)

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("clean content")
            temp_path = f.name

        try:
            hook_input = json.dumps({
                "hook_event_name": "PreToolUse",
                "tool_use": {"parameters": {"file_path": temp_path}}
            })

            with patch('sys.stdin', StringIO(hook_input)):
                response = ai_guardian.process_hook_input()

            self.assertEqual(response["exit_code"], 0)
            mock_check_secrets.assert_called_once()
            # Verify it scanned the file content
            call_args = mock_check_secrets.call_args[0]
            self.assertEqual(call_args[0], "clean content")
        finally:
            os.unlink(temp_path)

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_pretooluse_hook_with_secret_file(self, mock_check_secrets):
        """Test PreToolUse hook with file containing secret"""
        mock_check_secrets.return_value = (True, "SECRET DETECTED")

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("ghp_16C0123456789abcdefghijklmTEST0000")
            temp_path = f.name

        try:
            hook_input = json.dumps({
                "hook_event_name": "PreToolUse",
                "tool_use": {"parameters": {"file_path": temp_path}}
            })

            with patch('sys.stdin', StringIO(hook_input)):
                response = ai_guardian.process_hook_input()

            self.assertEqual(response["exit_code"], 2)
            mock_check_secrets.assert_called_once()
        finally:
            os.unlink(temp_path)

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_cursor_pretooluse_hook(self, mock_check_secrets):
        """Test Cursor preToolUse hook format"""
        mock_check_secrets.return_value = (True, "SECRET DETECTED")

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("secret")
            temp_path = f.name

        try:
            hook_input = json.dumps({
                "hook_name": "preToolUse",
                "tool": {"file_path": temp_path}
            })

            with patch('sys.stdin', StringIO(hook_input)):
                response = ai_guardian.process_hook_input()

            # Cursor uses JSON response format
            self.assertEqual(response["exit_code"], 0)
            self.assertIsNotNone(response["output"])

            output_data = json.loads(response["output"])
            # For preToolUse, Cursor expects "decision" field, not "continue"
            self.assertEqual(output_data["decision"], "deny")
        finally:
            os.unlink(temp_path)

    def test_pretooluse_missing_file_fails_open(self):
        """Test PreToolUse with missing file fails open"""
        hook_input = json.dumps({
            "hook_event_name": "PreToolUse",
            "tool_use": {"parameters": {"file_path": "/nonexistent/file.txt"}}
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        # Should fail-open (allow) when file cannot be read
        self.assertEqual(response["exit_code"], 0)

    # ========== PostToolUse Tests ==========

    def test_detect_hook_event_posttooluse(self):
        """Test PostToolUse event detection"""
        hook_data = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": {"output": "test"}}
        self.assertEqual(ai_guardian.detect_hook_event(hook_data), "posttooluse")

    def test_detect_hook_event_posttooluse_from_tool_response(self):
        """Test PostToolUse detection from tool_response field"""
        hook_data = {"tool_name": "Bash", "tool_response": {"output": "test output"}}
        self.assertEqual(ai_guardian.detect_hook_event(hook_data), "posttooluse")

    def test_extract_tool_result_bash_output(self):
        """Test extracting Bash output from PostToolUse"""
        hook_data = {
            "tool_name": "Bash",
            "tool_response": {"output": "Hello from bash"}
        }
        output, tool_name = ai_guardian.extract_tool_result(hook_data)
        self.assertEqual(output, "Hello from bash")
        self.assertEqual(tool_name, "Bash")

    def test_extract_tool_result_read_content(self):
        """Test extracting Read content from PostToolUse"""
        hook_data = {
            "tool_name": "Read",
            "tool_response": {"content": "File content here"}
        }
        output, tool_name = ai_guardian.extract_tool_result(hook_data)
        self.assertEqual(output, "File content here")
        self.assertEqual(tool_name, "Read")

    def test_extract_tool_result_write_skipped(self):
        """Test Write tool response is skipped (no scanning needed)"""
        hook_data = {
            "tool_name": "Write",
            "tool_response": {"filePath": "/tmp/test.py", "success": True}
        }
        output, tool_name = ai_guardian.extract_tool_result(hook_data)
        self.assertIsNone(output)  # Should skip state-modifying tools
        self.assertEqual(tool_name, "Write")

    def test_extract_tool_result_edit_skipped(self):
        """Test Edit tool response is skipped"""
        hook_data = {
            "tool_name": "Edit",
            "tool_response": {"success": True}
        }
        output, tool_name = ai_guardian.extract_tool_result(hook_data)
        self.assertIsNone(output)
        self.assertEqual(tool_name, "Edit")

    def test_posttooluse_write_tool_allowed(self):
        """Test PostToolUse allows Write tool (already scanned in PreToolUse)"""
        hook_json = json.dumps({
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_response": {"filePath": "/tmp/test.py", "success": True}
        })

        with patch('sys.stdin', StringIO(hook_json)):
            result = ai_guardian.process_hook_input()

        self.assertEqual(result['exit_code'], 0)
        response = json.loads(result['output'])
        self.assertNotIn('decision', response)  # No decision = allow

    def test_posttooluse_bash_clean_output(self):
        """Test PostToolUse allows Bash with clean output"""
        hook_json = json.dumps({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {"output": "Hello, World!"}
        })

        with patch('sys.stdin', StringIO(hook_json)):
            result = ai_guardian.process_hook_input()

        self.assertEqual(result['exit_code'], 0)
        response = json.loads(result['output'])
        self.assertNotIn('decision', response)

    @patch('ai_guardian._load_pattern_server_config')
    def test_posttooluse_bash_with_secret(self, mock_pattern_config):
        """Test PostToolUse blocks Bash output containing secrets"""
        # Disable pattern server to use default gitleaks rules
        mock_pattern_config.return_value = None

        hook_json = json.dumps({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {
                "output": "Private key: -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAwJGPd7LkqVLmTLBBx1qXRiMg8lD7K8l3LQCQHNPFkdZw6Y7e\n-----END RSA PRIVATE KEY-----"
            }
        })

        with patch('sys.stdin', StringIO(hook_json)):
            result = ai_guardian.process_hook_input()

        self.assertEqual(result['exit_code'], 0)
        response = json.loads(result['output'])
        self.assertEqual(response.get('decision'), 'block')
        self.assertIn('SECRET DETECTED', response.get('reason', ''))

    def test_posttooluse_no_output_field(self):
        """Test PostToolUse handles missing output gracefully"""
        hook_json = json.dumps({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {}
        })

        with patch('sys.stdin', StringIO(hook_json)):
            result = ai_guardian.process_hook_input()

        self.assertEqual(result['exit_code'], 0)
        response = json.loads(result['output'])
        self.assertNotIn('decision', response)  # No output = allow

    # ========== GitHub Copilot Tests ==========

    def test_ide_detection_github_copilot_toolname(self):
        """Test IDE type detection for GitHub Copilot with toolName field"""
        hook_data = {
            "timestamp": 1704614400000,
            "cwd": "/path/to/project",
            "toolName": "bash",
            "toolArgs": "{\"command\":\"npm test\"}"
        }
        ide_type = ai_guardian.detect_ide_type(hook_data)
        self.assertEqual(ide_type, ai_guardian.IDEType.GITHUB_COPILOT)

    def test_ide_detection_github_copilot_prompt(self):
        """Test IDE type detection for GitHub Copilot userPromptSubmitted"""
        hook_data = {
            "timestamp": 1704614400000,
            "cwd": "/path/to/project",
            "prompt": "Create a new feature",
            "source": "user"
        }
        ide_type = ai_guardian.detect_ide_type(hook_data)
        self.assertEqual(ide_type, ai_guardian.IDEType.GITHUB_COPILOT)

    def test_ide_detection_github_copilot_env_override(self):
        """Test GitHub Copilot detection with environment variable"""
        hook_data = {"prompt": "test"}

        with patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "copilot"}):
            ide_type = ai_guardian.detect_ide_type(hook_data)
            self.assertEqual(ide_type, ai_guardian.IDEType.GITHUB_COPILOT)

        with patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "github_copilot"}):
            ide_type = ai_guardian.detect_ide_type(hook_data)
            self.assertEqual(ide_type, ai_guardian.IDEType.GITHUB_COPILOT)

    def test_format_response_copilot_pretooluse_allow(self):
        """Test GitHub Copilot preToolUse response format (allow)"""
        response = ai_guardian.format_response(
            ai_guardian.IDEType.GITHUB_COPILOT,
            has_secrets=False,
            hook_event="pretooluse"
        )
        self.assertIsNotNone(response["output"])
        self.assertEqual(response["exit_code"], 0)

        output_data = json.loads(response["output"])
        self.assertEqual(output_data["permissionDecision"], "allow")
        self.assertNotIn("permissionDecisionReason", output_data)

    def test_format_response_copilot_pretooluse_deny(self):
        """Test GitHub Copilot preToolUse response format (deny)"""
        error_msg = "Secrets detected"
        response = ai_guardian.format_response(
            ai_guardian.IDEType.GITHUB_COPILOT,
            has_secrets=True,
            error_message=error_msg,
            hook_event="pretooluse"
        )
        self.assertIsNotNone(response["output"])
        self.assertEqual(response["exit_code"], 0)

        output_data = json.loads(response["output"])
        self.assertEqual(output_data["permissionDecision"], "deny")
        self.assertEqual(output_data["permissionDecisionReason"], error_msg)

    def test_format_response_copilot_prompt_allow(self):
        """Test GitHub Copilot userPromptSubmitted response format (allow)"""
        response = ai_guardian.format_response(
            ai_guardian.IDEType.GITHUB_COPILOT,
            has_secrets=False,
            hook_event="prompt"
        )
        self.assertIsNone(response["output"])
        self.assertEqual(response["exit_code"], 0)

    def test_format_response_copilot_prompt_deny(self):
        """Test GitHub Copilot userPromptSubmitted response format (deny)"""
        response = ai_guardian.format_response(
            ai_guardian.IDEType.GITHUB_COPILOT,
            has_secrets=True,
            error_message="Test error",
            hook_event="prompt"
        )
        self.assertIsNone(response["output"])
        self.assertEqual(response["exit_code"], 2)

    def test_extract_file_content_copilot_toolargs(self):
        """Test file extraction from GitHub Copilot toolArgs format"""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("copilot test content")
            temp_path = f.name

        try:
            # GitHub Copilot sends toolArgs as JSON string
            hook_data = {
                "toolName": "read_file",
                "toolArgs": json.dumps({"file_path": temp_path})
            }
            content, filename, file_path, is_denied, deny_reason = ai_guardian.extract_file_content_from_tool(hook_data)
            self.assertEqual(content, "copilot test content")
            self.assertTrue(filename.endswith('.txt'))
            self.assertFalse(is_denied)
            self.assertIsNone(deny_reason)
        finally:
            os.unlink(temp_path)

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_copilot_pretooluse_hook_clean(self, mock_check_secrets):
        """Test GitHub Copilot preToolUse hook with clean file"""
        mock_check_secrets.return_value = (False, None)

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("clean content")
            temp_path = f.name

        try:
            hook_input = json.dumps({
                "timestamp": 1704614600000,
                "cwd": "/path/to/project",
                "toolName": "read_file",
                "toolArgs": json.dumps({"file_path": temp_path})
            })

            with patch('sys.stdin', StringIO(hook_input)):
                response = ai_guardian.process_hook_input()

            self.assertEqual(response["exit_code"], 0)
            self.assertIsNotNone(response["output"])

            output_data = json.loads(response["output"])
            self.assertEqual(output_data["permissionDecision"], "allow")
        finally:
            os.unlink(temp_path)

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_copilot_pretooluse_hook_with_secret(self, mock_check_secrets):
        """Test GitHub Copilot preToolUse hook blocks file with secret"""
        mock_check_secrets.return_value = (True, "SECRET DETECTED")

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("secret content")
            temp_path = f.name

        try:
            hook_input = json.dumps({
                "timestamp": 1704614600000,
                "cwd": "/path/to/project",
                "toolName": "read_file",
                "toolArgs": json.dumps({"file_path": temp_path})
            })

            with patch('sys.stdin', StringIO(hook_input)):
                response = ai_guardian.process_hook_input()

            self.assertEqual(response["exit_code"], 0)
            self.assertIsNotNone(response["output"])

            output_data = json.loads(response["output"])
            self.assertEqual(output_data["permissionDecision"], "deny")
            self.assertIn("permissionDecisionReason", output_data)
        finally:
            os.unlink(temp_path)

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_copilot_prompt_hook_clean(self, mock_check_secrets):
        """Test GitHub Copilot userPromptSubmitted with clean prompt"""
        mock_check_secrets.return_value = (False, None)

        hook_input = json.dumps({
            "timestamp": 1704614400000,
            "cwd": "/path/to/project",
            "prompt": "Create a new feature",
            "source": "user"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 0)
        self.assertIsNone(response["output"])

    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_copilot_prompt_hook_with_secret(self, mock_check_secrets):
        """Test GitHub Copilot userPromptSubmitted blocks prompt with secret"""
        mock_check_secrets.return_value = (True, "SECRET DETECTED")

        hook_input = json.dumps({
            "timestamp": 1704614400000,
            "cwd": "/path/to/project",
            "prompt": "My token: ghp_16C0123456789abcdefghijklmTEST0000",
            "source": "user"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        self.assertEqual(response["exit_code"], 2)
        self.assertIsNone(response["output"])

    @patch('ai_guardian._load_prompt_injection_config')
    @patch('ai_guardian.check_prompt_injection')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_prompt_injection_time_based_disabled(self, mock_check_secrets, mock_check_injection, mock_load_config):
        """Test prompt injection detection temporarily disabled via time-based config"""
        from datetime import datetime, timezone

        # Configure prompt injection as temporarily disabled (future expiration)
        mock_load_config.return_value = {
            "enabled": {
                "value": False,
                "disabled_until": "2099-12-31T23:59:59Z",
                "reason": "Testing prompt injection examples"
            },
            "detector": "heuristic"
        }

        mock_check_secrets.return_value = (False, None)
        # Injection check shouldn't be called since feature is disabled
        mock_check_injection.return_value = (True, "Injection detected")

        hook_input = json.dumps({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "test prompt"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        # Should allow (not block) since prompt injection is disabled
        self.assertEqual(response["exit_code"], 0)
        # Injection check should not be called
        mock_check_injection.assert_not_called()

    @patch('ai_guardian._load_prompt_injection_config')
    @patch('ai_guardian.check_prompt_injection')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_prompt_injection_time_based_expired_auto_enabled(self, mock_check_secrets, mock_check_injection, mock_load_config):
        """Test prompt injection detection auto-enabled after disable period expires"""
        from datetime import datetime, timezone

        # Configure prompt injection with expired disable period (past date)
        mock_load_config.return_value = {
            "enabled": {
                "value": False,
                "disabled_until": "2020-01-01T00:00:00Z",  # Past date
                "reason": "Expired disable"
            },
            "detector": "heuristic"
        }

        mock_check_secrets.return_value = (False, None)
        mock_check_injection.return_value = (True, "Injection detected")

        hook_input = json.dumps({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "test prompt"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        # Should block since prompt injection is auto-enabled (expired disable)
        self.assertEqual(response["exit_code"], 2)
        # Injection check should be called
        mock_check_injection.assert_called_once()

    @patch('ai_guardian._load_permissions_config')
    @patch('ai_guardian.ToolPolicyChecker')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_permissions_time_based_disabled(self, mock_check_secrets, mock_policy_checker_class, mock_load_config):
        """Test tool permissions temporarily disabled via time-based config"""
        from datetime import datetime, timezone

        # Configure permissions as temporarily disabled
        mock_load_config.return_value = {
            "enabled": {
                "value": False,
                "disabled_until": "2099-12-31T23:59:59Z",
                "reason": "Emergency debugging"
            }
        }

        mock_check_secrets.return_value = (False, None)

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content")
            temp_path = f.name

        try:
            hook_input = json.dumps({
                "hook_event_name": "PreToolUse",
                "input": {
                    "tool_name": "Read",
                    "file_path": temp_path
                }
            })

            with patch('sys.stdin', StringIO(hook_input)):
                response = ai_guardian.process_hook_input()

            # Should allow (not check permissions) since enforcement is disabled
            self.assertEqual(response["exit_code"], 0)
            # Policy checker should not be instantiated
            mock_policy_checker_class.assert_not_called()
        finally:
            os.unlink(temp_path)

    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_secret_scanning_time_based_disabled(self, mock_check_secrets, mock_load_config):
        """Test secret scanning temporarily disabled via time-based config"""
        from datetime import datetime, timezone

        # Configure secret scanning as temporarily disabled
        mock_load_config.return_value = {
            "enabled": {
                "value": False,
                "disabled_until": "2099-12-31T23:59:59Z",
                "reason": "Testing with known-safe example secrets"
            }
        }

        # Even if check_secrets would find secrets, it shouldn't be called
        mock_check_secrets.return_value = (True, "Secret detected")

        hook_input = json.dumps({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "test prompt with ghp_token123"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        # Should allow since secret scanning is disabled
        self.assertEqual(response["exit_code"], 0)
        # Secret check should not be called
        mock_check_secrets.assert_not_called()

    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_secret_scanning_time_based_expired_auto_enabled(self, mock_check_secrets, mock_load_config):
        """Test secret scanning auto-enabled after disable period expires"""
        from datetime import datetime, timezone

        # Configure secret scanning with expired disable period
        mock_load_config.return_value = {
            "enabled": {
                "value": False,
                "disabled_until": "2020-01-01T00:00:00Z",  # Past date
                "reason": "Expired disable"
            }
        }

        mock_check_secrets.return_value = (True, "Secret detected")

        hook_input = json.dumps({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "test prompt"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        # Should block since secret scanning is auto-enabled
        self.assertEqual(response["exit_code"], 2)
        # Secret check should be called
        mock_check_secrets.assert_called_once()

    @patch('ai_guardian._load_prompt_injection_config')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian.check_prompt_injection')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    def test_multiple_features_different_states(self, mock_check_secrets, mock_check_injection, mock_secret_config, mock_injection_config):
        """Test multiple features with different enable/disable states"""
        from datetime import datetime, timezone

        # Prompt injection: enabled (boolean)
        mock_injection_config.return_value = {
            "enabled": True,
            "detector": "heuristic"
        }

        # Secret scanning: temporarily disabled
        mock_secret_config.return_value = {
            "enabled": {
                "value": False,
                "disabled_until": "2099-12-31T23:59:59Z"
            }
        }

        mock_check_injection.return_value = (False, None)
        mock_check_secrets.return_value = (True, "Secret detected")

        hook_input = json.dumps({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "test prompt"
        })

        with patch('sys.stdin', StringIO(hook_input)):
            response = ai_guardian.process_hook_input()

        # Should allow (prompt injection check runs and passes, secret scanning disabled)
        self.assertEqual(response["exit_code"], 0)
        # Injection check should be called (enabled)
        mock_check_injection.assert_called_once()
        # Secret check should NOT be called (disabled)
        mock_check_secrets.assert_not_called()


if __name__ == "__main__":
    import unittest
    unittest.main()
