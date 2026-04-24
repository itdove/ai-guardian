"""
Test hook processing logic in ai_guardian.__init__.py

Tests the main hook processing functions including input parsing,
hook event routing, and response formatting.
"""

import json
from io import StringIO
from unittest import TestCase
from unittest.mock import patch

from tests.fixtures.mock_mcp_server import create_hook_data
from tests.fixtures import attack_constants
import ai_guardian


class HookInputParsingTests(TestCase):
    """Test hook input parsing and validation"""

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_valid_json_processed(self, mock_pattern_config, mock_redaction_config):
        """Verify valid JSON hook data is processed"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Normal prompt"
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        assert result is not None
        assert 'exit_code' in result

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_userpromptsubmit_hook_processing(self, mock_pattern_config, mock_redaction_config):
        """Test UserPromptSubmit hook is processed"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "What is the capital of France?"
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0, "Normal prompt should be allowed"

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_pretooluse_hook_processing(self, mock_pattern_config, mock_redaction_config):
        """Test PreToolUse hook is processed"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        hook_data = create_hook_data(
            tool_name="Bash",
            tool_input={"command": "ls -la"},
            hook_event="PreToolUse"
        )

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0, "Normal Bash command should be allowed"

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_posttooluse_hook_processing(self, mock_pattern_config, mock_redaction_config):
        """Test PostToolUse hook is processed"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {
                "output": "Hello, World!"
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0, "Clean output should be allowed"


class HookToolResponseExtractionTests(TestCase):
    """Test tool response extraction for different tools"""

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_bash_output_extraction(self, mock_pattern_config, mock_redaction_config):
        """Verify Bash output is extracted correctly"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {
                "output": "Command output here"
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_read_content_extraction(self, mock_pattern_config, mock_redaction_config):
        """Verify Read file content is extracted correctly"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": {
                "content": "File content here"
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_mcp_tool_response_extraction(self, mock_pattern_config, mock_redaction_config):
        """Verify MCP tool responses are handled"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": attack_constants.MCP_TOOL_NOTEBOOKLM_QUERY,
            "tool_response": {
                "answer": "Query result",
                "sources": []
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_tool_with_no_scannable_output(self, mock_pattern_config, mock_redaction_config):
        """Verify tools with no scannable output are skipped"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_response": {
                "success": True,
                "file_path": "/tmp/test.txt"
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        # Write tool output shouldn't be scanned
        assert result['exit_code'] == 0


class PreToolUsePermissionTests(TestCase):
    """Test PreToolUse hook permission decision behavior

    Note: Edit/Write tools don't scan content for secrets in PreToolUse
    (they return early with has_secrets=False). This tests that they
    don't get auto-approved when clean.
    """

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_pretooluse_no_permission_override_for_edit_claude_code(self, mock_pattern_config, mock_redaction_config):
        """Verify PreToolUse does NOT auto-approve Edit operations (Claude Code)"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        # Edit tool with clean content
        # Edit tools don't scan for secrets in PreToolUse - they return has_secrets=False
        hook_data = create_hook_data(
            tool_name="Edit",
            tool_input={
                "file_path": "/tmp/config.py",
                "old_string": "old code",
                "new_string": "print('Hello, World!')"
            },
            hook_event="PreToolUse"
        )

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        # Should allow (exit_code 0)
        assert result['exit_code'] == 0

        # Parse JSON response
        response = json.loads(result['output'])

        # CRITICAL: Should NOT contain permissionDecision when no threat detected
        # This allows Claude Code's normal permission system to prompt user
        if 'hookSpecificOutput' in response:
            assert 'permissionDecision' not in response['hookSpecificOutput'], \
                "permissionDecision should be omitted to allow normal permission prompt"
        # Also check that response is empty (no auto-approve)
        assert response == {} or 'systemMessage' in response, \
            "Response should be empty or only contain systemMessage (warnings)"

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    @patch('ai_guardian.detect_ide_type')
    def test_pretooluse_no_permission_override_for_edit_github_copilot(self, mock_ide_type, mock_pattern_config, mock_redaction_config):
        """Verify PreToolUse does NOT auto-approve Edit operations (GitHub Copilot)"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)
        mock_ide_type.return_value = ai_guardian.IDEType.GITHUB_COPILOT

        # GitHub Copilot format: toolName and toolArgs (JSON string)
        hook_data = {
            "hookEventName": "preToolUse",
            "toolName": "Edit",
            "toolArgs": json.dumps({
                "file_path": "/tmp/config.py",
                "old_string": "old code",
                "new_string": "print('Hello, World!')"
            })
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        # Should allow
        assert result['exit_code'] == 0

        # Parse JSON response
        response = json.loads(result['output'])

        # CRITICAL: Should NOT contain permissionDecision when no threat detected
        # Empty response allows Claude Code's normal permission system
        assert 'permissionDecision' not in response, \
            "permissionDecision should be omitted to allow normal permission prompt"
        # Also check that response is empty (no auto-approve)
        assert response == {}, f"Response should be empty but got: {response}"

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_pretooluse_no_permission_override_for_write_claude_code(self, mock_pattern_config, mock_redaction_config):
        """Verify PreToolUse does NOT auto-approve Write operations (Claude Code)"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        # Write tool with clean content
        hook_data = create_hook_data(
            tool_name="Write",
            tool_input={
                "file_path": "/tmp/output.txt",
                "content": "Hello, World!"
            },
            hook_event="PreToolUse"
        )

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        # Should allow (exit_code 0)
        assert result['exit_code'] == 0

        # Parse JSON response
        response = json.loads(result['output'])

        # CRITICAL: Should NOT contain permissionDecision when no threat detected
        if 'hookSpecificOutput' in response:
            assert 'permissionDecision' not in response['hookSpecificOutput'], \
                "permissionDecision should be omitted to allow normal permission prompt"
        # Also check that response is empty or only has warnings
        assert response == {} or 'systemMessage' in response, \
            "Response should be empty or only contain systemMessage (warnings)"

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    @patch('ai_guardian.detect_ide_type')
    def test_pretooluse_no_permission_override_for_write_github_copilot(self, mock_ide_type, mock_pattern_config, mock_redaction_config):
        """Verify PreToolUse does NOT auto-approve Write operations (GitHub Copilot)"""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)
        mock_ide_type.return_value = ai_guardian.IDEType.GITHUB_COPILOT

        # GitHub Copilot format: toolName and toolArgs (JSON string)
        hook_data = {
            "hookEventName": "preToolUse",
            "toolName": "Write",
            "toolArgs": json.dumps({
                "file_path": "/tmp/output.txt",
                "content": "Hello, World!"
            })
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        # Should allow
        assert result['exit_code'] == 0

        # Parse JSON response
        response = json.loads(result['output'])

        # CRITICAL: Should NOT contain permissionDecision when no threat detected
        assert 'permissionDecision' not in response, \
            "permissionDecision should be omitted to allow normal permission prompt"
        # Also check that response is empty
        assert response == {}, f"Response should be empty but got: {response}"
