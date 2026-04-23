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
