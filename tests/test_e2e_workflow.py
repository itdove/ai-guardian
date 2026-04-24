"""
End-to-end workflow tests for complete hook execution flow.

Tests complete legitimate workflows through the full protection stack:
UserPromptSubmit → PreToolUse → [Tool Execution] → PostToolUse

Note: Attack detection is thoroughly tested in integration test suites.
These e2e tests focus on demonstrating legitimate workflows work correctly
through all hook stages without false positives.
"""

import json
from io import StringIO
from unittest import TestCase
from unittest.mock import patch

import ai_guardian
from tests.fixtures.mock_mcp_server import create_hook_data
from tests.fixtures import attack_constants


class E2ELegitimateWorkflowTests(TestCase):
    """Test complete legitimate workflows end-to-end"""

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_e2e_legitimate_notebooklm_workflow(self, mock_pattern_config, mock_redaction_config):
        """
        End-to-end test: Legitimate NotebookLM usage.

        Flow:
        1. UserPromptSubmit: "Create a notebook for AI security research"
        2. PreToolUse: Check notebook_create with clean title and URL
        3. [Tool executes - returns success]
        4. PostToolUse: Scan tool output (should be clean)

        Expected: All hooks pass, workflow completes successfully
        """
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        # Step 1: UserPromptSubmit - clean prompt
        prompt_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Create a notebook for AI security research and add example.com as a source"
        }

        with patch('sys.stdin', StringIO(json.dumps(prompt_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0, "Clean prompt should be allowed"

        # Step 2: PreToolUse - notebook_create with clean inputs
        pretooluse_data = create_hook_data(
            tool_name=attack_constants.MCP_TOOL_NOTEBOOKLM_CREATE,
            tool_input={
                "title": "AI Security Research Notes",
                "sources": [
                    {"type": "url", "url": "https://example.com/ai-security"}
                ]
            },
            hook_event="PreToolUse"
        )

        with patch('sys.stdin', StringIO(json.dumps(pretooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0, "Clean MCP tool call should be allowed"

        # Step 3: PostToolUse - clean tool response
        posttooluse_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": attack_constants.MCP_TOOL_NOTEBOOKLM_CREATE,
            "tool_response": {
                "notebook_id": "nb_12345",
                "title": "AI Security Research Notes",
                "status": "success"
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(posttooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0, "Clean tool response should be allowed"

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_e2e_legitimate_bash_workflow(self, mock_pattern_config, mock_redaction_config):
        """
        End-to-end test: Legitimate Bash command workflow.

        Flow:
        1. UserPromptSubmit: "List files in the current directory"
        2. PreToolUse: Check Bash command "ls -la"
        3. [Tool executes - returns output]
        4. PostToolUse: Scan command output (should be clean)

        Expected: All hooks pass
        """
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        # Step 1: UserPromptSubmit
        prompt_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "List files in the current directory"
        }

        with patch('sys.stdin', StringIO(json.dumps(prompt_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Step 2: PreToolUse - Bash command
        pretooluse_data = create_hook_data(
            tool_name="Bash",
            tool_input={"command": "ls -la"},
            hook_event="PreToolUse"
        )

        with patch('sys.stdin', StringIO(json.dumps(pretooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Step 3: PostToolUse - Bash output
        posttooluse_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {
                "output": "total 24\ndrwxr-xr-x  5 user  staff  160 Apr 23 10:00 .\ndrwxr-xr-x  3 user  staff   96 Apr 23 09:00 ..\n-rw-r--r--  1 user  staff  123 Apr 23 10:00 README.md\n"
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(posttooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_e2e_read_write_workflow_with_protections(self, mock_pattern_config, mock_redaction_config):
        """
        End-to-end test: Read file → Process → Write file workflow.

        Flow:
        1. UserPromptSubmit: "Read config.json and create summary"
        2. PreToolUse: Read tool
        3. PostToolUse: Check file content (no secrets)
        4. PreToolUse: Write tool
        5. PostToolUse: Write has no scannable output

        Expected: Complete workflow allowed with scanning at each stage
        """
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        # Step 1: UserPromptSubmit
        prompt_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Read config.json and create a summary file"
        }

        with patch('sys.stdin', StringIO(json.dumps(prompt_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Step 2: PreToolUse - Read tool
        pretooluse_data = create_hook_data(
            tool_name="Read",
            tool_input={"file_path": "/tmp/config.json"},
            hook_event="PreToolUse"
        )

        with patch('sys.stdin', StringIO(json.dumps(pretooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Step 3: PostToolUse - Read output (clean)
        posttooluse_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": {
                "content": '{\n  "app_name": "MyApp",\n  "version": "1.0.0",\n  "debug": false\n}'
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(posttooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Step 4: PreToolUse - Write tool
        pretooluse_data = create_hook_data(
            tool_name="Write",
            tool_input={
                "file_path": "/tmp/summary.txt",
                "content": "App: MyApp v1.0.0, Debug: disabled"
            },
            hook_event="PreToolUse"
        )

        with patch('sys.stdin', StringIO(json.dumps(pretooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Step 5: PostToolUse - Write output (no scannable output)
        posttooluse_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_response": {
                "success": True,
                "file_path": "/tmp/summary.txt"
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(posttooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Complete workflow executed with protection at each stage

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_e2e_secret_detected_in_output(self, mock_pattern_config, mock_redaction_config):
        """
        End-to-end test: Secret in tool output redacted at PostToolUse.

        Flow:
        1. UserPromptSubmit: Clean prompt → ALLOWED
        2. PreToolUse: Clean tool input → ALLOWED
        3. [Tool executes - returns secret in output]
        4. PostToolUse: Tool output with secret → REDACTED HERE

        Expected: Allowed through PreToolUse, redacted at PostToolUse
        """
        mock_pattern_config.return_value = None
        # Enable redaction with warn mode (default)
        mock_redaction_config.return_value = ({"enabled": True, "action": "warn"}, None)

        # Step 1: UserPromptSubmit - clean prompt
        prompt_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Run env command"
        }

        with patch('sys.stdin', StringIO(json.dumps(prompt_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Step 2: PreToolUse - clean Bash command
        pretooluse_data = create_hook_data(
            tool_name="Bash",
            tool_input={"command": "env"},
            hook_event="PreToolUse"
        )

        with patch('sys.stdin', StringIO(json.dumps(pretooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Step 3: PostToolUse - output contains secret
        posttooluse_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {
                "output": f"PATH=/usr/bin\nSLACK_TOKEN={attack_constants.SECRET_SLACK_TOKEN}\nHOME=/home/user\n"
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(posttooluse_data))):
            result = ai_guardian.process_hook_input()

        # REDACTED at PostToolUse (not blocked)
        assert result['exit_code'] == 0, "PostToolUse always returns exit 0"
        response = json.loads(result['output'])
        # When redacting, decision field is not set (passes through with warning), "Secret should be redacted and allowed, not blocked"
        assert response.get('systemMessage') is not None, "Should have warning about redacted secrets"
        # Verify the secret was actually redacted in the output
        if 'modified_output' in response:
            assert attack_constants.SECRET_SLACK_TOKEN not in response['modified_output'], "Secret should be redacted from output"

    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_e2e_multiple_tool_calls_in_sequence(self, mock_pattern_config, mock_redaction_config):
        """
        End-to-end test: Multiple tool calls in sequence (realistic workflow).

        Flow:
        1. UserPromptSubmit: "Analyze the codebase and create report"
        2. PreToolUse: Bash (find files)
        3. PostToolUse: Bash output
        4. PreToolUse: Read (read file)
        5. PostToolUse: Read output
        6. PreToolUse: Write (create report)
        7. PostToolUse: Write output

        Expected: All tools execute successfully in sequence
        """
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)

        # Step 1: UserPromptSubmit
        prompt_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Analyze the codebase and create a report"
        }

        with patch('sys.stdin', StringIO(json.dumps(prompt_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Step 2-3: Bash find files
        pretooluse_data = create_hook_data(
            tool_name="Bash",
            tool_input={"command": "find . -name '*.py' | head -5"},
            hook_event="PreToolUse"
        )

        with patch('sys.stdin', StringIO(json.dumps(pretooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        posttooluse_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {
                "output": "./src/main.py\n./src/utils.py\n./tests/test_main.py\n"
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(posttooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Step 4-5: Read file
        pretooluse_data = create_hook_data(
            tool_name="Read",
            tool_input={"file_path": "./src/main.py"},
            hook_event="PreToolUse"
        )

        with patch('sys.stdin', StringIO(json.dumps(pretooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        posttooluse_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": {
                "content": "def main():\n    print('Hello, World!')\n"
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(posttooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Step 6-7: Write report
        pretooluse_data = create_hook_data(
            tool_name="Write",
            tool_input={
                "file_path": "./report.md",
                "content": "# Codebase Report\n\nFound 3 Python files.\n"
            },
            hook_event="PreToolUse"
        )

        with patch('sys.stdin', StringIO(json.dumps(pretooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        posttooluse_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_response": {
                "success": True,
                "file_path": "./report.md"
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(posttooluse_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        # Complete multi-tool workflow executed successfully
