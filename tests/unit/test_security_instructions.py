"""
Test security instructions injection via systemMessage on every prompt.

Issue #580: Inject never-bypass rules via systemMessage on every UserPromptSubmit.
"""

import json
from io import StringIO
from unittest import TestCase
from unittest.mock import patch

import ai_guardian
from ai_guardian import _SECURITY_SYSTEM_MESSAGE, IDEType, format_response


class TestSecurityMessageConstant(TestCase):
    """Verify the security message uses generic language."""

    def test_generic_language_no_specific_bypass_terms(self):
        """The constant must NOT name specific bypass mechanisms."""
        forbidden_terms = [
            ".ai-read-deny",
            ".aiguardignore.toml",
            "ai-guardian.json",
            "annotations",
            "--skip-checksum-verification",
            "--no-verify",
        ]
        for term in forbidden_terms:
            self.assertNotIn(
                term, _SECURITY_SYSTEM_MESSAGE,
                f"Security message must not name specific mechanism: {term}"
            )

    def test_contains_security_rules(self):
        """The constant should contain key security rules."""
        self.assertIn("bypass", _SECURITY_SYSTEM_MESSAGE.lower())
        self.assertIn("security", _SECURITY_SYSTEM_MESSAGE.lower())
        self.assertIn("blocked", _SECURITY_SYSTEM_MESSAGE.lower())


class TestFormatResponseSecurityMessage(TestCase):
    """Unit tests for format_response with security_message parameter."""

    def test_security_message_in_prompt_allow(self):
        """Security message appears in systemMessage for Claude Code prompt allow."""
        result = format_response(
            IDEType.CLAUDE_CODE,
            has_secrets=False,
            hook_event="prompt",
            security_message="TEST_SECURITY_RULES"
        )
        output = json.loads(result["output"])
        self.assertIn("systemMessage", output)
        self.assertIn("TEST_SECURITY_RULES", output["systemMessage"])

    def test_security_message_combined_with_warning(self):
        """Security message is prepended to warning_message."""
        result = format_response(
            IDEType.CLAUDE_CODE,
            has_secrets=False,
            hook_event="prompt",
            warning_message="Warning: config error",
            security_message="TEST_SECURITY_RULES"
        )
        output = json.loads(result["output"])
        self.assertIn("systemMessage", output)
        self.assertIn("TEST_SECURITY_RULES", output["systemMessage"])
        self.assertIn("Warning: config error", output["systemMessage"])
        self.assertTrue(
            output["systemMessage"].index("TEST_SECURITY_RULES") <
            output["systemMessage"].index("Warning: config error"),
            "Security rules should come before warnings"
        )

    def test_security_message_not_in_block_response(self):
        """Blocked prompts don't include security message."""
        result = format_response(
            IDEType.CLAUDE_CODE,
            has_secrets=True,
            error_message="Secret detected",
            hook_event="prompt",
            security_message="TEST_SECURITY_RULES"
        )
        output = json.loads(result["output"])
        self.assertEqual(output.get("decision"), "block")
        self.assertNotIn("TEST_SECURITY_RULES", output.get("reason", ""))

    def test_no_security_message_when_none(self):
        """No systemMessage when security_message is None and no warnings."""
        result = format_response(
            IDEType.CLAUDE_CODE,
            has_secrets=False,
            hook_event="prompt",
            security_message=None
        )
        output = json.loads(result["output"])
        self.assertNotIn("systemMessage", output)

    def test_security_message_ignored_for_pretooluse(self):
        """Security message parameter is ignored for PreToolUse hooks."""
        result = format_response(
            IDEType.CLAUDE_CODE,
            has_secrets=False,
            hook_event="pretooluse",
            security_message="TEST_SECURITY_RULES"
        )
        output = json.loads(result["output"])
        self.assertNotIn("TEST_SECURITY_RULES", json.dumps(output))

    def test_security_message_ignored_for_cursor(self):
        """Security message parameter is ignored for Cursor IDE."""
        result = format_response(
            IDEType.CURSOR,
            has_secrets=False,
            hook_event="prompt",
            security_message="TEST_SECURITY_RULES"
        )
        output = json.loads(result["output"])
        self.assertNotIn("TEST_SECURITY_RULES", json.dumps(output))


class TestProcessHookDataSecurityMessage(TestCase):
    """Integration tests for security message injection in process_hook_data."""

    @patch('ai_guardian._load_security_instructions_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_security_message_injected_on_clean_prompt(
        self, mock_pattern_config, mock_redaction_config, mock_si_config
    ):
        """Clean prompt with default config includes security message in systemMessage."""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)
        mock_si_config.return_value = (None, None)

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "What is the capital of France?"
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        self.assertEqual(result['exit_code'], 0)
        output = json.loads(result['output'])
        self.assertIn("systemMessage", output)
        self.assertIn("SECURITY RULES", output["systemMessage"])

    @patch('ai_guardian._load_security_instructions_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_security_message_not_injected_when_disabled(
        self, mock_pattern_config, mock_redaction_config, mock_si_config
    ):
        """When inject_on_prompt is False, no security message on clean prompts."""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)
        mock_si_config.return_value = ({"inject_on_prompt": False}, None)

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "What is the capital of France?"
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        self.assertEqual(result['exit_code'], 0)
        output = json.loads(result['output'])
        self.assertEqual(output, {})

    @patch('ai_guardian._load_security_instructions_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_security_message_not_injected_for_pretooluse(
        self, mock_pattern_config, mock_redaction_config, mock_si_config
    ):
        """PreToolUse hooks should not get security message injection."""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)
        mock_si_config.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Read",
                "parameters": {"file_path": "/tmp/test.txt"}
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        self.assertEqual(result['exit_code'], 0)
        output = json.loads(result['output'])
        self.assertNotIn("SECURITY RULES", json.dumps(output))

    @patch('ai_guardian.detect_ide_type')
    @patch('ai_guardian._load_security_instructions_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_security_message_not_injected_for_cursor(
        self, mock_pattern_config, mock_redaction_config, mock_si_config, mock_ide_type
    ):
        """Cursor IDE should not get security message injection."""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)
        mock_si_config.return_value = (None, None)
        mock_ide_type.return_value = IDEType.CURSOR

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "What is the capital of France?"
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        output = json.loads(result['output'])
        self.assertNotIn("SECURITY RULES", json.dumps(output))

    @patch('ai_guardian._load_security_instructions_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_security_message_on_empty_prompt(
        self, mock_pattern_config, mock_redaction_config, mock_si_config
    ):
        """Empty prompt still gets security message injection."""
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = (None, None)
        mock_si_config.return_value = (None, None)

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": ""
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        self.assertEqual(result['exit_code'], 0)
        output = json.loads(result['output'])
        self.assertIn("systemMessage", output)
        self.assertIn("SECURITY RULES", output["systemMessage"])
