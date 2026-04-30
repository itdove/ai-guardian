"""
User Experience Contract Tests for PII Detection (Issue #262)

These tests document and verify the expected user experience when ai-guardian
detects PII (personally identifiable information) in the three hook events:
UserPromptSubmit, PreToolUse, and PostToolUse.

Tests verify that PII is blocked/redacted based on the scan_pii configuration
and that ignore_files patterns are respected.
"""

import json
from io import StringIO
from unittest import TestCase
from unittest.mock import patch, MagicMock

import ai_guardian


class PIIUserPromptSubmitTests(TestCase):
    """Test PII detection in user prompts (UserPromptSubmit hook)."""

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_prompt_injection_config')
    def test_user_prompt_with_ssn_blocked(self, mock_pi, mock_ss, mock_gitleaks, mock_pii):
        """
        USER EXPERIENCE: User submits prompt containing SSN -> BLOCKED

        Scenario:
        1. User types: "My SSN is 123-45-6789"
        2. ai-guardian UserPromptSubmit hook runs
        3. PII detected (SSN)

        Expected User Experience:
        ❌ Prompt is BLOCKED
        🛡️ User sees: "PII DETECTED ... SSN"
        """
        mock_pi.return_value = (None, None)
        mock_ss.return_value = (None, None)
        mock_gitleaks.return_value = (False, None)
        mock_pii.return_value = ({
            'enabled': True,
            'pii_types': ['ssn', 'credit_card', 'phone', 'email'],
            'action': 'redact',
            'ignore_files': []
        }, None)

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "My SSN is 123-45-6789, please help"
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        output = json.loads(result['output'])
        assert output.get('decision') == 'block', f"Expected block, got: {output}"
        assert 'PII' in output.get('reason', ''), "Should mention PII in reason"

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_prompt_injection_config')
    def test_user_prompt_without_pii_allowed(self, mock_pi, mock_ss, mock_gitleaks, mock_pii):
        """
        USER EXPERIENCE: Normal prompt without PII -> ALLOWED

        Scenario:
        1. User types: "Help me write a function"
        2. ai-guardian checks for PII
        3. No PII found

        Expected User Experience:
        ✅ Prompt is ALLOWED
        """
        mock_pi.return_value = (None, None)
        mock_ss.return_value = (None, None)
        mock_gitleaks.return_value = (False, None)
        mock_pii.return_value = ({
            'enabled': True,
            'pii_types': ['ssn', 'credit_card', 'phone', 'email'],
            'action': 'redact',
            'ignore_files': []
        }, None)

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Help me write a Python function"
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        output = json.loads(result['output'])
        assert output.get('decision') != 'block', f"Should not block: {output}"

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_prompt_injection_config')
    def test_user_prompt_pii_disabled(self, mock_pi, mock_ss, mock_gitleaks, mock_pii):
        """
        USER EXPERIENCE: PII scanning disabled -> prompt with PII ALLOWED

        Scenario:
        1. User has scan_pii.enabled = false
        2. User types prompt containing SSN
        3. PII scanning is skipped

        Expected User Experience:
        ✅ Prompt is ALLOWED (PII scanning disabled)
        """
        mock_pi.return_value = (None, None)
        mock_ss.return_value = (None, None)
        mock_gitleaks.return_value = (False, None)
        mock_pii.return_value = ({'enabled': False}, None)

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "My SSN is 123-45-6789"
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        output = json.loads(result['output'])
        assert output.get('decision') != 'block', f"Should not block when disabled: {output}"


class PIIPostToolUseTests(TestCase):
    """Test PII redaction in tool outputs (PostToolUse hook)."""

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    def test_posttooluse_redacts_credit_card(self, mock_ss, mock_gitleaks, mock_pii):
        """
        USER EXPERIENCE: Tool output contains credit card -> REDACTED

        Scenario:
        1. Claude runs a Bash command
        2. Output contains credit card number 4532015112830366
        3. ai-guardian PostToolUse hook runs

        Expected User Experience:
        ✅ Output is returned (not blocked)
        🔒 Credit card is masked: [HIDDEN CREDIT CARD ****0366]
        ⚠️ User sees warning about PII redaction
        """
        mock_ss.return_value = (None, None)
        mock_gitleaks.return_value = (False, None)
        mock_pii.return_value = ({
            'enabled': True,
            'pii_types': ['credit_card'],
            'action': 'redact',
            'ignore_files': []
        }, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": "cat data.txt"},
            },
            "tool_result": {
                "content": [{"type": "text", "text": "Card: 4532015112830366"}]
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        output = json.loads(result['output'])
        # Should have modified output with redacted credit card
        modified = output.get('output', '')
        assert '4532015112830366' not in modified, "Credit card should be redacted"
        if modified:
            assert '0366' in modified, "Last 4 digits should be preserved"

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    def test_posttooluse_log_only_mode(self, mock_ss, mock_gitleaks, mock_pii):
        """
        USER EXPERIENCE: PII found with action=log-only -> ALLOWED with warning

        Scenario:
        1. scan_pii.action = "log-only"
        2. Tool output contains SSN
        3. PII is detected but NOT redacted

        Expected User Experience:
        ✅ Output is returned unmodified
        ⚠️ Warning message shown about PII
        """
        mock_ss.return_value = (None, None)
        mock_gitleaks.return_value = (False, None)
        mock_pii.return_value = ({
            'enabled': True,
            'pii_types': ['ssn'],
            'action': 'log-only',
            'ignore_files': []
        }, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_use": {
                "name": "Bash",
                "input": {"command": "cat data.txt"},
            },
            "tool_result": {
                "content": [{"type": "text", "text": "SSN: 123-45-6789"}]
            }
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        output = json.loads(result['output'])
        # Should NOT block
        assert output.get('decision') != 'block', "log-only should not block"
        # Should have a system message warning
        assert 'systemMessage' in output or output == {}, f"Expected warning or pass-through: {output}"


class PIIPreToolUseTests(TestCase):
    """Test PII detection in file reads (PreToolUse hook)."""

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    def test_pretooluse_redact_blocks_read(self, mock_ss, mock_gitleaks, mock_pii):
        """
        USER EXPERIENCE: File read with PII + action=redact -> BLOCKED

        Scenario:
        1. Claude tries to Read a file containing SSN
        2. ai-guardian PreToolUse hook scans file
        3. PII detected, action is "redact"

        Expected User Experience:
        ❌ Read operation is BLOCKED (PreToolUse cannot modify content,
           so redact mode falls back to blocking)
        🛡️ User sees: "PII DETECTED"

        Note: PostToolUse CAN redact tool output. PreToolUse/UserPromptSubmit
        cannot modify content, so both redact and block modes deny the operation.
        """
        mock_ss.return_value = (None, None)
        mock_gitleaks.return_value = (False, None)
        mock_pii.return_value = ({
            'enabled': True,
            'pii_types': ['ssn'],
            'action': 'redact',
            'ignore_files': []
        }, None)

        import tempfile, os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Employee SSN: 123-45-6789\nName: John Doe")
            tmp_path = f.name

        try:
            hook_data = {
                "hook_event_name": "PreToolUse",
                "tool_use": {
                    "name": "Read",
                    "parameters": {"file_path": tmp_path}
                }
            }

            with patch('sys.stdin', StringIO(json.dumps(hook_data))):
                result = ai_guardian.process_hook_input()

            output = json.loads(result['output'])
            # Should block — PreToolUse can't modify content, redact falls back to block
            assert 'permissionDecision' in output.get('hookSpecificOutput', {}) or \
                   'PII' in output.get('systemMessage', ''), \
                   f"Expected PII block: {output}"
        finally:
            os.unlink(tmp_path)

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    def test_pretooluse_block_action_blocks_read(self, mock_ss, mock_gitleaks, mock_pii):
        """
        USER EXPERIENCE: File read with PII + action=block -> BLOCKED

        Scenario:
        1. Claude tries to Read a file containing SSN
        2. ai-guardian PreToolUse hook scans file
        3. PII detected, action is "block"

        Expected User Experience:
        ❌ Read operation is BLOCKED
        🛡️ User sees: "PII DETECTED"
        """
        mock_ss.return_value = (None, None)
        mock_gitleaks.return_value = (False, None)
        mock_pii.return_value = ({
            'enabled': True,
            'pii_types': ['ssn'],
            'action': 'block',
            'ignore_files': []
        }, None)

        import tempfile, os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Employee SSN: 123-45-6789\nName: John Doe")
            tmp_path = f.name

        try:
            hook_data = {
                "hook_event_name": "PreToolUse",
                "tool_use": {
                    "name": "Read",
                    "parameters": {"file_path": tmp_path}
                }
            }

            with patch('sys.stdin', StringIO(json.dumps(hook_data))):
                result = ai_guardian.process_hook_input()

            output = json.loads(result['output'])
            # Should block due to action=block
            assert 'permissionDecision' in output.get('hookSpecificOutput', {}) or \
                   'PII' in output.get('systemMessage', ''), \
                   f"Expected PII block: {output}"
        finally:
            os.unlink(tmp_path)

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    def test_pretooluse_ignore_files_skips_test_file(self, mock_ss, mock_gitleaks, mock_pii):
        """
        USER EXPERIENCE: File matching ignore_files pattern -> PII scan SKIPPED

        Scenario:
        1. scan_pii.ignore_files = ["*.test.txt"]
        2. Claude reads "data.test.txt" containing SSN
        3. PII scanning is skipped for this file

        Expected User Experience:
        ✅ Read operation is ALLOWED (file matches ignore pattern)
        """
        mock_ss.return_value = (None, None)
        mock_gitleaks.return_value = (False, None)
        mock_pii.return_value = ({
            'enabled': True,
            'pii_types': ['ssn'],
            'action': 'redact',
            'ignore_files': ['*.test.txt']
        }, None)

        import tempfile, os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.test.txt', delete=False) as f:
            f.write("SSN: 123-45-6789")
            tmp_path = f.name

        try:
            hook_data = {
                "hook_event_name": "PreToolUse",
                "tool_use": {
                    "name": "Read",
                    "parameters": {"file_path": tmp_path}
                }
            }

            with patch('sys.stdin', StringIO(json.dumps(hook_data))):
                result = ai_guardian.process_hook_input()

            output = json.loads(result['output'])
            # Should NOT block — file matches ignore pattern
            has_deny = output.get('hookSpecificOutput', {}).get('permissionDecision') == 'deny'
            assert not has_deny, f"Should not block ignored file: {output}"
        finally:
            os.unlink(tmp_path)
