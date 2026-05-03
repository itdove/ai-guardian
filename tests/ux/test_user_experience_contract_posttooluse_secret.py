"""
User Experience Contract Tests for PostToolUse Secret Handling

These tests document and verify the expected user experience when ai-guardian
detects secrets in PostToolUse output with different secret_redaction settings.

Issue #414: PostToolUse must BLOCK secrets when secret_redaction is disabled,
not allow them through as an "emergency bypass".

All tests use isolated_config_dir fixture (#344) to avoid writing to real
violations.jsonl.
"""

import json
from io import StringIO
from unittest import TestCase
from unittest.mock import patch

import ai_guardian


class PostToolUseSecretBlockingTests(TestCase):
    """
    Tests verifying PostToolUse correctly blocks secrets when redaction is disabled.
    """

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_posttooluse_blocks_secret_when_redaction_disabled(
        self, mock_pattern, mock_scan, mock_gitleaks, mock_redact, mock_pii
    ):
        """
        USER EXPERIENCE: Bash output with secret + redaction disabled -> BLOCKED

        Scenario:
        1. User runs: cat credentials.txt
        2. Output contains: SECRET_KEY=FAKE_TEST_SECRET_VALUE_1234
        3. ai-guardian PostToolUse hook runs
        4. Secret detected, redaction disabled

        Expected User Experience:
        x Tool output BLOCKED
        User sees: "Secret Detected - aws-access-token"
        Output does NOT reach AI model
        """
        mock_pattern.return_value = (None, None)
        mock_scan.return_value = ({"enabled": True, "engines": ["gitleaks"]}, None)
        mock_gitleaks.return_value = (True, "Secret Detected - aws-access-token")
        mock_redact.return_value = ({"enabled": False}, None)
        mock_pii.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "test_001",
            "tool_input": {"command": "cat /tmp/test.txt"},
            "tool_response": {"output": "SECRET_KEY=FAKE_TEST_SECRET_VALUE_1234"}
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        output = json.loads(result['output'])
        assert output.get('decision') == 'block', \
            f"PostToolUse must BLOCK secrets when redaction is disabled, got: {output}"

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_posttooluse_redacts_secret_when_redaction_enabled(
        self, mock_pattern, mock_scan, mock_gitleaks, mock_redact, mock_pii
    ):
        """
        USER EXPERIENCE: Bash output with secret + redaction enabled -> REDACTED

        Scenario:
        1. User runs: cat credentials.txt
        2. Output contains: SECRET_KEY=FAKE_TEST_SECRET_VALUE_1234
        3. ai-guardian PostToolUse hook runs
        4. Secret detected, redaction enabled

        Expected User Experience:
        Tool output is REDACTED (not blocked)
        Secret value is replaced with masked text
        Output DOES reach AI model (with secret masked)
        """
        mock_pattern.return_value = (None, None)
        mock_scan.return_value = ({"enabled": True, "engines": ["gitleaks"]}, None)
        mock_gitleaks.return_value = (True, "Secret Detected - aws-access-token")
        mock_redact.return_value = ({"enabled": True, "action": "warn"}, None)
        mock_pii.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "test_002",
            "tool_input": {"command": "cat /tmp/test.txt"},
            "tool_response": {"output": "SECRET_KEY=FAKE_TEST_SECRET_VALUE_1234"}
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            with patch('ai_guardian.secret_redactor.SecretRedactor') as MockRedactor:
                mock_instance = MockRedactor.return_value
                mock_instance.redact.return_value = {
                    'redacted_text': 'AWS_ACCESS_KEY=***REDACTED***',
                    'redactions': [{'type': 'aws-access-token', 'position': 16, 'strategy': 'mask'}]
                }
                result = ai_guardian.process_hook_input()

        output = json.loads(result['output'])
        assert output.get('decision') != 'block', \
            f"PostToolUse should redact, not block, when redaction is enabled, got: {output}"
        updated = output.get('hookSpecificOutput', {}).get('updatedToolOutput', '')
        assert 'FAKE_TEST_SECRET_VALUE_1234' not in updated, \
            "Redacted output must not contain the raw secret"

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_posttooluse_blocks_when_redaction_config_missing(
        self, mock_pattern, mock_scan, mock_gitleaks, mock_redact, mock_pii
    ):
        """
        USER EXPERIENCE: Secret detected + no redaction config -> defaults to redact

        When secret_redaction config is None (not configured), enabled defaults
        to True and the system uses redaction rather than blocking.
        """
        mock_pattern.return_value = (None, None)
        mock_scan.return_value = ({"enabled": True, "engines": ["gitleaks"]}, None)
        mock_gitleaks.return_value = (True, "Secret Detected - aws-access-token")
        mock_redact.return_value = (None, None)
        mock_pii.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "test_003",
            "tool_input": {"command": "cat /tmp/test.txt"},
            "tool_response": {"output": "SECRET_KEY=FAKE_TEST_SECRET_VALUE_1234"}
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            with patch('ai_guardian.secret_redactor.SecretRedactor') as MockRedactor:
                mock_instance = MockRedactor.return_value
                mock_instance.redact.return_value = {
                    'redacted_text': 'AWS_ACCESS_KEY=***REDACTED***',
                    'redactions': [{'type': 'aws-access-token', 'position': 16, 'strategy': 'mask'}]
                }
                result = ai_guardian.process_hook_input()

        output = json.loads(result['output'])
        assert output.get('decision') != 'block', \
            "When redaction config is None (default enabled=True), should redact not block"

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_posttooluse_blocks_when_redaction_config_error(
        self, mock_pattern, mock_scan, mock_gitleaks, mock_redact, mock_pii
    ):
        """
        USER EXPERIENCE: Secret detected + redaction config error -> BLOCKED

        When loading secret_redaction config fails, the system falls back to
        blocking to prevent secrets from leaking.
        """
        mock_pattern.return_value = (None, None)
        mock_scan.return_value = ({"enabled": True, "engines": ["gitleaks"]}, None)
        mock_gitleaks.return_value = (True, "Secret Detected - aws-access-token")
        mock_redact.return_value = (None, "Failed to load config")
        mock_pii.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "test_004",
            "tool_input": {"command": "cat /tmp/test.txt"},
            "tool_response": {"output": "SECRET_KEY=FAKE_TEST_SECRET_VALUE_1234"}
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        output = json.loads(result['output'])
        assert output.get('decision') == 'block', \
            f"PostToolUse must BLOCK when redaction config has errors, got: {output}"


class PostToolUseSecretBlockingUXContractTests(TestCase):
    """
    UX Contract tests documenting the full user experience flow for
    PostToolUse secret detection with redaction disabled.
    """

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_user_experience_posttooluse_secret_blocked_no_redaction(
        self, mock_pattern, mock_scan, mock_gitleaks, mock_redact, mock_pii
    ):
        """
        USER EXPERIENCE: Bash output with secret + redaction disabled -> BLOCKED

        Scenario:
        1. User asks Claude: "Show me what's in credentials.txt"
        2. Claude runs: cat credentials.txt
        3. Output contains: SECRET_KEY=FAKE_TEST_SECRET_VALUE_1234
        4. ai-guardian PostToolUse hook runs
        5. Gitleaks detects secret
        6. secret_redaction.enabled = false

        Expected User Experience:
        x Tool output BLOCKED
        User sees: "Secret Detected - aws-access-token"
        Output does NOT reach AI model
        Claude does NOT see the secret value

        MANUAL VERIFICATION:
        1. Configure ai-guardian.json with secret_redaction.enabled = false
        2. Ask Claude to "cat" a file with an AWS key
        3. Verify output is blocked, not shown to Claude
        """
        mock_pattern.return_value = (None, None)
        mock_scan.return_value = ({"enabled": True, "engines": ["gitleaks"]}, None)
        mock_gitleaks.return_value = (True, "Secret Detected - aws-access-token")
        mock_redact.return_value = ({"enabled": False}, None)
        mock_pii.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "ux_test_001",
            "tool_input": {"command": "cat credentials.txt"},
            "tool_response": {"output": "SECRET_KEY=FAKE_TEST_SECRET_VALUE_1234"}
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        response = json.loads(result['output'])

        # CONTRACT: Response MUST block the output
        assert response.get('decision') == 'block', \
            "PostToolUse MUST block output containing secrets when redaction is disabled"

        # CONTRACT: Response MUST include reason
        assert 'reason' in response, \
            "Block response must include a reason for the user"
        assert 'secret' in response['reason'].lower() or 'Secret' in response['reason'], \
            "Reason should mention secret detection"

        # CONTRACT: Response MUST include hookSpecificOutput
        assert 'hookSpecificOutput' in response, \
            "Response must include hookSpecificOutput for Claude Code"
        assert response['hookSpecificOutput']['hookEventName'] == 'PostToolUse', \
            "Must identify hook event as PostToolUse"

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_user_experience_posttooluse_secret_redacted_with_redaction(
        self, mock_pattern, mock_scan, mock_gitleaks, mock_redact, mock_pii
    ):
        """
        USER EXPERIENCE: Bash output with secret + redaction enabled -> REDACTED

        Scenario:
        1. User asks Claude: "Show me what's in credentials.txt"
        2. Claude runs: cat credentials.txt
        3. Output contains: SECRET_KEY=FAKE_TEST_SECRET_VALUE_1234
        4. ai-guardian PostToolUse hook runs
        5. Gitleaks detects secret
        6. secret_redaction.enabled = true

        Expected User Experience:
        Tool output is MODIFIED (secret masked)
        Claude sees: AWS_ACCESS_KEY=***REDACTED***
        User may see warning about redaction
        Claude can continue working without seeing the real secret

        MANUAL VERIFICATION:
        1. Configure ai-guardian.json with secret_redaction.enabled = true
        2. Ask Claude to "cat" a file with an AWS key
        3. Verify output shows masked value, not the real key
        """
        mock_pattern.return_value = (None, None)
        mock_scan.return_value = ({"enabled": True, "engines": ["gitleaks"]}, None)
        mock_gitleaks.return_value = (True, "Secret Detected - aws-access-token")
        mock_redact.return_value = ({"enabled": True, "action": "warn"}, None)
        mock_pii.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "ux_test_002",
            "tool_input": {"command": "cat credentials.txt"},
            "tool_response": {"output": "SECRET_KEY=FAKE_TEST_SECRET_VALUE_1234"}
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            with patch('ai_guardian.secret_redactor.SecretRedactor') as MockRedactor:
                mock_instance = MockRedactor.return_value
                mock_instance.redact.return_value = {
                    'redacted_text': 'AWS_ACCESS_KEY=***REDACTED***',
                    'redactions': [{'type': 'aws-access-token', 'position': 16, 'strategy': 'mask'}]
                }
                result = ai_guardian.process_hook_input()

        assert result['exit_code'] == 0

        response = json.loads(result['output'])

        # CONTRACT: Response must NOT block
        assert response.get('decision') != 'block', \
            "PostToolUse should NOT block when redaction is enabled - should redact instead"

        # CONTRACT: Response must include modified output
        hook_output = response.get('hookSpecificOutput', {})
        updated_output = hook_output.get('updatedToolOutput', '')
        assert 'FAKE_TEST_SECRET_VALUE_1234' not in updated_output, \
            "Redacted output must not contain the raw secret value"


class GitleaksAllowGuidanceTests(TestCase):
    """
    Tests verifying that gitleaks:allow guidance tells users to put the
    comment inline (at the end of the line), not before the line.

    Issue #416: gitleaks only recognizes # gitleaks:allow when it appears
    on the SAME line as the secret, not on a preceding line.
    """

    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_block_message_says_end_of_line(
        self, mock_pattern, mock_scan, mock_gitleaks, mock_redact, mock_pii
    ):
        """
        USER EXPERIENCE: Block message gitleaks:allow guidance says "at the end of the line"

        Issue #416: The old text said "comment to the line" which is ambiguous.
        gitleaks:allow MUST be on the same line as the secret to work.

        Expected User Experience:
        User sees: "add '# gitleaks:allow' at the end of the line"
        NOT: "add '# gitleaks:allow' comment to the line"
        NOT: "before the line"
        """
        mock_pattern.return_value = (None, None)
        mock_scan.return_value = ({"enabled": True, "engines": ["gitleaks"]}, None)
        error_with_guidance = (
            "Secret Detected\n"
            "Recommendation:\n"
            "  • If false positive: add '# gitleaks:allow' at the end of the line\n"
        )
        mock_gitleaks.return_value = (True, error_with_guidance)
        mock_redact.return_value = ({"enabled": False}, None)
        mock_pii.return_value = (None, None)

        hook_data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "guidance_test_001",
            "tool_input": {"command": "cat /tmp/test.txt"},
            "tool_response": {"output": "SECRET_KEY=FAKE_TEST_SECRET_VALUE_1234"}
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        response = json.loads(result['output'])
        reason = response.get('reason', '')

        assert "at the end of the line" in reason, \
            f"Block message must say 'at the end of the line', got: {reason}"
        assert "before the line" not in reason, \
            f"Block message must NOT say 'before the line', got: {reason}"

    def test_check_secrets_error_message_text(self):
        """
        USER EXPERIENCE: check_secrets_with_gitleaks error message uses correct guidance

        Directly verifies the source code text for the gitleaks:allow recommendation.
        This test does NOT require gitleaks to be installed — it reads the source.
        """
        import inspect
        source = inspect.getsource(ai_guardian.check_secrets_with_gitleaks)

        assert "at the end of the line" in source, \
            "check_secrets_with_gitleaks must say 'at the end of the line'"
        assert "before the line" not in source, \
            "check_secrets_with_gitleaks must NOT say 'before the line'"
        assert "comment to the line" not in source, \
            "check_secrets_with_gitleaks must NOT say 'comment to the line'"

    def test_tui_violations_gitleaks_allow_guidance(self):
        """
        USER EXPERIENCE: TUI violations secret allowlisting says "inline" / "at the end"

        Issue #416: The TUI said "Add comment before the line" which is wrong.
        Must say "Add inline comment at the end of the line" with an example
        showing the comment on the same line as the secret.
        """
        import inspect
        from ai_guardian.tui import violations
        source = inspect.getsource(violations)

        assert "before the line" not in source, \
            "TUI violations must NOT say 'before the line' for gitleaks:allow"
        assert "inline comment at the end of the line" in source, \
            "TUI violations must say 'inline comment at the end of the line'"
        assert "YOUR_SECRET_LINE # gitleaks:allow" in source, \
            "TUI violations must show inline example: YOUR_SECRET_LINE # gitleaks:allow"
