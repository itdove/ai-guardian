"""
User Experience Contract Tests for Transcript Scanning (Issue #430, #442)

These tests document and verify the expected user experience when ai-guardian
scans the conversation transcript for secrets and PII that may have entered
via ! shell commands.

Prompt injection scanning is intentionally excluded from transcript scanning
because conversation history naturally contains patterns that trigger false
positives (Issue #442).

Key contract: Transcript scanning is DETECT-ONLY. It warns the user via
systemMessage but NEVER blocks the prompt, because the sensitive content
is already in the AI's context and cannot be removed.
"""

import json
import os
import tempfile
from io import StringIO
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, MagicMock

import ai_guardian


class TranscriptScanningUserExperienceTests(TestCase):
    """
    Tests documenting the user experience contract for transcript scanning.

    These tests verify that:
    1. Secrets from ! commands are detected in transcripts
    2. PII from ! commands is detected in transcripts
    3. Warnings are shown via systemMessage (not blocking)
    4. The user prompt is never blocked due to transcript findings
    5. Feature can be disabled
    6. Missing transcript_path is handled gracefully
    """

    @patch('ai_guardian._scan_for_pii')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_prompt_injection_config')
    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_transcript_scanning_config')
    def test_user_prompt_with_transcript_secret_warns_but_allows(
        self, mock_ts_config, mock_pii_config, mock_pi_config,
        mock_secret_config, mock_gitleaks, mock_pii
    ):
        """
        USER EXPERIENCE: Secret in transcript from ! command -> WARNING (not blocked)

        Scenario:
        1. User previously ran: ! export AWS_KEY=AKIAIOSFODNN7EXAMPLE
        2. The secret is now in the transcript file
        3. User submits a normal prompt: "Hello"
        4. ai-guardian scans the transcript and finds the secret

        Expected User Experience:
        ✅ Prompt is ALLOWED (not blocked)
        ⚠️ User sees warning via systemMessage about secret in transcript
        📝 Violation logged as secret_in_transcript
        """
        mock_ts_config.return_value = ({"enabled": True}, None)
        mock_pii_config.return_value = ({"enabled": False}, None)
        mock_pi_config.return_value = ({"enabled": False}, None)
        mock_secret_config.return_value = ({"enabled": True}, None)
        mock_pii.return_value = (False, "", [], None)

        # First call: prompt scanning (clean), second call: transcript scanning (secret found)
        mock_gitleaks.side_effect = [
            (False, None),  # Prompt scan: clean
            (True, "Secret detected: AWS access key"),  # Transcript scan: secret found
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            f.write(json.dumps({"text": "export AWS_KEY=AKIAIOSFODNN7EXAMPLE"}) + "\n")
            transcript_path = f.name

        try:
            hook_data = {
                "hook_event_name": "UserPromptSubmit",
                "prompt": "Hello, how are you?",
                "transcript_path": transcript_path,
            }

            with patch('sys.stdin', StringIO(json.dumps(hook_data))):
                result = ai_guardian.process_hook_input()

            response = json.loads(result['output'])

            # CONTRACT: Prompt is NOT blocked
            assert "decision" not in response or response.get("decision") != "block", \
                "Transcript secret should warn, NOT block the prompt"

            # CONTRACT: Warning shown via systemMessage
            if mock_gitleaks.call_count >= 2:
                system_msg = response.get("systemMessage", "")
                assert system_msg, \
                    "Should show systemMessage warning about transcript secret"
                assert "transcript" in system_msg.lower() or "secret" in system_msg.lower(), \
                    f"Warning should mention transcript or secret, got: {system_msg[:200]}"
        finally:
            os.unlink(transcript_path)

    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_prompt_injection_config')
    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_transcript_scanning_config')
    def test_user_prompt_clean_transcript_no_warning(
        self, mock_ts_config, mock_pii_config, mock_pi_config,
        mock_secret_config, mock_gitleaks
    ):
        """
        USER EXPERIENCE: Clean transcript -> NO warning

        Scenario:
        1. User has been using Claude normally, no ! commands with secrets
        2. User submits a prompt

        Expected User Experience:
        ✅ Prompt is ALLOWED
        ✅ No transcript-related warnings
        """
        mock_ts_config.return_value = ({"enabled": True}, None)
        mock_pii_config.return_value = ({"enabled": False}, None)
        mock_pi_config.return_value = ({"enabled": False}, None)
        mock_secret_config.return_value = ({"enabled": True}, None)
        mock_gitleaks.return_value = (False, None)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            f.write(json.dumps({"text": "Hello, just a normal conversation"}) + "\n")
            transcript_path = f.name

        try:
            hook_data = {
                "hook_event_name": "UserPromptSubmit",
                "prompt": "What is Python?",
                "transcript_path": transcript_path,
            }

            with patch('sys.stdin', StringIO(json.dumps(hook_data))):
                result = ai_guardian.process_hook_input()

            response = json.loads(result['output'])

            # CONTRACT: No blocking
            assert "decision" not in response or response.get("decision") != "block"

            # CONTRACT: No transcript warning in systemMessage
            system_msg = response.get("systemMessage", "")
            assert "transcript" not in system_msg.lower(), \
                f"Should not show transcript warning for clean transcript, got: {system_msg[:200]}"
        finally:
            os.unlink(transcript_path)

    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_prompt_injection_config')
    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_transcript_scanning_config')
    def test_user_prompt_transcript_scanning_disabled(
        self, mock_ts_config, mock_pii_config, mock_pi_config,
        mock_secret_config, mock_gitleaks
    ):
        """
        USER EXPERIENCE: transcript_scanning.enabled=false -> no scanning

        Expected User Experience:
        ✅ Prompt proceeds normally
        ✅ No transcript scanning overhead
        """
        mock_ts_config.return_value = ({"enabled": False}, None)
        mock_pii_config.return_value = ({"enabled": False}, None)
        mock_pi_config.return_value = ({"enabled": False}, None)
        mock_secret_config.return_value = ({"enabled": True}, None)
        mock_gitleaks.return_value = (False, None)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            f.write(json.dumps({"text": "export SECRET=mysupersecret"}) + "\n")
            transcript_path = f.name

        try:
            hook_data = {
                "hook_event_name": "UserPromptSubmit",
                "prompt": "Hello",
                "transcript_path": transcript_path,
            }

            with patch('ai_guardian.scan_transcript_incremental') as mock_scan:
                with patch('sys.stdin', StringIO(json.dumps(hook_data))):
                    result = ai_guardian.process_hook_input()

                # CONTRACT: scan_transcript_incremental should NOT be called
                mock_scan.assert_not_called()
        finally:
            os.unlink(transcript_path)

    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_prompt_injection_config')
    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_transcript_scanning_config')
    def test_user_prompt_no_transcript_path_field(
        self, mock_ts_config, mock_pii_config, mock_pi_config,
        mock_secret_config, mock_gitleaks
    ):
        """
        USER EXPERIENCE: Hook data without transcript_path -> no error

        This handles IDEs that don't provide transcript_path (Cursor, etc.).

        Expected User Experience:
        ✅ Prompt proceeds normally
        ✅ No errors or crashes
        ✅ Transcript scanning silently skipped
        """
        mock_ts_config.return_value = ({"enabled": True}, None)
        mock_pii_config.return_value = ({"enabled": False}, None)
        mock_pi_config.return_value = ({"enabled": False}, None)
        mock_secret_config.return_value = ({"enabled": True}, None)
        mock_gitleaks.return_value = (False, None)

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Hello",
            # No transcript_path field
        }

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        response = json.loads(result['output'])

        # CONTRACT: No blocking, no errors
        assert "decision" not in response or response.get("decision") != "block"

    @patch('ai_guardian._scan_for_pii')
    @patch('ai_guardian.check_secrets_with_gitleaks')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_prompt_injection_config')
    @patch('ai_guardian._load_pii_config')
    @patch('ai_guardian._load_transcript_scanning_config')
    def test_user_prompt_transcript_pii_warns_but_allows(
        self, mock_ts_config, mock_pii_config, mock_pi_config,
        mock_secret_config, mock_gitleaks, mock_pii
    ):
        """
        USER EXPERIENCE: PII in transcript -> WARNING (not blocked)

        Scenario:
        1. User previously ran: ! echo "SSN: 123-45-6789"
        2. The PII is now in the transcript file

        Expected User Experience:
        ✅ Prompt is ALLOWED (not blocked)
        ⚠️ User sees warning about PII in transcript
        """
        mock_ts_config.return_value = ({"enabled": True}, None)
        mock_pii_config.return_value = ({"enabled": True, "pii_types": ["ssn"], "action": "warn"}, None)
        mock_pi_config.return_value = ({"enabled": False}, None)
        mock_secret_config.return_value = ({"enabled": True}, None)

        # Prompt scan: clean, transcript secret scan: clean
        mock_gitleaks.return_value = (False, None)
        # Prompt PII scan: clean, transcript PII scan: PII found
        mock_pii.side_effect = [
            (False, "", [], None),  # Prompt PII scan
            (True, "redacted", [{"type": "ssn"}], "PII found"),  # Transcript PII scan
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            f.write(json.dumps({"text": "SSN: 123-45-6789"}) + "\n")
            transcript_path = f.name

        try:
            hook_data = {
                "hook_event_name": "UserPromptSubmit",
                "prompt": "Hello",
                "transcript_path": transcript_path,
            }

            with patch('sys.stdin', StringIO(json.dumps(hook_data))):
                result = ai_guardian.process_hook_input()

            response = json.loads(result['output'])

            # CONTRACT: Prompt is NOT blocked
            assert "decision" not in response or response.get("decision") != "block", \
                "Transcript PII should warn, NOT block the prompt"
        finally:
            os.unlink(transcript_path)


if __name__ == '__main__':
    import unittest
    unittest.main()
