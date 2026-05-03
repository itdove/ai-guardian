#!/usr/bin/env python3
"""
Tests for scanner engine integration in secret scanning.

Tests the integration of flexible scanner engines with the main scanning flow.
"""

import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_guardian import check_secrets_with_gitleaks


class TestScannerEngineIntegration(unittest.TestCase):
    """Tests for scanner engine integration."""

    @patch('ai_guardian.HAS_SCANNER_ENGINE', True)
    @patch('ai_guardian.select_engine')
    @patch('ai_guardian._load_secret_scanning_config')
    def test_scanner_not_found_warns(self, mock_load_config, mock_select_engine):
        """Test that missing scanner warns instead of blocking (Issue #343)."""
        # Mock configuration with leaktk
        mock_load_config.return_value = ({"engines": ["leaktk"]}, None)

        # Mock select_engine to raise RuntimeError (no scanner found)
        mock_select_engine.side_effect = RuntimeError(
            "No secret scanner found. Install one of:\n"
            "  • Gitleaks: brew install gitleaks\n"
            "  • BetterLeaks: brew install betterleaks\n"
            "  • LeakTK: brew install leaktk/tap/leaktk"
        )

        # Should return warning (not blocking)
        has_secrets, error_msg = check_secrets_with_gitleaks(
            "aws_key=AKIAIOSFODNN7EXAMPLE",
            filename="test.txt"
        )

        # Verify it warns but does NOT block
        self.assertFalse(has_secrets, "Should NOT block when scanner not found (Issue #343)")
        self.assertIsNotNone(error_msg, "Warning message should be returned")
        self.assertIn("WARNING", error_msg, "Should indicate warning")
        self.assertIn("ai-guardian scanner install leaktk", error_msg, "Should suggest installing configured scanner")
        self.assertIn("you may leak secrets", error_msg, "Should warn about risk")
        # Issue #384: Context-aware message
        self.assertIn("No secret scanning available", error_msg, "Should use context-aware title")
        self.assertIn("['leaktk']", error_msg, "Should list tried engines")

    @patch('ai_guardian.HAS_SCANNER_ENGINE', True)
    @patch('ai_guardian.select_engine')
    @patch('ai_guardian.build_scanner_command')
    @patch('ai_guardian.get_parser')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian.subprocess.run')
    def test_scanner_engine_used_when_available(
        self, mock_run, mock_load_config, mock_get_parser,
        mock_build_command, mock_select_engine
    ):
        """Test that configured scanner engine is used when available."""
        # Mock configuration with betterleaks
        mock_load_config.return_value = ({"engines": ["betterleaks", "gitleaks"]}, None)

        # Mock engine selection (betterleaks found)
        mock_engine = MagicMock()
        mock_engine.type = "betterleaks"
        mock_engine.output_parser = "gitleaks"
        mock_engine.secrets_found_exit_code = 42
        mock_engine.success_exit_code = 0
        mock_select_engine.return_value = mock_engine

        # Mock command building
        mock_build_command.return_value = ["betterleaks", "detect", "..."]

        # Mock scanner run (no secrets)
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock parser
        mock_parser = MagicMock()
        mock_parser.parse.return_value = {
            "has_secrets": False,
            "findings": [],
            "total_findings": 0
        }
        mock_get_parser.return_value = mock_parser

        # Run scan
        has_secrets, error_msg = check_secrets_with_gitleaks(
            "clean content",
            filename="test.txt"
        )

        # Verify betterleaks was selected
        mock_select_engine.assert_called_once()
        call_args = mock_select_engine.call_args[0][0]
        self.assertEqual(call_args, ["betterleaks", "gitleaks"])

        # Verify command was built with betterleaks
        mock_build_command.assert_called_once()
        self.assertEqual(mock_build_command.call_args[1]["engine_config"], mock_engine)

        # Verify no secrets found
        self.assertFalse(has_secrets)
        self.assertIsNone(error_msg)

    @patch('ai_guardian.HAS_SCANNER_ENGINE', False)
    @patch('ai_guardian.subprocess.run')
    def test_legacy_fallback_when_scanner_engine_unavailable(self, mock_run):
        """Test that legacy gitleaks is used when scanner engine module unavailable."""
        # Mock gitleaks run (no secrets)
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Run scan
        has_secrets, error_msg = check_secrets_with_gitleaks(
            "clean content",
            filename="test.txt"
        )

        # Verify gitleaks command was used (legacy fallback)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "gitleaks")

        # Verify no secrets found
        self.assertFalse(has_secrets)
        self.assertIsNone(error_msg)

    @patch('ai_guardian.HAS_SCANNER_ENGINE', True)
    @patch('ai_guardian.select_engine')
    @patch('ai_guardian._load_secret_scanning_config')
    def test_unexpected_error_fails_open(self, mock_load_config, mock_select_engine):
        """Test that unexpected errors fail open (allow operation)."""
        # Mock configuration
        mock_load_config.return_value = ({"engines": ["gitleaks"]}, None)

        # Mock select_engine to raise unexpected error
        mock_select_engine.side_effect = Exception("Unexpected error")

        # Should fail open
        has_secrets, error_msg = check_secrets_with_gitleaks(
            "some content",
            filename="test.txt"
        )

        # Verify it fails open (allows operation)
        self.assertFalse(has_secrets, "Should fail open on unexpected errors")
        self.assertIsNone(error_msg)

    @patch('ai_guardian.HAS_SCANNER_ENGINE', True)
    @patch('ai_guardian.select_engine')
    @patch('ai_guardian.build_scanner_command')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian.subprocess.run')
    def test_gitleaks_exit_code_1_not_treated_as_success(
        self, mock_run, mock_load_config, mock_build_command, mock_select_engine
    ):
        """Exit code 1 from gitleaks must NOT be treated as success (Issue #411).

        Gitleaks exit code 1 is its default 'secrets found' code when --exit-code
        is not specified or not honored. Treating it as success silently bypasses
        secret detection.
        """
        mock_load_config.return_value = ({"engines": ["gitleaks"]}, None)

        mock_engine = MagicMock()
        mock_engine.type = "gitleaks"
        mock_engine.output_parser = "gitleaks"
        mock_engine.secrets_found_exit_code = 42
        mock_engine.success_exit_code = 0
        mock_select_engine.return_value = mock_engine

        mock_build_command.return_value = ["gitleaks", "detect", "..."]

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "leaks found: 1"
        mock_run.return_value = mock_result

        has_secrets, error_msg = check_secrets_with_gitleaks(
            "AWS_ACCESS_KEY=AKIAIOSFODNN7TESTKEY",  # notsecret
            filename="test.txt"
        )

        self.assertTrue(has_secrets, "Exit code 1 from gitleaks must mean secrets found, not success (Issue #411)")
        self.assertIsNotNone(error_msg)

    @patch('ai_guardian.HAS_SCANNER_ENGINE', True)
    @patch('ai_guardian.select_engine')
    @patch('ai_guardian.build_scanner_command')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian.subprocess.run')
    def test_gitleaks_exit_code_42_blocks_operation(
        self, mock_run, mock_load_config, mock_build_command, mock_select_engine
    ):
        """Exit code 42 (custom) from gitleaks must be treated as secrets found."""
        mock_load_config.return_value = ({"engines": ["gitleaks"]}, None)

        mock_engine = MagicMock()
        mock_engine.type = "gitleaks"
        mock_engine.output_parser = "gitleaks"
        mock_engine.secrets_found_exit_code = 42
        mock_engine.success_exit_code = 0
        mock_select_engine.return_value = mock_engine

        mock_build_command.return_value = ["gitleaks", "detect", "..."]

        mock_result = MagicMock()
        mock_result.returncode = 42
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        has_secrets, error_msg = check_secrets_with_gitleaks(
            "AWS_ACCESS_KEY=AKIAIOSFODNN7TESTKEY",  # notsecret
            filename="test.txt"
        )

        self.assertTrue(has_secrets, "Exit code 42 from gitleaks must block the operation")
        self.assertIsNotNone(error_msg)
        self.assertIn("Secret Detected", error_msg)

    @patch('ai_guardian.HAS_SCANNER_ENGINE', True)
    @patch('ai_guardian.select_engine')
    @patch('ai_guardian.build_scanner_command')
    @patch('ai_guardian.get_parser')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian.subprocess.run')
    def test_gitleaks_exit_code_0_allows_operation(
        self, mock_run, mock_load_config, mock_get_parser,
        mock_build_command, mock_select_engine
    ):
        """Exit code 0 from gitleaks means no secrets found — allow operation."""
        mock_load_config.return_value = ({"engines": ["gitleaks"]}, None)

        mock_engine = MagicMock()
        mock_engine.type = "gitleaks"
        mock_engine.output_parser = "gitleaks"
        mock_engine.secrets_found_exit_code = 42
        mock_engine.success_exit_code = 0
        mock_select_engine.return_value = mock_engine

        mock_build_command.return_value = ["gitleaks", "detect", "..."]

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        mock_parser = MagicMock()
        mock_parser.parse.return_value = {
            "has_secrets": False,
            "findings": [],
            "total_findings": 0
        }
        mock_get_parser.return_value = mock_parser

        has_secrets, error_msg = check_secrets_with_gitleaks(
            "clean content without secrets",
            filename="test.txt"
        )

        self.assertFalse(has_secrets, "Exit code 0 should allow the operation")
        self.assertIsNone(error_msg)

    @patch('ai_guardian.HAS_SCANNER_ENGINE', True)
    @patch('ai_guardian.select_engine')
    @patch('ai_guardian.build_scanner_command')
    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian.subprocess.run')
    def test_betterleaks_exit_code_1_not_treated_as_success(
        self, mock_run, mock_load_config, mock_build_command, mock_select_engine
    ):
        """Exit code 1 from betterleaks must also be treated as secrets found (Issue #411)."""
        mock_load_config.return_value = ({"engines": ["betterleaks"]}, None)

        mock_engine = MagicMock()
        mock_engine.type = "betterleaks"
        mock_engine.output_parser = "gitleaks"
        mock_engine.secrets_found_exit_code = 42
        mock_engine.success_exit_code = 0
        mock_select_engine.return_value = mock_engine

        mock_build_command.return_value = ["betterleaks", "dir", "..."]

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "leaks found: 1"
        mock_run.return_value = mock_result

        has_secrets, error_msg = check_secrets_with_gitleaks(
            "AWS_ACCESS_KEY=AKIAIOSFODNN7TESTKEY",  # notsecret
            filename="test.txt"
        )

        self.assertTrue(has_secrets, "Exit code 1 from betterleaks must mean secrets found (Issue #411)")
        self.assertIsNotNone(error_msg)


if __name__ == '__main__':
    unittest.main()
