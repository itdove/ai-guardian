"""
Unit tests for pattern_server warn_on_failure configuration.

Tests verify that the warn_on_failure setting correctly controls whether
warnings are shown when the pattern server fails to provide patterns.
"""

import logging
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, MagicMock

import ai_guardian
from ai_guardian.pattern_server import PatternServerClient


class PatternServerWarningsTest(TestCase):
    """Test suite for pattern server warn_on_failure configuration"""

    def setUp(self):
        """Set up test fixtures"""
        # Capture logging output from ai_guardian modules
        self.log_capture = []

        # Create a custom handler that captures all log records
        class ListHandler(logging.Handler):
            def __init__(self, log_list):
                super().__init__()
                self.log_list = log_list

            def emit(self, record):
                self.log_list.append(record)

        self.log_handler = ListHandler(self.log_capture)
        self.log_handler.setLevel(logging.DEBUG)

        # Store original logging level
        self.original_level = logging.getLogger().level

        # Add handler to root logger (ai_guardian uses logging.warning, not logger.warning)
        logging.getLogger().addHandler(self.log_handler)
        logging.getLogger().setLevel(logging.DEBUG)

        # Also add to specific loggers for pattern_server
        logging.getLogger('ai_guardian.pattern_server').addHandler(self.log_handler)
        logging.getLogger('ai_guardian.pattern_server').setLevel(logging.DEBUG)

    def tearDown(self):
        """Clean up test fixtures"""
        # Remove handlers
        logging.getLogger().removeHandler(self.log_handler)
        logging.getLogger('ai_guardian.pattern_server').removeHandler(self.log_handler)

        # Restore original logging level
        logging.getLogger().setLevel(self.original_level)

        # Close handler
        self.log_handler.close()

    def test_warn_on_failure_default_is_true(self):
        """Test that warn_on_failure defaults to True when not specified"""
        config = {
            "url": "https://pattern-server.example.com",
            "auth": {"token_env": "TEST_TOKEN"}
        }

        client = PatternServerClient(config)

        self.assertTrue(client.warn_on_failure, "warn_on_failure should default to True")

    def test_warn_on_failure_explicit_true(self):
        """Test that warn_on_failure can be explicitly set to True"""
        config = {
            "url": "https://pattern-server.example.com",
            "warn_on_failure": True,
            "auth": {"token_env": "TEST_TOKEN"}
        }

        client = PatternServerClient(config)

        self.assertTrue(client.warn_on_failure, "warn_on_failure should be True when set")

    def test_warn_on_failure_explicit_false(self):
        """Test that warn_on_failure can be set to False"""
        config = {
            "url": "https://pattern-server.example.com",
            "warn_on_failure": False,
            "auth": {"token_env": "TEST_TOKEN"}
        }

        client = PatternServerClient(config)

        self.assertFalse(client.warn_on_failure, "warn_on_failure should be False when set")

    @patch('logging.warning')
    @patch('ai_guardian._load_pattern_server_config')
    @patch('ai_guardian.PatternServerClient')
    def test_warn_on_failure_true_shows_warning(self, mock_client_class, mock_pattern_config, mock_log_warning):
        """Test that warnings ARE shown when warn_on_failure is True"""
        # Setup: Pattern server configured with warn_on_failure=True
        pattern_config = {
            "url": "https://pattern-server.example.com",
            "warn_on_failure": True
        }
        mock_pattern_config.return_value = pattern_config

        # Mock client that fails to get patterns (returns None)
        mock_client = MagicMock()
        mock_client.warn_on_failure = True
        mock_client.get_patterns_path.return_value = None
        mock_client.token_file = Path("/tmp/test-token")
        mock_client_class.return_value = mock_client

        # Execute: Scan content (will attempt to use pattern server)
        content = "This is test content"
        with patch('ai_guardian.HAS_PATTERN_SERVER', True):
            has_secrets, _ = ai_guardian.check_secrets_with_gitleaks(content, "test.txt")

        # Verify: Warning should be logged
        # Check if logging.warning was called with a message about pattern server
        warning_calls = [str(call) for call in mock_log_warning.call_args_list]
        self.assertTrue(
            any("Pattern server configured" in str(call) for call in warning_calls),
            f"Expected pattern server warning to be logged. Got calls: {warning_calls}"
        )

    @patch('ai_guardian._load_pattern_server_config')
    @patch('ai_guardian.PatternServerClient')
    def test_warn_on_failure_false_suppresses_warning(self, mock_client_class, mock_pattern_config):
        """Test that warnings are NOT shown when warn_on_failure is False"""
        # Setup: Pattern server configured with warn_on_failure=False
        pattern_config = {
            "url": "https://pattern-server.example.com",
            "warn_on_failure": False
        }
        mock_pattern_config.return_value = pattern_config

        # Mock client that fails to get patterns (returns None)
        mock_client = MagicMock()
        mock_client.warn_on_failure = False
        mock_client.get_patterns_path.return_value = None
        mock_client.token_file = Path("/tmp/test-token")
        mock_client_class.return_value = mock_client

        # Clear any previous log captures
        self.log_capture.clear()

        # Execute: Scan content (will attempt to use pattern server)
        content = "This is test content"
        with patch('ai_guardian.HAS_PATTERN_SERVER', True):
            has_secrets, _ = ai_guardian.check_secrets_with_gitleaks(content, "test.txt")

        # Verify: No warning should be logged about pattern server
        warning_logs = [r for r in self.log_capture if r.levelno == logging.WARNING]
        warning_messages = [r.getMessage() for r in warning_logs]

        # Check that NO warning mentions pattern server failure
        self.assertFalse(
            any("Pattern server configured" in msg for msg in warning_messages),
            f"Expected NO pattern server warning when warn_on_failure=False. Got: {warning_messages}"
        )

    @patch('logging.warning')
    @patch('ai_guardian._load_pattern_server_config')
    @patch('ai_guardian.PatternServerClient')
    def test_warn_on_failure_default_shows_warning(self, mock_client_class, mock_pattern_config, mock_log_warning):
        """Test that warnings ARE shown by default (when warn_on_failure not specified)"""
        # Setup: Pattern server configured without warn_on_failure field
        pattern_config = {
            "url": "https://pattern-server.example.com"
            # Note: warn_on_failure not specified, should default to True
        }
        mock_pattern_config.return_value = pattern_config

        # Mock client that fails to get patterns (returns None)
        mock_client = MagicMock()
        mock_client.warn_on_failure = True  # Should be True by default
        mock_client.get_patterns_path.return_value = None
        mock_client.token_file = Path("/tmp/test-token")
        mock_client_class.return_value = mock_client

        # Execute: Scan content (will attempt to use pattern server)
        content = "This is test content"
        with patch('ai_guardian.HAS_PATTERN_SERVER', True):
            has_secrets, _ = ai_guardian.check_secrets_with_gitleaks(content, "test.txt")

        # Verify: Warning should be logged (default behavior)
        warning_calls = [str(call) for call in mock_log_warning.call_args_list]
        self.assertTrue(
            any("Pattern server configured" in str(call) for call in warning_calls),
            f"Expected pattern server warning by default. Got calls: {warning_calls}"
        )

    @patch('ai_guardian.pattern_server.logger')
    @patch('requests.get')
    def test_warn_on_failure_auth_error_scenario(self, mock_get, mock_logger):
        """Test warning behavior when pattern server returns 401 auth error"""
        # Setup: Pattern server with warn_on_failure=True
        config = {
            "url": "https://pattern-server.example.com",
            "warn_on_failure": True,
            "auth": {"token_env": "TEST_TOKEN"}
        }

        # Mock authentication error (401)
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        # Set auth token in environment
        with patch.dict('os.environ', {'TEST_TOKEN': 'fake-token'}):
            # Use a temporary cache directory that doesn't exist
            with tempfile.TemporaryDirectory() as tmpdir:
                config["cache"] = {"path": str(Path(tmpdir) / "test_patterns.toml")}
                client = PatternServerClient(config)

                # Execute: Try to get patterns (will fail with 401)
                patterns_path = client.get_patterns_path()

                # Verify: Should return None and log error
                self.assertIsNone(patterns_path, "Should return None on auth failure")

                # Check that error was logged
                error_calls = [str(call) for call in mock_logger.error.call_args_list]
                self.assertTrue(
                    any("401 Unauthorized" in str(call) for call in error_calls),
                    f"Expected 401 auth error in logs. Got: {error_calls}"
                )

    @patch('ai_guardian.pattern_server.logger')
    @patch('requests.get')
    def test_warn_on_failure_network_error_scenario(self, mock_get, mock_logger):
        """Test warning behavior when pattern server has network error"""
        import requests

        # Setup: Pattern server with warn_on_failure=True
        config = {
            "url": "https://pattern-server.example.com",
            "warn_on_failure": True,
            "auth": {"token_env": "TEST_TOKEN"}
        }

        # Mock network connection error
        mock_get.side_effect = requests.exceptions.ConnectionError("Network unreachable")

        # Set auth token in environment
        with patch.dict('os.environ', {'TEST_TOKEN': 'fake-token'}):
            # Use a temporary cache directory that doesn't exist
            with tempfile.TemporaryDirectory() as tmpdir:
                config["cache"] = {"path": str(Path(tmpdir) / "test_patterns.toml")}
                client = PatternServerClient(config)

                # Execute: Try to get patterns (will fail with network error)
                patterns_path = client.get_patterns_path()

                # Verify: Should return None and log error
                self.assertIsNone(patterns_path, "Should return None on network error")

                # Check that error was logged
                error_calls = [str(call) for call in mock_logger.error.call_args_list]
                self.assertTrue(
                    any("Connection error" in str(call) for call in error_calls),
                    f"Expected connection error in logs. Got: {error_calls}"
                )

    @patch('ai_guardian.pattern_server.logger')
    @patch('requests.get')
    def test_warn_on_failure_timeout_scenario(self, mock_get, mock_logger):
        """Test warning behavior when pattern server times out"""
        import requests

        # Setup: Pattern server with warn_on_failure=True
        config = {
            "url": "https://pattern-server.example.com",
            "warn_on_failure": True,
            "auth": {"token_env": "TEST_TOKEN"}
        }

        # Mock timeout error
        mock_get.side_effect = requests.exceptions.Timeout("Request timed out")

        # Set auth token in environment
        with patch.dict('os.environ', {'TEST_TOKEN': 'fake-token'}):
            # Use a temporary cache directory that doesn't exist
            with tempfile.TemporaryDirectory() as tmpdir:
                config["cache"] = {"path": str(Path(tmpdir) / "test_patterns.toml")}
                client = PatternServerClient(config)

                # Execute: Try to get patterns (will fail with timeout)
                patterns_path = client.get_patterns_path()

                # Verify: Should return None and log error
                self.assertIsNone(patterns_path, "Should return None on timeout")

                # Check that error was logged
                error_calls = [str(call) for call in mock_logger.error.call_args_list]
                self.assertTrue(
                    any("Timeout" in str(call) for call in error_calls),
                    f"Expected timeout error in logs. Got: {error_calls}"
                )

    @patch('ai_guardian.pattern_server.logger')
    @patch('requests.get')
    def test_warn_on_failure_server_unavailable_scenario(self, mock_get, mock_logger):
        """Test warning behavior when pattern server returns 503 (unavailable)"""
        # Setup: Pattern server with warn_on_failure=True
        config = {
            "url": "https://pattern-server.example.com",
            "warn_on_failure": True,
            "auth": {"token_env": "TEST_TOKEN"}
        }

        # Mock server unavailable error (503)
        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_get.return_value = mock_response

        # Set auth token in environment
        with patch.dict('os.environ', {'TEST_TOKEN': 'fake-token'}):
            # Use a temporary cache directory that doesn't exist
            with tempfile.TemporaryDirectory() as tmpdir:
                config["cache"] = {"path": str(Path(tmpdir) / "test_patterns.toml")}
                client = PatternServerClient(config)

                # Execute: Try to get patterns (will fail with 503)
                patterns_path = client.get_patterns_path()

                # Verify: Should return None and log error
                self.assertIsNone(patterns_path, "Should return None when server unavailable")

                # Check that error was logged
                error_calls = [str(call) for call in mock_logger.error.call_args_list]
                self.assertTrue(
                    any("returned error" in str(call) or "503" in str(call) for call in error_calls),
                    f"Expected 503 server error in logs. Got: {error_calls}"
                )

    @patch('ai_guardian._load_pattern_server_config')
    @patch('ai_guardian.PatternServerClient')
    def test_integration_warn_on_failure_with_secret_detection(self, mock_client_class, mock_pattern_config):
        """
        Integration test: Verify that secret detection still works correctly
        even when pattern server fails with warn_on_failure=False
        """
        # Setup: Pattern server configured with warn_on_failure=False
        pattern_config = {
            "url": "https://pattern-server.example.com",
            "warn_on_failure": False
        }
        mock_pattern_config.return_value = pattern_config

        # Mock client that fails to get patterns (returns None)
        # This simulates pattern server being down
        mock_client = MagicMock()
        mock_client.warn_on_failure = False
        mock_client.get_patterns_path.return_value = None
        mock_client_class.return_value = mock_client

        # Execute: Scan content with actual secret (should fall back to default gitleaks)
        secret_content = "My GitHub token: ghp_16C0123456789abcdefghijklmTEST0000"

        with patch('ai_guardian.HAS_PATTERN_SERVER', True):
            has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(
                secret_content, "test.txt"
            )

        # Verify: Secret detection should still work (using default gitleaks config)
        self.assertTrue(has_secrets, "Secret detection should work even when pattern server fails")
        self.assertIsNotNone(error_msg, "Error message should be returned for detected secret")

    @patch('logging.warning')
    @patch('ai_guardian._load_pattern_server_config')
    @patch('ai_guardian.PatternServerClient')
    def test_warn_on_failure_warning_message_content(self, mock_client_class, mock_pattern_config, mock_log_warning):
        """Test that warning message contains helpful information"""
        # Setup: Pattern server configured with warn_on_failure=True
        pattern_config = {
            "url": "https://pattern-server.example.com",
            "warn_on_failure": True
        }
        mock_pattern_config.return_value = pattern_config

        # Mock client that fails to get patterns
        mock_client = MagicMock()
        mock_client.warn_on_failure = True
        mock_client.get_patterns_path.return_value = None
        mock_client.token_file = Path("/home/user/.config/ai-guardian/pattern-token")
        mock_client_class.return_value = mock_client

        # Execute: Scan content
        content = "This is test content"
        with patch('ai_guardian.HAS_PATTERN_SERVER', True):
            ai_guardian.check_secrets_with_gitleaks(content, "test.txt")

        # Verify: Warning message contains helpful details
        # Find the pattern server warning call
        pattern_server_warnings = [
            call[0][0] for call in mock_log_warning.call_args_list
            if "Pattern server configured" in str(call)
        ]

        self.assertTrue(len(pattern_server_warnings) > 0, "Should have pattern server warning")

        warning_text = pattern_server_warnings[0]

        # Check for helpful information in warning
        self.assertIn("pattern-server.example.com", warning_text, "Should mention server URL")
        self.assertIn("Falling back", warning_text, "Should mention fallback behavior")
        self.assertIn("Common causes", warning_text, "Should mention common causes")
        self.assertIn("token", warning_text.lower(), "Should mention token")

    @patch('ai_guardian.pattern_server.logger')
    @patch('requests.get')
    def test_public_url_without_token_succeeds(self, mock_get, mock_logger):
        """Test that public URLs work without authentication token"""
        # Setup: Pattern server pointing to public URL (GitHub raw content)
        config = {
            "url": "https://raw.githubusercontent.com",
            "patterns_endpoint": "/leaktk/patterns/main/target/patterns/gitleaks/8.27.0",
            "auth": {"token_env": "TEST_TOKEN"}
        }

        # Mock successful response (200 OK) for unauthenticated request
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "[rules]\n# Test patterns"
        mock_get.return_value = mock_response

        # NO token in environment (public URL scenario)
        with patch.dict('os.environ', {}, clear=True):
            # Use a temporary cache directory
            with tempfile.TemporaryDirectory() as tmpdir:
                config["cache"] = {"path": str(Path(tmpdir) / "test_patterns.toml")}
                client = PatternServerClient(config)

                # Execute: Try to get patterns (should succeed without token)
                patterns_path = client.get_patterns_path()

                # Verify: Should succeed and return cache path
                self.assertIsNotNone(patterns_path, "Should succeed for public URLs without token")
                self.assertTrue(patterns_path.exists(), "Cache file should be created")

                # Verify the request was made without Authorization header
                mock_get.assert_called_once()
                call_args = mock_get.call_args
                headers = call_args[1]['headers']
                self.assertNotIn('Authorization', headers, "Should not include Authorization header for public URLs")

                # Check that debug log mentions unauthenticated request
                debug_calls = [str(call) for call in mock_logger.debug.call_args_list]
                self.assertTrue(
                    any("unauthenticated" in str(call).lower() for call in debug_calls),
                    f"Expected debug log about unauthenticated request. Got: {debug_calls}"
                )

    @patch('ai_guardian.pattern_server.logger')
    @patch('requests.get')
    def test_public_url_with_token_uses_auth(self, mock_get, mock_logger):
        """Test that authentication is used when token is available, even for public URLs"""
        # Setup: Pattern server pointing to public URL with token available
        config = {
            "url": "https://raw.githubusercontent.com",
            "patterns_endpoint": "/leaktk/patterns/main/target/patterns/gitleaks/8.27.0",
            "auth": {"token_env": "TEST_TOKEN"}
        }

        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "[rules]\n# Test patterns"
        mock_get.return_value = mock_response

        # Token IS available in environment
        with patch.dict('os.environ', {'TEST_TOKEN': 'ghp_test_token_12345'}):
            # Use a temporary cache directory
            with tempfile.TemporaryDirectory() as tmpdir:
                config["cache"] = {"path": str(Path(tmpdir) / "test_patterns.toml")}
                client = PatternServerClient(config)

                # Execute: Try to get patterns (should use token)
                patterns_path = client.get_patterns_path()

                # Verify: Should succeed and use authentication
                self.assertIsNotNone(patterns_path, "Should succeed with token")

                # Verify the request included Authorization header
                mock_get.assert_called_once()
                call_args = mock_get.call_args
                headers = call_args[1]['headers']
                self.assertIn('Authorization', headers, "Should include Authorization header when token available")
                self.assertEqual(headers['Authorization'], 'Bearer ghp_test_token_12345')

                # Check debug log mentions using authentication
                debug_calls = [str(call) for call in mock_logger.debug.call_args_list]
                self.assertTrue(
                    any("Using authentication" in str(call) for call in debug_calls),
                    f"Expected debug log about using authentication. Got: {debug_calls}"
                )

    @patch('ai_guardian.pattern_server.logger')
    @patch('requests.get')
    def test_private_url_without_token_shows_helpful_error(self, mock_get, mock_logger):
        """Test that private URLs without token show helpful error message"""
        # Setup: Pattern server pointing to private endpoint
        config = {
            "url": "https://private-patterns.example.com",
            "patterns_endpoint": "/api/v1/patterns",
            "auth": {"token_env": "PRIVATE_PATTERN_TOKEN"}
        }

        # Mock 401 Unauthorized response (requires auth)
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        # NO token in environment
        with patch.dict('os.environ', {}, clear=True):
            # Use a temporary cache directory
            with tempfile.TemporaryDirectory() as tmpdir:
                config["cache"] = {"path": str(Path(tmpdir) / "test_patterns.toml")}
                client = PatternServerClient(config)

                # Execute: Try to get patterns (should fail with helpful message)
                patterns_path = client.get_patterns_path()

                # Verify: Should fail
                self.assertIsNone(patterns_path, "Should fail for private URLs without token")

                # Check error message mentions authentication is required
                error_calls = [str(call) for call in mock_logger.error.call_args_list]
                self.assertTrue(
                    any("requires authentication" in str(call) for call in error_calls),
                    f"Expected error about authentication required. Got: {error_calls}"
                )

                # Check info message shows how to set token
                info_calls = [str(call) for call in mock_logger.info.call_args_list]
                self.assertTrue(
                    any("PRIVATE_PATTERN_TOKEN" in str(call) for call in info_calls),
                    f"Expected info about setting token. Got: {info_calls}"
                )

    @patch('ai_guardian.pattern_server.logger')
    @patch('requests.get')
    def test_private_url_with_wrong_token_shows_check_token_error(self, mock_get, mock_logger):
        """Test that private URLs with wrong token show different error message"""
        # Setup: Pattern server with token configured
        config = {
            "url": "https://private-patterns.example.com",
            "patterns_endpoint": "/api/v1/patterns",
            "auth": {"token_env": "PRIVATE_PATTERN_TOKEN"}
        }

        # Mock 401 Unauthorized response (wrong token)
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        # Token IS set but wrong
        with patch.dict('os.environ', {'PRIVATE_PATTERN_TOKEN': 'wrong_token'}):
            # Use a temporary cache directory
            with tempfile.TemporaryDirectory() as tmpdir:
                config["cache"] = {"path": str(Path(tmpdir) / "test_patterns.toml")}
                client = PatternServerClient(config)

                # Execute: Try to get patterns (should fail)
                patterns_path = client.get_patterns_path()

                # Verify: Should fail
                self.assertIsNone(patterns_path, "Should fail with wrong token")

                # Check error message mentions checking the token (different from "no token")
                error_calls = [str(call) for call in mock_logger.error.call_args_list]
                self.assertTrue(
                    any("authentication failed" in str(call).lower() for call in error_calls),
                    f"Expected error about authentication failed. Got: {error_calls}"
                )

                # Should mention checking the token
                info_calls = [str(call) for call in mock_logger.info.call_args_list]
                self.assertTrue(
                    any("check your" in str(call).lower() for call in info_calls),
                    f"Expected info about checking token. Got: {info_calls}"
                )
