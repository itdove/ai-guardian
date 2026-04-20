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

    @patch('logging.error')
    @patch('ai_guardian._load_pattern_server_config')
    @patch('ai_guardian.PatternServerClient')
    def test_pattern_server_failure_blocks_with_error(self, mock_client_class, mock_pattern_config, mock_log_error):
        """Test that operation is BLOCKED when pattern server fails"""
        # Setup: Pattern server configured
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
            has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(content, "test.txt")

        # Verify: Operation should be blocked
        self.assertTrue(has_secrets, "Operation should be blocked")
        self.assertIsNotNone(error_msg, "Error message should be returned")

        # Check if logging.error was called
        error_calls = [str(call) for call in mock_log_error.call_args_list]
        self.assertTrue(
            any("Pattern server failure" in str(call) for call in error_calls),
            f"Expected pattern server error to be logged. Got calls: {error_calls}"
        )

    @patch('ai_guardian._load_pattern_server_config')
    @patch('ai_guardian.PatternServerClient')
    def test_pattern_server_blocks_even_when_warn_on_failure_false(self, mock_client_class, mock_pattern_config):
        """
        Test that operation is BLOCKED even when warn_on_failure is False.

        Note: As of the security fix for issue #165, the warn_on_failure flag
        no longer controls blocking behavior. Pattern server failures always block.
        """
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
            has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(content, "test.txt")

        # Verify: Operation should be blocked (security fix)
        self.assertTrue(has_secrets, "Operation should be blocked even with warn_on_failure=False")
        self.assertIsNotNone(error_msg, "Error message should be returned")
        self.assertIn("BLOCKED BY POLICY", error_msg, "Should indicate blocking policy")

    @patch('ai_guardian._load_pattern_server_config')
    @patch('ai_guardian.PatternServerClient')
    def test_pattern_server_blocks_by_default(self, mock_client_class, mock_pattern_config):
        """Test that operation is BLOCKED by default (when warn_on_failure not specified)"""
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
            has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(content, "test.txt")

        # Verify: Operation should be blocked by default
        self.assertTrue(has_secrets, "Operation should be blocked by default")
        self.assertIsNotNone(error_msg, "Error message should be returned")
        self.assertIn("BLOCKED BY POLICY", error_msg, "Should indicate blocking policy")

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
    def test_pattern_server_unavailable_blocks_operation(self, mock_client_class, mock_pattern_config):
        """
        Test that operations are BLOCKED when pattern server is configured but unavailable.

        This is the critical security fix: if you configure a pattern server,
        those specific patterns are required. We do NOT fall back to defaults.
        """
        # Setup: Pattern server configured
        pattern_config = {
            "url": "https://pattern-server.example.com",
            "patterns_endpoint": "/patterns/gitleaks/8.27.0"
        }
        mock_pattern_config.return_value = pattern_config

        # Mock client that fails to get patterns (returns None)
        # This simulates: pattern server down + cache expired
        mock_client = MagicMock()
        mock_client.get_patterns_path.return_value = None
        mock_client.token_file = Path("/tmp/test-token")
        mock_client_class.return_value = mock_client

        # Execute: Attempt to scan content
        content = "This is test content"
        with patch('ai_guardian.HAS_PATTERN_SERVER', True):
            has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(content, "test.txt")

        # Verify: Operation should be BLOCKED
        self.assertTrue(has_secrets, "Operation should be blocked (has_secrets=True)")
        self.assertIsNotNone(error_msg, "Error message should be returned")
        self.assertIn("BLOCKED BY POLICY", error_msg, "Error should indicate blocking policy")
        self.assertIn("PATTERN SERVER UNAVAILABLE", error_msg, "Error should mention pattern server")
        self.assertIn("pattern-server.example.com", error_msg, "Error should show server URL")
        self.assertIn("/patterns/gitleaks/8.27.0", error_msg, "Error should show endpoint")

    @patch('ai_guardian._load_pattern_server_config')
    @patch('ai_guardian.PatternServerClient')
    def test_blocking_error_message_content(self, mock_client_class, mock_pattern_config):
        """Test that blocking error message contains helpful information"""
        # Setup: Pattern server configured
        pattern_config = {
            "url": "https://pattern-server.example.com",
            "patterns_endpoint": "/api/patterns",
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
            has_secrets, error_msg = ai_guardian.check_secrets_with_gitleaks(content, "test.txt")

        # Verify: Error message contains helpful details
        self.assertTrue(has_secrets, "Operation should be blocked")
        self.assertIsNotNone(error_msg, "Error message should be returned")

        # Check for helpful information in error message
        self.assertIn("BLOCKED BY POLICY", error_msg, "Should indicate blocking policy")
        self.assertIn("PATTERN SERVER UNAVAILABLE", error_msg, "Should indicate pattern server unavailable")
        self.assertIn("pattern-server.example.com", error_msg, "Should mention server URL")
        self.assertIn("/api/patterns", error_msg, "Should mention endpoint")
        self.assertIn("Common causes", error_msg, "Should list common causes")
        self.assertIn("Network error", error_msg, "Should mention network error")
        self.assertIn("Authentication failure", error_msg, "Should mention auth failure")
        self.assertIn("To fix", error_msg, "Should provide fix instructions")
        self.assertIn("disable pattern server", error_msg, "Should mention disabling as option")

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
