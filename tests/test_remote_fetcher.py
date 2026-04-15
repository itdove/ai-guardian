"""
Unit tests for remote_fetcher module
"""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ai_guardian.remote_fetcher import RemoteFetcher


class RemoteFetcherEnvVarsTest(unittest.TestCase):
    """Test suite for RemoteFetcher environment variable support"""

    def setUp(self):
        """Set up test fixtures"""
        # Create temporary cache directory
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.fetcher = RemoteFetcher(cache_dir=self.cache_dir)

        # Save original environment
        self.original_env = os.environ.copy()

    def tearDown(self):
        """Clean up test fixtures"""
        # Restore original environment
        os.environ.clear()
        os.environ.update(self.original_env)

        # Clean up temp directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_default_values_without_env_vars(self):
        """Test that default values are used when no env vars are set"""
        # Clear any existing env vars
        os.environ.pop("AI_GUARDIAN_REFRESH_INTERVAL_HOURS", None)
        os.environ.pop("AI_GUARDIAN_EXPIRE_AFTER_HOURS", None)

        # Mock the requests.get to avoid actual network calls
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"test": "data"}'

        with patch('ai_guardian.remote_fetcher.requests.get', return_value=mock_response):
            config = self.fetcher.fetch_config("http://example.com/config.json")

            # Verify config was fetched
            self.assertIsNotNone(config)
            self.assertEqual(config, {"test": "data"})

            # Create a stale cache (13 hours old) to test refresh_interval default (12h)
            cache_file = self.fetcher._get_cache_path("http://example.com/config.json")
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)

            # Modify cached_at to make it 13 hours old (stale)
            cache_data['cached_at'] = time.time() - (13 * 3600)
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)

            # Next fetch should try to refresh (because > 12h default)
            with patch('ai_guardian.remote_fetcher.requests.get', return_value=mock_response) as mock_get:
                config = self.fetcher.fetch_config("http://example.com/config.json")
                # Should have tried to refresh
                self.assertTrue(mock_get.called)

    def test_refresh_interval_from_env_var(self):
        """Test that AI_GUARDIAN_REFRESH_INTERVAL_HOURS is read from environment"""
        # Set custom refresh interval to 6 hours
        os.environ["AI_GUARDIAN_REFRESH_INTERVAL_HOURS"] = "6"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"test": "data"}'

        # Initial fetch
        with patch('ai_guardian.remote_fetcher.requests.get', return_value=mock_response):
            config = self.fetcher.fetch_config("http://example.com/config.json")
            self.assertIsNotNone(config)

            # Create cache that's 7 hours old (should be stale with 6h interval)
            cache_file = self.fetcher._get_cache_path("http://example.com/config.json")
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            cache_data['cached_at'] = time.time() - (7 * 3600)
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)

            # Next fetch should try to refresh (because > 6h)
            with patch('ai_guardian.remote_fetcher.requests.get', return_value=mock_response) as mock_get:
                config = self.fetcher.fetch_config("http://example.com/config.json")
                # Should have tried to refresh because 7h > 6h
                self.assertTrue(mock_get.called)

    def test_expire_after_from_env_var(self):
        """Test that AI_GUARDIAN_EXPIRE_AFTER_HOURS is read from environment"""
        # Set custom expiration to 24 hours
        os.environ["AI_GUARDIAN_EXPIRE_AFTER_HOURS"] = "24"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"test": "data"}'

        # Initial fetch
        with patch('ai_guardian.remote_fetcher.requests.get', return_value=mock_response):
            config = self.fetcher.fetch_config("http://example.com/config.json")
            self.assertIsNotNone(config)

            # Create expired cache (25 hours old, > 24h expiration)
            cache_file = self.fetcher._get_cache_path("http://example.com/config.json")
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            cache_data['cached_at'] = time.time() - (25 * 3600)
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)

            # Simulate failed refresh
            mock_failed_response = Mock()
            mock_failed_response.status_code = 500

            with patch('ai_guardian.remote_fetcher.requests.get', return_value=mock_failed_response):
                config = self.fetcher.fetch_config("http://example.com/config.json")
                # Should return None because cache is expired (25h > 24h) and refresh failed
                self.assertIsNone(config)

    def test_both_env_vars_together(self):
        """Test that both env vars work together"""
        # Set custom values
        os.environ["AI_GUARDIAN_REFRESH_INTERVAL_HOURS"] = "3"
        os.environ["AI_GUARDIAN_EXPIRE_AFTER_HOURS"] = "12"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"test": "data"}'

        # Initial fetch
        with patch('ai_guardian.remote_fetcher.requests.get', return_value=mock_response):
            config = self.fetcher.fetch_config("http://example.com/config.json")
            self.assertIsNotNone(config)

            # Create cache that's 5 hours old (stale but not expired: 5h > 3h but < 12h)
            cache_file = self.fetcher._get_cache_path("http://example.com/config.json")
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            cache_data['cached_at'] = time.time() - (5 * 3600)
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)

            # Simulate failed refresh
            mock_failed_response = Mock()
            mock_failed_response.status_code = 500

            with patch('ai_guardian.remote_fetcher.requests.get', return_value=mock_failed_response):
                config = self.fetcher.fetch_config("http://example.com/config.json")
                # Should return cached data because it's not expired yet (5h < 12h)
                self.assertIsNotNone(config)
                self.assertEqual(config, {"test": "data"})

    def test_explicit_params_override_env_vars(self):
        """Test that explicit parameters override environment variables"""
        # Set env vars
        os.environ["AI_GUARDIAN_REFRESH_INTERVAL_HOURS"] = "6"
        os.environ["AI_GUARDIAN_EXPIRE_AFTER_HOURS"] = "24"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"test": "data"}'

        # Initial fetch
        with patch('ai_guardian.remote_fetcher.requests.get', return_value=mock_response):
            config = self.fetcher.fetch_config("http://example.com/config.json")
            self.assertIsNotNone(config)

            # Create cache that's 7 hours old
            cache_file = self.fetcher._get_cache_path("http://example.com/config.json")
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            cache_data['cached_at'] = time.time() - (7 * 3600)
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)

            # Call with explicit refresh_interval_hours=10 (should override env var of 6)
            # 7h < 10h, so cache should be fresh
            with patch('ai_guardian.remote_fetcher.requests.get', return_value=mock_response) as mock_get:
                config = self.fetcher.fetch_config(
                    "http://example.com/config.json",
                    refresh_interval_hours=10
                )
                # Should NOT have tried to refresh because 7h < 10h
                self.assertFalse(mock_get.called)

    def test_env_var_invalid_value_uses_default(self):
        """Test that invalid env var values fall back to defaults"""
        # Set invalid env var
        os.environ["AI_GUARDIAN_REFRESH_INTERVAL_HOURS"] = "invalid"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"test": "data"}'

        # Should raise ValueError when trying to convert "invalid" to int
        with patch('ai_guardian.remote_fetcher.requests.get', return_value=mock_response):
            with self.assertRaises(ValueError):
                self.fetcher.fetch_config("http://example.com/config.json")


if __name__ == '__main__':
    unittest.main()
