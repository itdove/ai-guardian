"""Tests for mtime-based config file caching (#569)."""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ai_guardian import (
    _clear_config_cache,
    _load_config_file,
    _load_pattern_server_config,
    _load_prompt_injection_config,
    _load_secret_scanning_config,
)


class TestConfigCache(unittest.TestCase):
    """Test mtime-based caching in _load_config_file()."""

    def setUp(self):
        _clear_config_cache()

    def tearDown(self):
        _clear_config_cache()

    def test_cache_returns_same_result_on_repeated_calls(self):
        """Repeated calls with unchanged file return cached result (no re-read)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".ai-guardian.json"
            config_file.write_text(json.dumps({"secret_scanning": {"enabled": True}}))

            with patch(
                "ai_guardian.config.loaders.get_config_dir",
                return_value=Path("/nonexistent"),
            ):
                old_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    result1 = _load_config_file()
                    result2 = _load_config_file()

                    self.assertEqual(result1, result2)
                    self.assertIs(result1, result2)
                finally:
                    os.chdir(old_cwd)

    def test_cache_invalidates_on_mtime_change(self):
        """Cache is invalidated when the file's mtime changes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".ai-guardian.json"
            config_file.write_text(json.dumps({"secret_scanning": {"enabled": True}}))

            with patch(
                "ai_guardian.config.loaders.get_config_dir",
                return_value=Path("/nonexistent"),
            ):
                old_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    config1, _ = _load_config_file()
                    self.assertTrue(config1["secret_scanning"]["enabled"])

                    # Ensure mtime changes (some filesystems have 1s resolution)
                    time.sleep(0.05)
                    config_file.write_text(
                        json.dumps({"secret_scanning": {"enabled": False}})
                    )
                    # Force mtime change on filesystems with coarse resolution
                    new_mtime = os.path.getmtime(str(config_file)) + 1
                    os.utime(str(config_file), (new_mtime, new_mtime))

                    config2, _ = _load_config_file()
                    self.assertFalse(config2["secret_scanning"]["enabled"])
                finally:
                    os.chdir(old_cwd)

    def test_clear_config_cache(self):
        """_clear_config_cache() forces a re-read."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".ai-guardian.json"
            config_file.write_text(json.dumps({"key": "value1"}))

            with patch(
                "ai_guardian.config.loaders.get_config_dir",
                return_value=Path("/nonexistent"),
            ):
                old_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    result1 = _load_config_file()

                    _clear_config_cache()

                    result2 = _load_config_file()
                    self.assertEqual(result1, result2)
                    self.assertIsNot(result1, result2)
                finally:
                    os.chdir(old_cwd)

    def test_cache_handles_no_config_file(self):
        """When no config file exists, (None, None) is cached."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch(
                "ai_guardian.config.loaders.get_config_dir",
                return_value=Path("/nonexistent"),
            ):
                old_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    result1 = _load_config_file()
                    result2 = _load_config_file()

                    self.assertEqual(result1, (None, None))
                    self.assertIs(result1, result2)
                finally:
                    os.chdir(old_cwd)

    def test_cache_handles_invalid_json(self):
        """Invalid JSON is cached (error message returned consistently)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".ai-guardian.json"
            config_file.write_text("{bad json")

            with patch(
                "ai_guardian.config.loaders.get_config_dir",
                return_value=Path("/nonexistent"),
            ):
                old_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    result1 = _load_config_file()
                    result2 = _load_config_file()

                    self.assertIsNone(result1[0])
                    self.assertIn("Configuration Error", result1[1])
                    self.assertIs(result1, result2)
                finally:
                    os.chdir(old_cwd)

    def test_multiple_load_functions_share_cache(self):
        """Multiple _load_*_config() functions share one file read."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_data = {
                "secret_scanning": {"enabled": True},
                "prompt_injection": {"enabled": False},
            }
            config_file = Path(tmpdir) / ".ai-guardian.json"
            config_file.write_text(json.dumps(config_data))

            with patch(
                "ai_guardian.config.loaders.get_config_dir",
                return_value=Path("/nonexistent"),
            ):
                old_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    _clear_config_cache()

                    with patch("builtins.open", wraps=open) as mock_open:
                        _load_secret_scanning_config()
                        _load_prompt_injection_config()

                        config_name = config_file.name
                        json_reads = [
                            c for c in mock_open.call_args_list if config_name in str(c)
                        ]
                        self.assertEqual(
                            len(json_reads), 1, "Config file should be read only once"
                        )
                finally:
                    os.chdir(old_cwd)

    def test_pattern_server_uses_cached_config(self):
        """_load_pattern_server_config() uses _load_config_file() and benefits from cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_data = {
                "secret_scanning": {
                    "enabled": True,
                    "pattern_server": {
                        "url": "https://example.com/patterns",
                        "enabled": True,
                    },
                }
            }
            config_file = Path(tmpdir) / ".ai-guardian.json"
            config_file.write_text(json.dumps(config_data))

            with patch(
                "ai_guardian.config.loaders.get_config_dir",
                return_value=Path("/nonexistent"),
            ):
                old_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    _clear_config_cache()

                    _load_config_file()
                    with patch("builtins.open", wraps=open) as mock_open:
                        result = _load_pattern_server_config()

                        json_reads = [
                            c
                            for c in mock_open.call_args_list
                            if str(config_file) in str(c)
                        ]
                        self.assertEqual(
                            len(json_reads),
                            0,
                            "Pattern server should use cached config",
                        )

                    self.assertIsNotNone(result)
                    self.assertEqual(result["url"], "https://example.com/patterns")
                finally:
                    os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
