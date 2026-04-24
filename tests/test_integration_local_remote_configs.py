"""
Integration tests for local file paths in remote_configs.

Tests RemoteFetcher with mixed URL types and scenarios that simulate
real-world usage patterns.
"""

import json
import pytest
from pathlib import Path

from ai_guardian.remote_fetcher import RemoteFetcher


class TestRemoteFetcherIntegration:
    """Integration tests for RemoteFetcher with mixed URL types."""

    def test_fetch_multiple_local_sources(self, tmp_path):
        """Test fetching from multiple local sources in sequence."""
        # Create multiple local configs
        config1 = tmp_path / "config1.toml"
        config1.write_text('type = "first"')

        config2 = tmp_path / "config2.json"
        config2.write_text('{"type": "second"}')

        config3 = tmp_path / "config3.toml"
        config3.write_text('type = "third"')

        fetcher = RemoteFetcher()

        # Fetch all three in sequence
        result1 = fetcher.fetch_config(str(config1))
        result2 = fetcher.fetch_config(str(config2))
        result3 = fetcher.fetch_config(str(config3))

        assert result1 is not None
        assert result1["type"] == "first"
        assert result2 is not None
        assert result2["type"] == "second"
        assert result3 is not None
        assert result3["type"] == "third"

    def test_cache_isolation(self, tmp_path):
        """Test that local files don't interfere with HTTPS cache."""
        local_config = tmp_path / "local.json"
        local_config.write_text('{"source": "local"}')

        fetcher = RemoteFetcher()

        # Fetch local (no cache)
        local_result = fetcher.fetch_config(str(local_config))
        assert local_result is not None

        # Verify local file can be updated and re-fetched
        local_config.write_text('{"source": "updated"}')
        updated_result = fetcher.fetch_config(str(local_config))
        assert updated_result is not None
        assert updated_result["source"] == "updated"

    def test_json_and_toml_mixing(self, tmp_path):
        """Test mixing JSON and TOML local configs."""
        json_config = tmp_path / "config.json"
        json_config.write_text('{"format": "json", "patterns": ["json-*"]}')

        toml_config = tmp_path / "config.toml"
        toml_config.write_text('format = "toml"\npatterns = ["toml-*"]')

        fetcher = RemoteFetcher()

        # Fetch both
        json_result = fetcher.fetch_config(str(json_config))
        toml_result = fetcher.fetch_config(str(toml_config))

        assert json_result is not None
        assert json_result["format"] == "json"
        assert json_result["patterns"] == ["json-*"]

        assert toml_result is not None
        assert toml_result["format"] == "toml"
        assert toml_result["patterns"] == ["toml-*"]

    def test_local_and_https_mixed(self, tmp_path):
        """Test fetching mix of local and HTTPS URLs."""
        local_config = tmp_path / "local.toml"
        local_config.write_text('source = "local"')

        fetcher = RemoteFetcher()

        # Fetch local (should work)
        local_result = fetcher.fetch_config(str(local_config))
        assert local_result is not None
        assert local_result["source"] == "local"

        # Try HTTPS (will fail gracefully)
        https_result = fetcher.fetch_config("https://example.com/config.toml")
        # Expected to be None (network error)

        # Fetch local again (should still work)
        local_result2 = fetcher.fetch_config(str(local_config))
        assert local_result2 is not None
        assert local_result2["source"] == "local"

    def test_file_url_variations(self, tmp_path):
        """Test various file:// URL formats."""
        config = tmp_path / "config.toml"
        config.write_text('test = "value"')

        fetcher = RemoteFetcher()

        # Test different file URL formats
        result1 = fetcher.fetch_config(f"file://{config}")
        assert result1 is not None
        assert result1["test"] == "value"

        result2 = fetcher.fetch_config(f"file:///{config}")
        assert result2 is not None
        assert result2["test"] == "value"

    def test_symlink_chain(self, tmp_path):
        """Test following a chain of symlinks."""
        # Create actual config
        actual = tmp_path / "actual.toml"
        actual.write_text('data = "actual"')

        # Create symlink chain
        link1 = tmp_path / "link1.toml"
        link1.symlink_to(actual)

        link2 = tmp_path / "link2.toml"
        link2.symlink_to(link1)

        fetcher = RemoteFetcher()

        # Should resolve through the chain
        result = fetcher.fetch_config(str(link2))
        assert result is not None
        assert result["data"] == "actual"

    def test_concurrent_updates(self, tmp_path):
        """Test that concurrent file updates are reflected."""
        config = tmp_path / "config.json"
        config.write_text('{"version": "1"}')

        fetcher = RemoteFetcher()

        # Fetch multiple times with updates in between
        for version in ["1", "2", "3", "4"]:
            result = fetcher.fetch_config(str(config))
            assert result is not None
            assert result["version"] == version

            # Update for next iteration
            if version != "4":
                config.write_text(f'{{"version": "{int(version) + 1}"}}')

    def test_error_recovery(self, tmp_path):
        """Test that errors don't prevent future successes."""
        config = tmp_path / "config.toml"
        config.write_text('test = "value"')

        fetcher = RemoteFetcher()

        # Success
        result1 = fetcher.fetch_config(str(config))
        assert result1 is not None

        # Failure (missing file)
        result2 = fetcher.fetch_config("/nonexistent.toml")
        assert result2 is None

        # Success again
        result3 = fetcher.fetch_config(str(config))
        assert result3 is not None

        # Failure (invalid content)
        config.write_text('[invalid')
        result4 = fetcher.fetch_config(str(config))
        assert result4 is None

        # Success after fixing
        config.write_text('test = "fixed"')
        result5 = fetcher.fetch_config(str(config))
        assert result5 is not None
        assert result5["test"] == "fixed"

    def test_tilde_expansion_integration(self, tmp_path, monkeypatch):
        """Test tilde expansion in real scenarios."""
        # Mock HOME
        monkeypatch.setenv("HOME", str(tmp_path))

        # Create configs in "home"
        home_config = tmp_path / "config.toml"
        home_config.write_text('location = "home"')

        subdir = tmp_path / ".config"
        subdir.mkdir()
        sub_config = subdir / "app.toml"
        sub_config.write_text('location = "subdir"')

        fetcher = RemoteFetcher()

        # Test tilde expansion
        result1 = fetcher.fetch_config("~/config.toml")
        assert result1 is not None
        assert result1["location"] == "home"

        result2 = fetcher.fetch_config("~/.config/app.toml")
        assert result2 is not None
        assert result2["location"] == "subdir"

    def test_nested_directory_structures(self, tmp_path):
        """Test configs in deeply nested directories."""
        # Create nested structure
        deep = tmp_path / "a" / "b" / "c" / "d" / "e"
        deep.mkdir(parents=True)

        config = deep / "config.json"
        config.write_text('{"depth": "deep"}')

        fetcher = RemoteFetcher()
        result = fetcher.fetch_config(str(config))

        assert result is not None
        assert result["depth"] == "deep"
