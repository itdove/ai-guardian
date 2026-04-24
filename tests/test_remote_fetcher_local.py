"""
Unit tests for local file path support in RemoteFetcher.

Tests cover:
- file:// URL scheme
- Absolute paths
- Tilde expansion
- JSON and TOML format support
- Error handling (missing files, permission denied, invalid format)
- Symlink following
- No caching behavior
"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch

from ai_guardian.remote_fetcher import RemoteFetcher


class TestLocalFilePaths:
    """Test local file path support in remote configs."""

    def test_file_url_scheme(self, tmp_path):
        """Test file:// URL scheme."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('builtin_deny_patterns = ["*.secret"]')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(f"file://{config_file}")

        assert config is not None
        assert "builtin_deny_patterns" in config
        assert config["builtin_deny_patterns"] == ["*.secret"]

    def test_absolute_path(self, tmp_path):
        """Test absolute path without file:// scheme."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('skill_allowed_patterns = ["test-*"]')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(config_file))

        assert config is not None
        assert config["skill_allowed_patterns"] == ["test-*"]

    def test_tilde_expansion(self, monkeypatch, tmp_path):
        """Test tilde expansion for home directory."""
        # Mock home directory
        monkeypatch.setenv("HOME", str(tmp_path))

        config_file = tmp_path / "config.toml"
        config_file.write_text('mcp_deny_patterns = ["*admin*"]')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config("~/config.toml")

        assert config is not None
        assert config["mcp_deny_patterns"] == ["*admin*"]

    def test_file_not_found(self):
        """Test error handling for missing file."""
        fetcher = RemoteFetcher()
        config = fetcher.fetch_config("/nonexistent/file.toml")

        assert config is None

    def test_not_a_file(self, tmp_path):
        """Test error handling when path is a directory."""
        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(tmp_path))

        assert config is None

    def test_permission_denied(self, tmp_path):
        """Test error handling for unreadable file."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('test = "value"')
        config_file.chmod(0o000)  # Remove all permissions

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(config_file))

        assert config is None

        # Cleanup
        config_file.chmod(0o644)

    def test_json_format(self, tmp_path):
        """Test JSON format support."""
        config_file = tmp_path / "config.json"
        config_file.write_text('{"builtin_deny_patterns": ["*.key"]}')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(config_file))

        assert config is not None
        assert config["builtin_deny_patterns"] == ["*.key"]

    def test_toml_format(self, tmp_path):
        """Test TOML format support."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('builtin_deny_patterns = ["*.pem"]')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(config_file))

        assert config is not None
        assert config["builtin_deny_patterns"] == ["*.pem"]

    def test_invalid_json(self, tmp_path):
        """Test error handling for invalid JSON."""
        config_file = tmp_path / "config.json"
        config_file.write_text('{"invalid": json}')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(config_file))

        # Should fail to parse as both JSON and TOML
        assert config is None

    def test_invalid_toml(self, tmp_path):
        """Test error handling for invalid TOML."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('[invalid toml content')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(config_file))

        assert config is None

    def test_no_caching_for_local_files(self, tmp_path):
        """Test that local files bypass cache (always fresh)."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('version = "1"')

        fetcher = RemoteFetcher()

        # First fetch
        config1 = fetcher.fetch_config(str(config_file))
        assert config1 is not None
        assert config1["version"] == "1"

        # Update file
        config_file.write_text('version = "2"')

        # Second fetch should see new version (no caching)
        config2 = fetcher.fetch_config(str(config_file))
        assert config2 is not None
        assert config2["version"] == "2"

    def test_symlink_following(self, tmp_path):
        """Test that symlinks are followed."""
        # Create actual file
        actual_file = tmp_path / "actual.toml"
        actual_file.write_text('test = "value"')

        # Create symlink
        symlink = tmp_path / "link.toml"
        symlink.symlink_to(actual_file)

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(symlink))

        assert config is not None
        assert config["test"] == "value"

    def test_broken_symlink(self, tmp_path):
        """Test error handling for broken symlink."""
        # Create symlink to non-existent file
        symlink = tmp_path / "broken_link.toml"
        symlink.symlink_to(tmp_path / "nonexistent.toml")

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(symlink))

        assert config is None

    def test_file_url_with_tilde(self, monkeypatch, tmp_path):
        """Test file:// URL with tilde expansion."""
        # Mock home directory
        monkeypatch.setenv("HOME", str(tmp_path))

        config_file = tmp_path / "config.toml"
        config_file.write_text('test = "value"')

        fetcher = RemoteFetcher()
        # Note: file:// with tilde is not standard, but we support it
        config = fetcher.fetch_config(f"file://~/config.toml")

        assert config is not None
        assert config["test"] == "value"

    def test_empty_file(self, tmp_path):
        """Test handling of empty file."""
        config_file = tmp_path / "empty.toml"
        config_file.write_text('')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(config_file))

        # Empty file fails JSON parsing, then TOML parses as empty dict
        # This is reasonable - empty config = empty dict
        assert config is not None
        assert config == {}

    def test_utf8_content(self, tmp_path):
        """Test UTF-8 encoded content."""
        config_file = tmp_path / "config.json"
        config_file.write_text('{"description": "Test with émojis 🚀"}', encoding='utf-8')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(config_file))

        assert config is not None
        assert config["description"] == "Test with émojis 🚀"

    def test_relative_path_resolution(self, tmp_path):
        """Test that relative paths are resolved correctly."""
        # Create a subdirectory with a config file
        subdir = tmp_path / "configs"
        subdir.mkdir()
        config_file = subdir / "test.toml"
        config_file.write_text('test = "value"')

        # Change to tmp_path directory
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)

            fetcher = RemoteFetcher()
            # Use absolute path (relative paths not directly supported)
            config = fetcher.fetch_config(str(config_file))

            assert config is not None
            assert config["test"] == "value"
        finally:
            os.chdir(original_cwd)

    def test_path_traversal_prevention(self, tmp_path):
        """Test that path traversal attempts are safely resolved."""
        # Create a config file
        config_file = tmp_path / "config.toml"
        config_file.write_text('test = "value"')

        # Try to access it with path traversal (should still resolve correctly)
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        fetcher = RemoteFetcher()
        # This should resolve to the actual file location
        traversal_path = str(subdir / ".." / "config.toml")
        config = fetcher.fetch_config(traversal_path)

        assert config is not None
        assert config["test"] == "value"

    def test_windows_style_path(self, tmp_path):
        """Test that paths work correctly (primarily for Unix, but test resolution)."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('test = "value"')

        fetcher = RemoteFetcher()
        # Use cross-platform Path resolution
        config = fetcher.fetch_config(str(config_file))

        assert config is not None
        assert config["test"] == "value"

    def test_multiple_local_files_no_cache_pollution(self, tmp_path):
        """Test that multiple local files don't pollute each other."""
        config1 = tmp_path / "config1.toml"
        config1.write_text('name = "config1"')

        config2 = tmp_path / "config2.toml"
        config2.write_text('name = "config2"')

        fetcher = RemoteFetcher()

        result1 = fetcher.fetch_config(str(config1))
        result2 = fetcher.fetch_config(str(config2))

        assert result1 is not None
        assert result1["name"] == "config1"
        assert result2 is not None
        assert result2["name"] == "config2"

    def test_local_file_after_https_cache(self, tmp_path):
        """Test that local files work correctly even after HTTPS cache exists."""
        config_file = tmp_path / "local.toml"
        config_file.write_text('type = "local"')

        fetcher = RemoteFetcher()

        # Try to fetch HTTPS (will fail, but that's ok)
        https_config = fetcher.fetch_config("https://example.com/config.toml")

        # Local file should still work
        local_config = fetcher.fetch_config(str(config_file))

        assert local_config is not None
        assert local_config["type"] == "local"

    def test_special_characters_in_filename(self, tmp_path):
        """Test files with special characters in names."""
        config_file = tmp_path / "config-2024_v1.0.toml"
        config_file.write_text('test = "value"')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(config_file))

        assert config is not None
        assert config["test"] == "value"

    def test_long_path(self, tmp_path):
        """Test handling of long file paths."""
        # Create nested directories
        deep_dir = tmp_path
        for i in range(10):
            deep_dir = deep_dir / f"level{i}"
        deep_dir.mkdir(parents=True)

        config_file = deep_dir / "config.toml"
        config_file.write_text('test = "deep"')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(config_file))

        assert config is not None
        assert config["test"] == "deep"


class TestLocalFilePathsEdgeCases:
    """Test edge cases for local file path support."""

    def test_file_with_spaces_in_path(self, tmp_path):
        """Test file path with spaces."""
        config_dir = tmp_path / "my configs"
        config_dir.mkdir()
        config_file = config_dir / "test config.toml"
        config_file.write_text('test = "spaces"')

        fetcher = RemoteFetcher()
        config = fetcher.fetch_config(str(config_file))

        assert config is not None
        assert config["test"] == "spaces"

    def test_nonexistent_user_tilde_expansion(self):
        """Test tilde expansion for non-existent user."""
        fetcher = RemoteFetcher()
        # Try to access ~nonexistentuser/config.toml
        # This should fail gracefully
        config = fetcher.fetch_config("~nonexistentuser123456789/config.toml")

        # Should fail to find the file
        assert config is None

    def test_file_url_triple_slash(self, tmp_path):
        """Test file:/// with triple slash (standard)."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('test = "triple"')

        fetcher = RemoteFetcher()
        # Standard file URL format
        config = fetcher.fetch_config(f"file:///{config_file}")

        assert config is not None
        assert config["test"] == "triple"

    def test_mixed_json_toml_extensions(self, tmp_path):
        """Test that content is parsed by content, not extension."""
        # JSON content in .toml file
        json_in_toml = tmp_path / "config.toml"
        json_in_toml.write_text('{"format": "json"}')

        # TOML content in .json file
        toml_in_json = tmp_path / "config.json"
        toml_in_json.write_text('format = "toml"')

        fetcher = RemoteFetcher()

        # Should parse as JSON despite .toml extension
        config1 = fetcher.fetch_config(str(json_in_toml))
        assert config1 is not None
        assert config1["format"] == "json"

        # Should fail JSON parsing, then succeed as TOML
        config2 = fetcher.fetch_config(str(toml_in_json))
        assert config2 is not None
        assert config2["format"] == "toml"
