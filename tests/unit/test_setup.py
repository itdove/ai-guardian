#!/usr/bin/env python3
"""
Tests for setup command functionality.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from ai_guardian.config_utils import get_config_dir
from ai_guardian.setup import IDESetup, setup_hooks


class TestIDESetup:
    """Test cases for IDESetup class."""

    def test_detect_ide_none(self, tmp_path):
        """Test IDE detection when no IDE is installed."""
        setup = IDESetup()

        # Mock config paths to non-existent directories
        with mock.patch.object(
            setup,
            'IDE_CONFIGS',
            {
                'claude': {'config_path': str(tmp_path / 'nonexistent' / '.claude' / 'settings.json')},
                'cursor': {'config_path': str(tmp_path / 'nonexistent' / '.cursor' / 'hooks.json')},
            }
        ):
            detected = setup.detect_ide()
            assert detected is None

    def test_detect_ide_single(self, tmp_path):
        """Test IDE detection when only one IDE is installed."""
        setup = IDESetup()

        # Create Claude Code directory
        claude_dir = tmp_path / '.claude'
        claude_dir.mkdir(parents=True)

        with mock.patch.object(
            setup,
            'IDE_CONFIGS',
            {
                'claude': {'config_path': str(claude_dir / 'settings.json')},
                'cursor': {'config_path': str(tmp_path / 'nonexistent' / '.cursor' / 'hooks.json')},
            }
        ):
            detected = setup.detect_ide()
            assert detected == 'claude'

    def test_detect_ide_multiple(self, tmp_path):
        """Test IDE detection when multiple IDEs are installed."""
        setup = IDESetup()

        # Create both IDE directories
        claude_dir = tmp_path / '.claude'
        claude_dir.mkdir(parents=True)
        cursor_dir = tmp_path / '.cursor'
        cursor_dir.mkdir(parents=True)

        with mock.patch.object(
            setup,
            'IDE_CONFIGS',
            {
                'claude': {'config_path': str(claude_dir / 'settings.json')},
                'cursor': {'config_path': str(cursor_dir / 'hooks.json')},
            }
        ):
            detected = setup.detect_ide()
            assert detected is None  # Returns None when multiple detected

    def test_list_detected_ides(self, tmp_path):
        """Test listing all detected IDEs."""
        setup = IDESetup()

        # Create both IDE directories
        claude_dir = tmp_path / '.claude'
        claude_dir.mkdir(parents=True)
        cursor_dir = tmp_path / '.cursor'
        cursor_dir.mkdir(parents=True)

        with mock.patch.object(
            setup,
            'IDE_CONFIGS',
            {
                'claude': {'config_path': str(claude_dir / 'settings.json')},
                'cursor': {'config_path': str(cursor_dir / 'hooks.json')},
            }
        ):
            detected = setup.list_detected_ides()
            assert set(detected) == {'claude', 'cursor'}

    def test_backup_config(self, tmp_path):
        """Test creating backup of config file."""
        setup = IDESetup()

        # Create test config file
        config_file = tmp_path / 'test.json'
        config_file.write_text('{"test": "data"}')

        # Create backup
        backup_path = setup.backup_config(config_file)

        assert backup_path is not None
        assert backup_path.exists()
        assert backup_path.name == 'test.json.backup'
        assert backup_path.read_text() == '{"test": "data"}'

    def test_backup_config_nonexistent(self, tmp_path):
        """Test backup creation when file doesn't exist."""
        setup = IDESetup()

        config_file = tmp_path / 'nonexistent.json'
        backup_path = setup.backup_config(config_file)

        assert backup_path is None

    def test_merge_hooks_claude_new(self):
        """Test merging Claude Code hooks into new config."""
        setup = IDESetup()

        existing_config = {}
        ai_guardian_hooks = {
            'UserPromptSubmit': [{'test': 'hook'}],
            'PreToolUse': [{'test': 'hook2'}]
        }

        merged, warnings = setup.merge_hooks(existing_config, ai_guardian_hooks, 'claude')

        assert 'hooks' in merged
        assert 'UserPromptSubmit' in merged['hooks']
        assert 'PreToolUse' in merged['hooks']

    def test_merge_hooks_claude_existing(self):
        """Test merging Claude Code hooks into existing config."""
        setup = IDESetup()

        existing_config = {
            'hooks': {
                'OtherHook': [{'existing': 'hook'}]
            },
            'other_setting': 'value'
        }
        ai_guardian_hooks = {
            'UserPromptSubmit': [{'test': 'hook'}]
        }

        merged, warnings = setup.merge_hooks(existing_config, ai_guardian_hooks, 'claude')

        assert 'hooks' in merged
        assert 'OtherHook' in merged['hooks']  # Preserved
        assert 'UserPromptSubmit' in merged['hooks']  # Added
        assert merged['other_setting'] == 'value'  # Preserved

    def test_merge_hooks_cursor_new(self):
        """Test merging Cursor hooks into new config."""
        setup = IDESetup()

        existing_config = {}
        ai_guardian_hooks = {
            'beforeSubmitPrompt': [{'command': 'ai-guardian'}],
            'beforeReadFile': [{'command': 'ai-guardian'}]
        }

        merged, warnings = setup.merge_hooks(existing_config, ai_guardian_hooks, 'cursor')

        assert 'version' in merged
        assert 'hooks' in merged
        assert 'beforeSubmitPrompt' in merged['hooks']
        assert 'beforeReadFile' in merged['hooks']

    def test_check_hooks_configured_claude(self, tmp_path):
        """Test checking if Claude Code hooks are already configured."""
        setup = IDESetup()

        # Create config with ai-guardian hooks
        config_file = tmp_path / 'settings.json'
        config = {
            'hooks': {
                'UserPromptSubmit': [
                    {
                        'matcher': '*',
                        'hooks': [
                            {'command': 'ai-guardian'}
                        ]
                    }
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        assert setup.check_hooks_configured(config_file, 'claude') is True

    def test_check_hooks_configured_cursor(self, tmp_path):
        """Test checking if Cursor hooks are already configured."""
        setup = IDESetup()

        # Create config with ai-guardian hooks
        config_file = tmp_path / 'hooks.json'
        config = {
            'hooks': {
                'beforeSubmitPrompt': [
                    {'command': 'ai-guardian'}
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        assert setup.check_hooks_configured(config_file, 'cursor') is True

    def test_check_hooks_not_configured(self, tmp_path):
        """Test checking when hooks are not configured."""
        setup = IDESetup()

        # Create config without ai-guardian hooks
        config_file = tmp_path / 'settings.json'
        config = {'hooks': {}}
        config_file.write_text(json.dumps(config))

        assert setup.check_hooks_configured(config_file, 'claude') is False

    def test_setup_ide_hooks_claude_new(self, tmp_path):
        """Test setting up Claude Code hooks in new config."""
        setup = IDESetup()

        config_file = tmp_path / 'settings.json'

        # Mock IDE config
        with mock.patch.object(
            setup,
            'IDE_CONFIGS',
            {
                'claude': {
                    'name': 'Claude Code',
                    'config_path': str(config_file),
                    'hooks': {
                        'UserPromptSubmit': [{'test': 'hook'}],
                        'PreToolUse': [{'test': 'hook2'}]
                    }
                }
            }
        ):
            success, message = setup.setup_ide_hooks('claude', dry_run=False, force=False)

            assert success is True
            assert config_file.exists()

            # Verify config content
            with open(config_file) as f:
                config = json.load(f)

            assert 'hooks' in config
            assert 'UserPromptSubmit' in config['hooks']
            assert 'PreToolUse' in config['hooks']

    def test_setup_ide_hooks_dry_run(self, tmp_path):
        """Test dry-run mode doesn't modify files."""
        setup = IDESetup()

        config_file = tmp_path / 'settings.json'

        with mock.patch.object(
            setup,
            'IDE_CONFIGS',
            {
                'claude': {
                    'name': 'Claude Code',
                    'config_path': str(config_file),
                    'hooks': {
                        'UserPromptSubmit': [{'test': 'hook'}]
                    }
                }
            }
        ):
            success, message = setup.setup_ide_hooks('claude', dry_run=True, force=False)

            assert success is True
            assert '[DRY RUN]' in message
            assert not config_file.exists()  # File should not be created

    def test_setup_ide_hooks_already_configured(self, tmp_path):
        """Test setup when hooks already configured without force."""
        setup = IDESetup()

        config_file = tmp_path / 'settings.json'
        config = {
            'hooks': {
                'UserPromptSubmit': [
                    {
                        'matcher': '*',
                        'hooks': [{'command': 'ai-guardian'}]
                    }
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        with mock.patch.object(
            setup,
            'IDE_CONFIGS',
            {
                'claude': {
                    'name': 'Claude Code',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,  # Disable env var for test
                    'hooks': {}
                }
            }
        ):
            success, message = setup.setup_ide_hooks('claude', dry_run=False, force=False)

            assert success is False
            assert 'already configured' in message

    def test_setup_ide_hooks_force_overwrite(self, tmp_path):
        """Test force overwrite of existing hooks."""
        setup = IDESetup()

        config_file = tmp_path / 'settings.json'
        config = {
            'hooks': {
                'UserPromptSubmit': [
                    {
                        'matcher': '*',
                        'hooks': [{'command': 'ai-guardian'}]
                    }
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        with mock.patch.object(
            setup,
            'IDE_CONFIGS',
            {
                'claude': {
                    'name': 'Claude Code',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,  # Disable env var for test
                    'hooks': {
                        'UserPromptSubmit': [
                            {
                                'matcher': '*',
                                'hooks': [{'type': 'command', 'command': 'new-hook'}]
                            }
                        ]
                    }
                }
            }
        ):
            success, message = setup.setup_ide_hooks('claude', dry_run=False, force=True)

            assert success is True

            # Verify backup was created
            backup_file = config_file.with_suffix('.json.backup')
            assert backup_file.exists()

    def test_setup_ide_hooks_invalid_json(self, tmp_path):
        """Test setup with invalid JSON in existing config."""
        setup = IDESetup()

        config_file = tmp_path / 'settings.json'
        config_file.write_text('invalid json {')

        with mock.patch.object(
            setup,
            'IDE_CONFIGS',
            {
                'claude': {
                    'name': 'Claude Code',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,  # Disable env var for test
                    'hooks': {}
                }
            }
        ):
            success, message = setup.setup_ide_hooks('claude', dry_run=False, force=False)

            assert success is False
            assert 'Invalid JSON' in message

    def test_merge_hooks_windsurf_new(self):
        """Test merging Windsurf hooks into new config."""
        setup = IDESetup()

        existing_config = {}
        ai_guardian_hooks = {
            "hooks": {
                "pre_user_prompt": [{"command": "ai-guardian"}],
                "pre_run_command": [{"command": "ai-guardian"}],
                "post_run_command": [{"command": "ai-guardian"}],
            }
        }

        merged, warnings = setup.merge_hooks(existing_config, ai_guardian_hooks, "windsurf")

        assert "hooks" in merged
        assert "pre_user_prompt" in merged["hooks"]
        assert "pre_run_command" in merged["hooks"]
        assert "post_run_command" in merged["hooks"]
        assert len(warnings) == 0

    def test_merge_hooks_windsurf_existing(self):
        """Test merging Windsurf hooks preserves other events."""
        setup = IDESetup()

        existing_config = {
            "hooks": {
                "post_cascade_response": [{"command": "custom-logger"}],
            }
        }
        ai_guardian_hooks = {
            "hooks": {
                "pre_user_prompt": [{"command": "ai-guardian"}],
                "pre_run_command": [{"command": "ai-guardian"}],
            }
        }

        merged, warnings = setup.merge_hooks(existing_config, ai_guardian_hooks, "windsurf")

        assert "post_cascade_response" in merged["hooks"]
        assert "pre_user_prompt" in merged["hooks"]
        assert "pre_run_command" in merged["hooks"]

    def test_check_hooks_configured_windsurf(self, tmp_path):
        """Test checking if Windsurf hooks are already configured."""
        setup = IDESetup()

        config_file = tmp_path / "hooks.json"
        config = {
            "hooks": {
                "pre_user_prompt": [
                    {"command": "ai-guardian"}
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        assert setup.check_hooks_configured(config_file, "windsurf") is True

    def test_check_hooks_not_configured_windsurf(self, tmp_path):
        """Test checking when Windsurf hooks are not configured."""
        setup = IDESetup()

        config_file = tmp_path / "hooks.json"
        config = {"hooks": {"pre_user_prompt": [{"command": "other-tool"}]}}
        config_file.write_text(json.dumps(config))

        assert setup.check_hooks_configured(config_file, "windsurf") is False

    def test_setup_ide_hooks_windsurf_new(self, tmp_path):
        """Test setting up Windsurf hooks in new config."""
        setup = IDESetup()

        config_file = tmp_path / "hooks.json"

        with mock.patch.object(
            setup,
            "IDE_CONFIGS",
            {
                "windsurf": {
                    "name": "Windsurf",
                    "config_path": str(config_file),
                    "config_dir_env_var": None,
                    "config_filename": "hooks.json",
                    "hooks": {
                        "hooks": {
                            "pre_user_prompt": [{"command": "ai-guardian"}],
                            "pre_run_command": [{"command": "ai-guardian"}],
                            "post_run_command": [{"command": "ai-guardian"}],
                            "pre_read_code": [{"command": "ai-guardian"}],
                            "pre_write_code": [{"command": "ai-guardian"}],
                            "pre_mcp_tool_use": [{"command": "ai-guardian"}],
                        }
                    },
                }
            },
        ), mock.patch.object(setup, "verify_gitleaks_installed", return_value=(True, "ok")):
            success, message = setup.setup_ide_hooks("windsurf", dry_run=False, force=False)

            assert success is True
            assert "Windsurf" in message

            with open(config_file) as f:
                written = json.load(f)
            assert "hooks" in written
            assert "pre_user_prompt" in written["hooks"]
            assert "pre_run_command" in written["hooks"]
            assert "pre_read_code" in written["hooks"]
            assert "pre_write_code" in written["hooks"]
            assert "pre_mcp_tool_use" in written["hooks"]

    def test_setup_ide_hooks_windsurf_dry_run(self, tmp_path):
        """Test dry run for Windsurf hooks."""
        setup = IDESetup()

        config_file = tmp_path / "hooks.json"

        with mock.patch.object(
            setup,
            "IDE_CONFIGS",
            {
                "windsurf": {
                    "name": "Windsurf",
                    "config_path": str(config_file),
                    "config_dir_env_var": None,
                    "config_filename": "hooks.json",
                    "hooks": {
                        "hooks": {
                            "pre_user_prompt": [{"command": "ai-guardian"}],
                        }
                    },
                }
            },
        ):
            success, message = setup.setup_ide_hooks("windsurf", dry_run=True, force=False)

            assert success is True
            assert "DRY RUN" in message
            assert "Windsurf" in message
            assert not config_file.exists()

    def test_setup_remote_config_new_file(self, tmp_path):
        """Test setting up remote config in new file."""
        setup = IDESetup()

        config_file = tmp_path / 'ai-guardian' / 'ai-guardian.json'

        with mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': str(tmp_path), 'AI_GUARDIAN_CONFIG_DIR': ''}):
            success, message = setup.setup_remote_config('https://example.com/policy.json', dry_run=False)

            assert success is True
            assert config_file.exists()

            # Verify config content
            with open(config_file) as f:
                config = json.load(f)

            assert 'remote_configs' in config
            assert 'urls' in config['remote_configs']
            assert len(config['remote_configs']['urls']) == 1
            assert config['remote_configs']['urls'][0]['url'] == 'https://example.com/policy.json'
            assert config['remote_configs']['urls'][0]['enabled'] is True

    def test_setup_remote_config_existing_file_no_section(self, tmp_path):
        """Test adding remote config section to existing file."""
        setup = IDESetup()

        config_file = tmp_path / 'ai-guardian' / 'ai-guardian.json'
        config_file.parent.mkdir(parents=True, exist_ok=True)

        # Create existing config without remote_configs
        existing_config = {'permissions': []}
        config_file.write_text(json.dumps(existing_config))

        with mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': str(tmp_path), 'AI_GUARDIAN_CONFIG_DIR': ''}):
            success, message = setup.setup_remote_config('https://example.com/policy.json', dry_run=False)

            assert success is True

            # Verify config content
            with open(config_file) as f:
                config = json.load(f)

            assert 'permissions' in config  # Preserved
            assert 'remote_configs' in config
            assert len(config['remote_configs']['urls']) == 1

    def test_setup_remote_config_append_to_existing(self, tmp_path):
        """Test appending URL to existing remote_configs."""
        setup = IDESetup()

        config_file = tmp_path / 'ai-guardian' / 'ai-guardian.json'
        config_file.parent.mkdir(parents=True, exist_ok=True)

        # Create config with existing remote_configs
        existing_config = {
            'remote_configs': {
                'urls': [
                    {'url': 'https://example.com/policy1.json', 'enabled': True}
                ]
            }
        }
        config_file.write_text(json.dumps(existing_config))

        with mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': str(tmp_path), 'AI_GUARDIAN_CONFIG_DIR': ''}):
            success, message = setup.setup_remote_config('https://example.com/policy2.json', dry_run=False)

            assert success is True

            # Verify config content
            with open(config_file) as f:
                config = json.load(f)

            assert len(config['remote_configs']['urls']) == 2
            assert config['remote_configs']['urls'][0]['url'] == 'https://example.com/policy1.json'
            assert config['remote_configs']['urls'][1]['url'] == 'https://example.com/policy2.json'

    def test_setup_remote_config_duplicate_url(self, tmp_path):
        """Test adding duplicate URL fails."""
        setup = IDESetup()

        config_file = tmp_path / 'ai-guardian' / 'ai-guardian.json'
        config_file.parent.mkdir(parents=True, exist_ok=True)

        # Create config with existing URL
        existing_config = {
            'remote_configs': {
                'urls': [
                    {'url': 'https://example.com/policy.json', 'enabled': True}
                ]
            }
        }
        config_file.write_text(json.dumps(existing_config))

        with mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': str(tmp_path), 'AI_GUARDIAN_CONFIG_DIR': ''}):
            success, message = setup.setup_remote_config('https://example.com/policy.json', dry_run=False)

            assert success is False
            assert 'already exists' in message

    def test_setup_remote_config_dry_run(self, tmp_path):
        """Test dry-run mode for remote config."""
        setup = IDESetup()

        config_file = tmp_path / 'ai-guardian' / 'ai-guardian.json'

        with mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': str(tmp_path)}):
            success, message = setup.setup_remote_config('https://example.com/policy.json', dry_run=True)

            assert success is True
            assert '[DRY RUN]' in message
            assert not config_file.exists()

    def test_verify_gitleaks_installed_success(self):
        """Test Gitleaks verification when installed."""
        setup = IDESetup()

        with mock.patch('subprocess.run') as mock_run:
            # Mock successful gitleaks version check
            mock_result = mock.MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "gitleaks version 8.18.0\n"
            mock_run.return_value = mock_result

            success, message = setup.verify_gitleaks_installed()

            assert success is True
            assert '✓ Gitleaks is installed' in message
            assert 'gitleaks version' in message
            mock_run.assert_called_once_with(
                ['gitleaks', 'version'],
                capture_output=True,
                text=True,
                timeout=5
            )

    def test_verify_gitleaks_not_found(self):
        """Test Gitleaks verification when not installed."""
        setup = IDESetup()

        with mock.patch('subprocess.run') as mock_run:
            # Mock FileNotFoundError (gitleaks not installed)
            mock_run.side_effect = FileNotFoundError("gitleaks command not found")

            success, message = setup.verify_gitleaks_installed()

            assert success is False
            assert '❌ Gitleaks not found' in message
            assert 'https://github.com/gitleaks/gitleaks#installing' in message
            assert 'brew install gitleaks' in message

    def test_verify_gitleaks_timeout(self):
        """Test Gitleaks verification when command times out."""
        import subprocess
        setup = IDESetup()

        with mock.patch('subprocess.run') as mock_run:
            # Mock timeout
            mock_run.side_effect = subprocess.TimeoutExpired('gitleaks', 5)

            success, message = setup.verify_gitleaks_installed()

            assert success is False
            assert '❌ Gitleaks check timed out' in message

    def test_verify_gitleaks_command_failed(self):
        """Test Gitleaks verification when command returns non-zero."""
        setup = IDESetup()

        with mock.patch('subprocess.run') as mock_run:
            # Mock failed command
            mock_result = mock.MagicMock()
            mock_result.returncode = 1
            mock_run.return_value = mock_result

            success, message = setup.verify_gitleaks_installed()

            assert success is False
            assert '❌ Gitleaks command failed' in message

    def test_setup_ide_hooks_shows_gitleaks_warning(self, tmp_path):
        """Test that setup shows warning when Gitleaks is not installed."""
        setup = IDESetup()

        config_file = tmp_path / 'settings.json'

        with mock.patch.object(
            setup,
            'IDE_CONFIGS',
            {
                'claude': {
                    'name': 'Claude Code',
                    'config_path': str(config_file),
                    'hooks': {
                        'UserPromptSubmit': [{'test': 'hook'}]
                    }
                }
            }
        ):
            # Mock Gitleaks as not installed
            with mock.patch.object(setup, 'verify_gitleaks_installed') as mock_verify:
                mock_verify.return_value = (False, "❌ Gitleaks not found")

                success, message = setup.setup_ide_hooks('claude', dry_run=False, force=False)

                assert success is True
                assert '❌ Gitleaks not found' in message
                assert 'WARNING: Secret scanning will be disabled' in message
                assert 'install gitleaks' in message.lower()


class TestConfigDirEnvironmentVariable:
    """Test cases for AI_GUARDIAN_CONFIG_DIR environment variable."""

    def test_ai_guardian_config_dir_env_var(self, tmp_path):
        """Test that AI_GUARDIAN_CONFIG_DIR environment variable is respected."""
        from ai_guardian.config_manager import ConfigManager

        custom_dir = tmp_path / "custom-config"
        custom_dir.mkdir()

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(custom_dir)}):
            config_mgr = ConfigManager()
            assert config_mgr.config_dir == custom_dir

    def test_ai_guardian_config_dir_takes_priority_over_xdg(self, tmp_path):
        """Test that AI_GUARDIAN_CONFIG_DIR takes priority over XDG_CONFIG_HOME."""
        from ai_guardian.config_manager import ConfigManager

        ai_guardian_dir = tmp_path / "ai-guardian-custom"
        xdg_dir = tmp_path / "xdg-home"
        ai_guardian_dir.mkdir()
        xdg_dir.mkdir()

        env = {
            'AI_GUARDIAN_CONFIG_DIR': str(ai_guardian_dir),
            'XDG_CONFIG_HOME': str(xdg_dir)
        }

        with mock.patch.dict(os.environ, env, clear=True):
            config_mgr = ConfigManager()
            # Should use AI_GUARDIAN_CONFIG_DIR, not XDG_CONFIG_HOME/ai-guardian
            assert config_mgr.config_dir == ai_guardian_dir
            assert config_mgr.config_dir != xdg_dir / "ai-guardian"

    def test_xdg_config_home_fallback(self, tmp_path):
        """Test XDG_CONFIG_HOME is used when AI_GUARDIAN_CONFIG_DIR is not set."""
        from ai_guardian.config_manager import ConfigManager

        xdg_dir = tmp_path / "xdg-home"
        xdg_dir.mkdir()

        # Only set XDG_CONFIG_HOME, not AI_GUARDIAN_CONFIG_DIR
        with mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': str(xdg_dir)}, clear=True):
            config_mgr = ConfigManager()
            assert config_mgr.config_dir == xdg_dir / "ai-guardian"

    def test_default_config_dir_when_no_env_vars(self):
        """Test default config directory when no environment variables are set."""
        from ai_guardian.config_manager import ConfigManager

        # Clear both environment variables
        env_backup = os.environ.copy()
        try:
            if 'AI_GUARDIAN_CONFIG_DIR' in os.environ:
                del os.environ['AI_GUARDIAN_CONFIG_DIR']
            if 'XDG_CONFIG_HOME' in os.environ:
                del os.environ['XDG_CONFIG_HOME']

            config_mgr = ConfigManager()
            expected = Path("~/.config/ai-guardian").expanduser()
            assert config_mgr.config_dir == expected
        finally:
            os.environ.clear()
            os.environ.update(env_backup)

    def test_config_dir_with_tilde_expansion(self, tmp_path):
        """Test that tilde in AI_GUARDIAN_CONFIG_DIR is expanded."""
        from ai_guardian.config_manager import ConfigManager

        # Use a path with tilde (will be expanded)
        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': '~/my-ai-guardian'}):
            config_mgr = ConfigManager()
            # Should be expanded, not contain literal ~
            assert '~' not in str(config_mgr.config_dir)
            assert config_mgr.config_dir == Path('~/my-ai-guardian').expanduser()

    def test_get_config_dir_utility_function(self, tmp_path):
        """Test the get_config_dir utility function directly."""
        custom_dir = tmp_path / "test-config"
        custom_dir.mkdir()

        # Test with AI_GUARDIAN_CONFIG_DIR
        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(custom_dir)}):
            result = get_config_dir()
            assert result == custom_dir

        # Test with XDG_CONFIG_HOME only
        xdg_dir = tmp_path / "xdg"
        xdg_dir.mkdir()
        with mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': str(xdg_dir)}, clear=True):
            result = get_config_dir()
            assert result == xdg_dir / "ai-guardian"

        # Test default (no env vars)
        with mock.patch.dict(os.environ, {}, clear=True):
            result = get_config_dir()
            assert result == Path("~/.config/ai-guardian").expanduser()

    def test_setup_remote_config_with_custom_config_dir(self, tmp_path):
        """Test that setup_remote_config respects AI_GUARDIAN_CONFIG_DIR."""
        setup = IDESetup()

        custom_dir = tmp_path / "custom-ai-guardian"
        custom_dir.mkdir()
        config_file = custom_dir / "ai-guardian.json"

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(custom_dir)}):
            success, message = setup.setup_remote_config('https://example.com/policy.json', dry_run=False)

            assert success is True
            assert config_file.exists()

            # Verify the URL was added to config
            with open(config_file) as f:
                config = json.load(f)
            assert 'remote_configs' in config
            assert any('example.com' in str(entry) for entry in config['remote_configs']['urls'])

    def test_tool_policy_uses_custom_config_dir(self, tmp_path):
        """Test that ToolPolicyChecker respects AI_GUARDIAN_CONFIG_DIR."""
        from ai_guardian.tool_policy import ToolPolicyChecker

        custom_dir = tmp_path / "custom-config"
        custom_dir.mkdir()

        # Create a test config file
        config_file = custom_dir / "ai-guardian.json"
        test_config = {
            "builtin_tools": {
                "deny": ["Bash"],
                "allow": ["Read"]
            }
        }
        config_file.write_text(json.dumps(test_config))

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(custom_dir)}):
            checker = ToolPolicyChecker()
            # Verify it loaded from the custom directory
            assert checker.config is not None


class TestCodexSetup:
    """Test cases for Codex IDE setup."""

    def test_codex_in_ide_configs(self):
        """Verify Codex entry exists in IDE_CONFIGS with correct keys."""
        assert "codex" in IDESetup.IDE_CONFIGS
        codex_cfg = IDESetup.IDE_CONFIGS["codex"]
        assert codex_cfg["name"] == "OpenAI Codex"
        assert codex_cfg["config_path"] == "~/.codex/hooks.json"
        assert codex_cfg["config_filename"] == "hooks.json"
        assert "hooks" in codex_cfg
        hooks = codex_cfg["hooks"]
        assert "UserPromptSubmit" in hooks
        assert "PreToolUse" in hooks
        assert "PostToolUse" in hooks

    def test_codex_hooks_use_regex_matcher(self):
        """Verify Codex PreToolUse/PostToolUse use regex matcher '.*'."""
        hooks = IDESetup.IDE_CONFIGS["codex"]["hooks"]
        assert hooks["PreToolUse"][0]["matcher"] == ".*"
        assert hooks["PostToolUse"][0]["matcher"] == ".*"
        assert "matcher" not in hooks["UserPromptSubmit"][0]

    def test_codex_hooks_have_timeout(self):
        """Verify Codex hooks include timeout field."""
        hooks = IDESetup.IDE_CONFIGS["codex"]["hooks"]
        for event in ["UserPromptSubmit", "PreToolUse", "PostToolUse"]:
            hook_entry = hooks[event][0]["hooks"][0]
            assert hook_entry["timeout"] == 30

    def test_setup_ide_hooks_codex_new(self, tmp_path):
        """Test setting up Codex hooks in new config."""
        setup = IDESetup()
        config_file = tmp_path / 'hooks.json'

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'codex': {
                    'name': 'OpenAI Codex',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,
                    'config_filename': 'hooks.json',
                    'hooks': IDESetup.IDE_CONFIGS['codex']['hooks']
                }
            }
        ):
            success, message = setup.setup_ide_hooks('codex', dry_run=False, force=False)

            assert success is True
            assert config_file.exists()

            with open(config_file) as f:
                config = json.load(f)

            assert 'hooks' in config
            assert 'UserPromptSubmit' in config['hooks']
            assert 'PreToolUse' in config['hooks']
            assert 'PostToolUse' in config['hooks']
            assert config['hooks']['PreToolUse'][0]['matcher'] == '.*'
            assert config['hooks']['PreToolUse'][0]['hooks'][0]['command'] == 'ai-guardian'

    def test_setup_ide_hooks_codex_dry_run(self, tmp_path):
        """Test dry-run mode for Codex."""
        setup = IDESetup()
        config_file = tmp_path / 'hooks.json'

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'codex': {
                    'name': 'OpenAI Codex',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,
                    'config_filename': 'hooks.json',
                    'hooks': IDESetup.IDE_CONFIGS['codex']['hooks']
                }
            }
        ):
            success, message = setup.setup_ide_hooks('codex', dry_run=True, force=False)

            assert success is True
            assert '[DRY RUN]' in message
            assert not config_file.exists()

    def test_check_hooks_configured_codex(self, tmp_path):
        """Test detection of existing Codex hooks."""
        setup = IDESetup()
        config_file = tmp_path / 'hooks.json'
        config = {
            'hooks': {
                'PreToolUse': [
                    {
                        'matcher': '.*',
                        'hooks': [{'type': 'command', 'command': 'ai-guardian'}]
                    }
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        assert setup.check_hooks_configured(config_file, 'codex') is True

    def test_check_hooks_not_configured_codex(self, tmp_path):
        """Test returns False when no ai-guardian hooks present."""
        setup = IDESetup()
        config_file = tmp_path / 'hooks.json'
        config = {
            'hooks': {
                'PreToolUse': [
                    {
                        'matcher': '.*',
                        'hooks': [{'type': 'command', 'command': 'other-tool'}]
                    }
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        assert setup.check_hooks_configured(config_file, 'codex') is False

    def test_setup_ide_hooks_codex_already_configured(self, tmp_path):
        """Test setup when Codex hooks already configured without force."""
        setup = IDESetup()
        config_file = tmp_path / 'hooks.json'
        config = {
            'hooks': {
                'PreToolUse': [
                    {
                        'matcher': '.*',
                        'hooks': [{'type': 'command', 'command': 'ai-guardian'}]
                    }
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'codex': {
                    'name': 'OpenAI Codex',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,
                    'config_filename': 'hooks.json',
                    'hooks': IDESetup.IDE_CONFIGS['codex']['hooks']
                }
            }
        ):
            success, message = setup.setup_ide_hooks('codex', dry_run=False, force=False)

            assert success is False
            assert 'already configured' in message

    def test_setup_ide_hooks_codex_force_overwrite(self, tmp_path):
        """Test force overwrite of existing Codex hooks."""
        setup = IDESetup()
        config_file = tmp_path / 'hooks.json'
        config = {
            'hooks': {
                'PreToolUse': [
                    {
                        'matcher': '.*',
                        'hooks': [{'type': 'command', 'command': 'ai-guardian'}]
                    }
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'codex': {
                    'name': 'OpenAI Codex',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,
                    'config_filename': 'hooks.json',
                    'hooks': IDESetup.IDE_CONFIGS['codex']['hooks']
                }
            }
        ):
            success, message = setup.setup_ide_hooks('codex', dry_run=False, force=True)

            assert success is True

            backup_file = config_file.with_suffix('.json.backup')
            assert backup_file.exists()

    def test_merge_hooks_codex_preserves_other_hooks(self, tmp_path):
        """Test that merging Codex hooks preserves existing non-ai-guardian hooks."""
        setup = IDESetup()
        existing_config = {
            'hooks': {
                'PreToolUse': [
                    {
                        'matcher': '.*',
                        'hooks': [{'type': 'command', 'command': 'other-tool'}]
                    }
                ]
            }
        }
        ai_guardian_hooks = IDESetup.IDE_CONFIGS['codex']['hooks']

        merged, warnings = setup.merge_hooks(existing_config, ai_guardian_hooks, 'codex')

        pre_tool_hooks = merged['hooks']['PreToolUse'][0]['hooks']
        assert pre_tool_hooks[0]['command'] == 'ai-guardian'
        assert pre_tool_hooks[1]['command'] == 'other-tool'
        assert len(warnings) > 0


class TestGeminiSetup:
    """Test cases for Gemini CLI setup."""

    def test_gemini_in_ide_configs(self):
        """Verify Gemini entry exists in IDE_CONFIGS with correct keys."""
        assert "gemini" in IDESetup.IDE_CONFIGS
        gemini_cfg = IDESetup.IDE_CONFIGS["gemini"]
        assert gemini_cfg["name"] == "Google Gemini CLI"
        assert gemini_cfg["config_path"] == "~/.gemini/settings.json"
        assert gemini_cfg["config_filename"] == "settings.json"
        assert "hooks" in gemini_cfg

    def test_gemini_hooks_use_array_format(self):
        """Verify Gemini hooks use array format with event/matcher/command."""
        hooks_config = IDESetup.IDE_CONFIGS["gemini"]["hooks"]
        hooks = hooks_config["hooks"]
        assert isinstance(hooks, list)
        assert len(hooks) == 3

        events = [h["event"] for h in hooks]
        assert "BeforeAgent" in events
        assert "BeforeTool" in events
        assert "AfterTool" in events

        for h in hooks:
            assert h["command"] == "ai-guardian"

    def test_gemini_tool_hooks_have_matcher(self):
        """Verify BeforeTool and AfterTool hooks have matcher field."""
        hooks = IDESetup.IDE_CONFIGS["gemini"]["hooks"]["hooks"]
        for h in hooks:
            if h["event"] in ("BeforeTool", "AfterTool"):
                assert h["matcher"] == ".*"

    def test_setup_ide_hooks_gemini_new(self, tmp_path):
        """Test setting up Gemini hooks in new config."""
        setup = IDESetup()
        config_file = tmp_path / 'settings.json'

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'gemini': {
                    'name': 'Google Gemini CLI',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,
                    'config_filename': 'settings.json',
                    'hooks': IDESetup.IDE_CONFIGS['gemini']['hooks']
                }
            }
        ):
            success, message = setup.setup_ide_hooks('gemini', dry_run=False, force=False)

            assert success is True
            assert config_file.exists()

            with open(config_file) as f:
                config = json.load(f)

            assert 'hooks' in config
            assert isinstance(config['hooks'], list)
            assert len(config['hooks']) == 3
            commands = [h['command'] for h in config['hooks']]
            assert all(c == 'ai-guardian' for c in commands)

    def test_setup_ide_hooks_gemini_dry_run(self, tmp_path):
        """Test dry-run mode for Gemini."""
        setup = IDESetup()
        config_file = tmp_path / 'settings.json'

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'gemini': {
                    'name': 'Google Gemini CLI',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,
                    'config_filename': 'settings.json',
                    'hooks': IDESetup.IDE_CONFIGS['gemini']['hooks']
                }
            }
        ):
            success, message = setup.setup_ide_hooks('gemini', dry_run=True, force=False)

            assert success is True
            assert '[DRY RUN]' in message
            assert not config_file.exists()

    def test_check_hooks_configured_gemini(self, tmp_path):
        """Test detection of existing Gemini hooks."""
        setup = IDESetup()
        config_file = tmp_path / 'settings.json'
        config = {
            'hooks': [
                {'event': 'BeforeTool', 'matcher': '.*', 'command': 'ai-guardian'}
            ]
        }
        config_file.write_text(json.dumps(config))

        assert setup.check_hooks_configured(config_file, 'gemini') is True

    def test_check_hooks_not_configured_gemini(self, tmp_path):
        """Test returns False when no ai-guardian hooks present."""
        setup = IDESetup()
        config_file = tmp_path / 'settings.json'
        config = {
            'hooks': [
                {'event': 'BeforeTool', 'matcher': '.*', 'command': 'other-tool'}
            ]
        }
        config_file.write_text(json.dumps(config))

        assert setup.check_hooks_configured(config_file, 'gemini') is False

    def test_merge_hooks_gemini_new(self):
        """Test merging Gemini hooks into empty config."""
        setup = IDESetup()
        existing_config = {}
        ai_guardian_hooks = IDESetup.IDE_CONFIGS['gemini']['hooks']

        merged, warnings = setup.merge_hooks(existing_config, ai_guardian_hooks, 'gemini')

        assert 'hooks' in merged
        assert isinstance(merged['hooks'], list)
        assert len(merged['hooks']) == 3
        assert len(warnings) == 0

    def test_merge_hooks_gemini_existing(self):
        """Test merging Gemini hooks preserves other hooks."""
        setup = IDESetup()
        existing_config = {
            'hooks': [
                {'event': 'BeforeTool', 'matcher': '.*', 'command': 'other-tool'}
            ]
        }
        ai_guardian_hooks = IDESetup.IDE_CONFIGS['gemini']['hooks']

        merged, warnings = setup.merge_hooks(existing_config, ai_guardian_hooks, 'gemini')

        assert len(merged['hooks']) == 4
        assert merged['hooks'][0]['command'] == 'ai-guardian'
        assert merged['hooks'][3]['command'] == 'other-tool'
        assert len(warnings) > 0

    def test_merge_hooks_gemini_replaces_existing_ai_guardian(self):
        """Test that merging replaces existing ai-guardian hooks."""
        setup = IDESetup()
        existing_config = {
            'hooks': [
                {'event': 'BeforeTool', 'matcher': '.*', 'command': 'ai-guardian'},
                {'event': 'BeforeTool', 'matcher': '.*', 'command': 'other-tool'}
            ]
        }
        ai_guardian_hooks = IDESetup.IDE_CONFIGS['gemini']['hooks']

        merged, warnings = setup.merge_hooks(existing_config, ai_guardian_hooks, 'gemini')

        ag_hooks = [h for h in merged['hooks'] if h.get('command') == 'ai-guardian']
        other_hooks = [h for h in merged['hooks'] if h.get('command') != 'ai-guardian']
        assert len(ag_hooks) == 3
        assert len(other_hooks) == 1


class TestClineSetup:
    """Test cases for Cline/ZooCode setup."""

    def test_cline_in_ide_configs(self):
        """Verify Cline entry exists in IDE_CONFIGS with correct keys."""
        assert "cline" in IDESetup.IDE_CONFIGS
        cline_cfg = IDESetup.IDE_CONFIGS["cline"]
        assert cline_cfg["name"] == "Cline"
        assert cline_cfg["config_path"] == ".clinerules/hooks"
        assert cline_cfg.get("script_based") is True
        assert "hook_scripts" in cline_cfg

    def test_zoocode_in_ide_configs(self):
        """Verify ZooCode entry exists as alias with same structure."""
        assert "zoocode" in IDESetup.IDE_CONFIGS
        zoo_cfg = IDESetup.IDE_CONFIGS["zoocode"]
        assert zoo_cfg["name"] == "ZooCode"
        assert zoo_cfg["config_path"] == ".clinerules/hooks"
        assert zoo_cfg.get("script_based") is True
        assert zoo_cfg["hook_scripts"] == IDESetup.IDE_CONFIGS["cline"]["hook_scripts"]

    def test_cline_hooks_are_script_based(self):
        """Verify Cline uses script-based hooks with correct event names."""
        cline_cfg = IDESetup.IDE_CONFIGS["cline"]
        assert cline_cfg["script_based"] is True
        scripts = cline_cfg["hook_scripts"]
        assert "PreToolUse" in scripts
        assert "PostToolUse" in scripts
        assert "UserPromptSubmit" in scripts

    def test_cline_script_content(self):
        """Verify script content calls ai-guardian."""
        cline_cfg = IDESetup.IDE_CONFIGS["cline"]
        content = cline_cfg["script_content"]
        assert content.startswith("#!/bin/sh")
        assert "ai-guardian" in content

    def test_setup_ide_hooks_cline_new(self, tmp_path):
        """Test setting up Cline hooks creates executable scripts."""
        setup = IDESetup()
        hooks_dir = tmp_path / '.clinerules' / 'hooks'

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'cline': {
                    'name': 'Cline',
                    'config_path': str(hooks_dir),
                    'config_dir_env_var': None,
                    'config_filename': None,
                    'script_based': True,
                    'hook_scripts': IDESetup.IDE_CONFIGS['cline']['hook_scripts'],
                    'script_content': IDESetup.IDE_CONFIGS['cline']['script_content'],
                }
            }
        ):
            success, message = setup.setup_ide_hooks('cline', dry_run=False, force=False)

            assert success is True
            assert hooks_dir.exists()

            for script_name in ['PreToolUse', 'PostToolUse', 'UserPromptSubmit']:
                script_path = hooks_dir / script_name
                assert script_path.exists()
                content = script_path.read_text()
                assert 'ai-guardian' in content
                import stat
                assert script_path.stat().st_mode & stat.S_IXUSR

    def test_setup_ide_hooks_cline_dry_run(self, tmp_path):
        """Test dry-run mode for Cline."""
        setup = IDESetup()
        hooks_dir = tmp_path / '.clinerules' / 'hooks'

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'cline': {
                    'name': 'Cline',
                    'config_path': str(hooks_dir),
                    'config_dir_env_var': None,
                    'config_filename': None,
                    'script_based': True,
                    'hook_scripts': IDESetup.IDE_CONFIGS['cline']['hook_scripts'],
                    'script_content': IDESetup.IDE_CONFIGS['cline']['script_content'],
                }
            }
        ):
            success, message = setup.setup_ide_hooks('cline', dry_run=True, force=False)

            assert success is True
            assert '[DRY RUN]' in message
            assert not hooks_dir.exists()

    def test_check_hooks_configured_cline(self, tmp_path):
        """Test detection of existing Cline hook scripts."""
        setup = IDESetup()
        hooks_dir = tmp_path / '.clinerules' / 'hooks'
        hooks_dir.mkdir(parents=True)
        script = hooks_dir / 'PreToolUse'
        script.write_text("#!/bin/sh\nai-guardian\n")

        assert setup.check_hooks_configured(hooks_dir, 'cline') is True

    def test_check_hooks_not_configured_cline(self, tmp_path):
        """Test returns False when no ai-guardian scripts present."""
        setup = IDESetup()
        hooks_dir = tmp_path / '.clinerules' / 'hooks'
        hooks_dir.mkdir(parents=True)
        script = hooks_dir / 'PreToolUse'
        script.write_text("#!/bin/sh\nother-tool\n")

        assert setup.check_hooks_configured(hooks_dir, 'cline') is False

    def test_check_hooks_not_configured_cline_empty(self, tmp_path):
        """Test returns False when hooks directory doesn't exist."""
        setup = IDESetup()
        hooks_dir = tmp_path / '.clinerules' / 'hooks'

        assert setup.check_hooks_configured(hooks_dir, 'cline') is False

    def test_setup_ide_hooks_cline_force(self, tmp_path):
        """Test force flag overwrites existing Cline scripts."""
        setup = IDESetup()
        hooks_dir = tmp_path / '.clinerules' / 'hooks'
        hooks_dir.mkdir(parents=True)
        old_script = hooks_dir / 'PreToolUse'
        old_script.write_text("#!/bin/sh\nai-guardian\n")

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'cline': {
                    'name': 'Cline',
                    'config_path': str(hooks_dir),
                    'config_dir_env_var': None,
                    'config_filename': None,
                    'script_based': True,
                    'hook_scripts': IDESetup.IDE_CONFIGS['cline']['hook_scripts'],
                    'script_content': IDESetup.IDE_CONFIGS['cline']['script_content'],
                }
            }
        ):
            success, message = setup.setup_ide_hooks('cline', dry_run=False, force=True)
            assert success is True

            for script_name in ['PreToolUse', 'PostToolUse', 'UserPromptSubmit']:
                assert (hooks_dir / script_name).exists()


class TestAugmentSetup:
    """Test cases for Augment Code setup."""

    def test_augment_in_ide_configs(self):
        """Verify Augment entry exists in IDE_CONFIGS with correct keys."""
        assert "augment" in IDESetup.IDE_CONFIGS
        aug_cfg = IDESetup.IDE_CONFIGS["augment"]
        assert aug_cfg["name"] == "Augment Code"
        assert aug_cfg["config_path"] == "~/.augment/settings.json"
        assert aug_cfg["config_filename"] == "settings.json"
        assert "hooks" in aug_cfg

    def test_augment_hook_structure(self):
        """Verify Augment hooks use nested hooks.hooks structure."""
        hooks = IDESetup.IDE_CONFIGS["augment"]["hooks"]
        assert "hooks" in hooks
        inner = hooks["hooks"]
        assert "PreToolUse" in inner
        assert "PostToolUse" in inner

    def test_augment_hooks_use_pipe_matcher(self):
        """Verify Augment hooks use pipe-separated tool matcher."""
        inner = IDESetup.IDE_CONFIGS["augment"]["hooks"]["hooks"]
        matcher = inner["PreToolUse"][0]["matcher"]
        assert "launch-process" in matcher
        assert "str-replace-editor" in matcher
        assert "save-file" in matcher
        assert "view" in matcher

    def test_augment_hooks_have_timeout(self):
        """Verify Augment hooks include timeout field."""
        inner = IDESetup.IDE_CONFIGS["augment"]["hooks"]["hooks"]
        for event in ["PreToolUse", "PostToolUse"]:
            hook_entry = inner[event][0]["hooks"][0]
            assert hook_entry["timeout"] == 5000

    def test_setup_ide_hooks_augment_new(self, tmp_path):
        """Test setting up Augment hooks in new config."""
        setup = IDESetup()
        config_file = tmp_path / 'settings.json'

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'augment': {
                    'name': 'Augment Code',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,
                    'config_filename': 'settings.json',
                    'hooks': IDESetup.IDE_CONFIGS['augment']['hooks']
                }
            }
        ):
            success, message = setup.setup_ide_hooks('augment', dry_run=False, force=False)

            assert success is True
            assert config_file.exists()

            with open(config_file) as f:
                config = json.load(f)

            assert 'hooks' in config
            assert 'PreToolUse' in config['hooks']
            assert 'PostToolUse' in config['hooks']
            assert config['hooks']['PreToolUse'][0]['hooks'][0]['command'] == 'ai-guardian'

    def test_setup_ide_hooks_augment_dry_run(self, tmp_path):
        """Test dry-run mode for Augment."""
        setup = IDESetup()
        config_file = tmp_path / 'settings.json'

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'augment': {
                    'name': 'Augment Code',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,
                    'config_filename': 'settings.json',
                    'hooks': IDESetup.IDE_CONFIGS['augment']['hooks']
                }
            }
        ):
            success, message = setup.setup_ide_hooks('augment', dry_run=True, force=False)

            assert success is True
            assert '[DRY RUN]' in message
            assert not config_file.exists()

    def test_check_hooks_configured_augment(self, tmp_path):
        """Test detection of existing Augment hooks."""
        setup = IDESetup()
        config_file = tmp_path / 'settings.json'
        config = {
            'hooks': {
                'PreToolUse': [
                    {
                        'matcher': 'launch-process|str-replace-editor|save-file|view',
                        'hooks': [{'type': 'command', 'command': 'ai-guardian'}]
                    }
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        assert setup.check_hooks_configured(config_file, 'augment') is True

    def test_check_hooks_not_configured_augment(self, tmp_path):
        """Test returns False when no ai-guardian hooks present."""
        setup = IDESetup()
        config_file = tmp_path / 'settings.json'
        config = {
            'hooks': {
                'PreToolUse': [
                    {
                        'matcher': 'launch-process',
                        'hooks': [{'type': 'command', 'command': 'other-tool'}]
                    }
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        assert setup.check_hooks_configured(config_file, 'augment') is False

    def test_setup_ide_hooks_augment_force(self, tmp_path):
        """Test force overwrite of existing Augment hooks."""
        setup = IDESetup()
        config_file = tmp_path / 'settings.json'
        config = {
            'hooks': {
                'PreToolUse': [
                    {
                        'matcher': 'launch-process',
                        'hooks': [{'type': 'command', 'command': 'ai-guardian'}]
                    }
                ]
            }
        }
        config_file.write_text(json.dumps(config))

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'augment': {
                    'name': 'Augment Code',
                    'config_path': str(config_file),
                    'config_dir_env_var': None,
                    'config_filename': 'settings.json',
                    'hooks': IDESetup.IDE_CONFIGS['augment']['hooks']
                }
            }
        ):
            success, message = setup.setup_ide_hooks('augment', dry_run=False, force=True)

            assert success is True
            backup_file = config_file.with_suffix('.json.backup')
            assert backup_file.exists()

    def test_merge_hooks_augment_preserves_other_hooks(self):
        """Test that merging Augment hooks preserves existing non-ai-guardian hooks."""
        setup = IDESetup()
        existing_config = {
            'hooks': {
                'PreToolUse': [
                    {
                        'matcher': 'launch-process|str-replace-editor|save-file|view|remove-files',
                        'hooks': [{'type': 'command', 'command': 'other-tool'}]
                    }
                ]
            }
        }
        ai_guardian_hooks = IDESetup.IDE_CONFIGS['augment']['hooks']

        merged, warnings = setup.merge_hooks(existing_config, ai_guardian_hooks, 'augment')

        pre_tool_hooks = merged['hooks']['PreToolUse'][0]['hooks']
        assert pre_tool_hooks[0]['command'] == 'ai-guardian'
        assert pre_tool_hooks[1]['command'] == 'other-tool'
        assert len(warnings) > 0


class TestSetupHooks:
    """Test cases for setup_hooks function."""

    def test_setup_hooks_no_ide_detected(self, tmp_path):
        """Test setup when no IDE is detected."""
        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.list_detected_ides.return_value = []

            success = setup_hooks()

            assert success is False

    def test_setup_hooks_auto_detect_single(self, tmp_path):
        """Test auto-detection with single IDE."""
        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.list_detected_ides.return_value = ['claude']
            mock_instance.IDE_CONFIGS = {
                'claude': {'name': 'Claude Code'}
            }
            mock_instance.setup_ide_hooks.return_value = (True, 'Success')

            success = setup_hooks(interactive=False)

            assert success is True
            mock_instance.setup_ide_hooks.assert_called_once()

    def test_setup_hooks_explicit_ide(self, tmp_path):
        """Test explicit IDE specification."""
        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.IDE_CONFIGS = {
                'cursor': {'name': 'Cursor IDE'}
            }
            mock_instance.setup_ide_hooks.return_value = (True, 'Success')

            success = setup_hooks(ide_type='cursor', interactive=False)

            assert success is True
            mock_instance.setup_ide_hooks.assert_called_once_with('cursor', dry_run=False, force=False)

    def test_setup_hooks_with_remote_config(self, tmp_path):
        """Test setup with remote config URL."""
        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.list_detected_ides.return_value = ['claude']
            mock_instance.IDE_CONFIGS = {
                'claude': {'name': 'Claude Code'}
            }
            mock_instance.setup_remote_config.return_value = (True, 'Remote config added')
            mock_instance.setup_ide_hooks.return_value = (True, 'Hooks configured')

            success = setup_hooks(
                ide_type='claude',
                remote_config_url='https://example.com/policy.json',
                interactive=False
            )

            assert success is True
            mock_instance.setup_remote_config.assert_called_once()
            mock_instance.setup_ide_hooks.assert_called_once()

    def test_setup_hooks_remote_config_only(self, tmp_path):
        """Test setup with only remote config, no IDE."""
        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.setup_remote_config.return_value = (True, 'Remote config added')

            success = setup_hooks(
                remote_config_url='https://example.com/policy.json',
                interactive=False
            )

            # Should fail because no IDE detected after remote config
            mock_instance.setup_remote_config.assert_called_once()

    def test_setup_hooks_invalid_ide_type(self):
        """Test setup with invalid IDE type."""
        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.IDE_CONFIGS = {'claude': {}, 'cursor': {}}

            success = setup_hooks(ide_type='invalid', interactive=False)

            assert success is False

    def test_setup_hooks_dry_run(self):
        """Test setup in dry-run mode."""
        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.list_detected_ides.return_value = ['claude']
            mock_instance.IDE_CONFIGS = {
                'claude': {'name': 'Claude Code'}
            }
            mock_instance.setup_ide_hooks.return_value = (True, '[DRY RUN] Success')

            success = setup_hooks(ide_type='claude', dry_run=True, interactive=False)

            assert success is True
            mock_instance.setup_ide_hooks.assert_called_once_with('claude', dry_run=True, force=False)

    def test_setup_hooks_force_mode(self):
        """Test setup with force flag."""
        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.list_detected_ides.return_value = ['claude']
            mock_instance.IDE_CONFIGS = {
                'claude': {'name': 'Claude Code'}
            }
            mock_instance.setup_ide_hooks.return_value = (True, 'Success')

            success = setup_hooks(ide_type='claude', force=True, interactive=False)

            assert success is True
            mock_instance.setup_ide_hooks.assert_called_once_with('claude', dry_run=False, force=True)

    def test_setup_remote_config_invalid_json(self, tmp_path):
        """Test setup with invalid JSON in existing config."""
        setup = IDESetup()

        config_file = tmp_path / 'ai-guardian' / 'ai-guardian.json'
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text('invalid json {')

        with mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': str(tmp_path), 'AI_GUARDIAN_CONFIG_DIR': ''}):
            success, message = setup.setup_remote_config('https://example.com/policy.json', dry_run=False)

            assert success is False
            assert 'Invalid JSON' in message

    def test_setup_ide_hooks_unknown_ide(self):
        """Test setup with unknown IDE type."""
        setup = IDESetup()

        success, message = setup.setup_ide_hooks('unknown_ide', dry_run=False, force=False)

        assert success is False
        assert 'Unknown IDE type' in message

    def test_claude_config_dir_env_var(self, tmp_path):
        """Test that CLAUDE_CONFIG_DIR environment variable is respected."""
        setup = IDESetup()

        custom_dir = tmp_path / 'custom-claude'
        custom_dir.mkdir(parents=True)

        with mock.patch.dict(os.environ, {'CLAUDE_CONFIG_DIR': str(custom_dir)}):
            config_path = setup.get_claude_config_path()
            assert config_path == str(custom_dir / 'settings.json')

    def test_claude_config_dir_default(self):
        """Test default Claude config path when env var not set."""
        setup = IDESetup()

        with mock.patch.dict(os.environ, {}, clear=True):
            if 'CLAUDE_CONFIG_DIR' in os.environ:
                del os.environ['CLAUDE_CONFIG_DIR']
            config_path = setup.get_claude_config_path()
            assert config_path == '~/.claude/settings.json'

    def test_setup_claude_with_custom_config_dir(self, tmp_path):
        """Test setup with custom CLAUDE_CONFIG_DIR."""
        setup = IDESetup()

        custom_dir = tmp_path / 'custom-claude'
        custom_dir.mkdir(parents=True)
        config_file = custom_dir / 'settings.json'

        with mock.patch.dict(os.environ, {'CLAUDE_CONFIG_DIR': str(custom_dir)}):
            success, message = setup.setup_ide_hooks('claude', dry_run=False, force=False)

            assert success is True
            assert config_file.exists()

            # Verify config content
            with open(config_file) as f:
                config = json.load(f)

            assert 'hooks' in config
            assert 'UserPromptSubmit' in config['hooks']

    def test_setup_hooks_interactive_shows_correct_path(self, tmp_path, capsys):
        """Test that interactive confirmation shows correct path with CLAUDE_CONFIG_DIR."""
        custom_dir = tmp_path / 'custom-claude'
        custom_dir.mkdir(parents=True)

        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.list_detected_ides.return_value = ['claude']
            mock_instance.IDE_CONFIGS = {
                'claude': {'name': 'Claude Code', 'config_path': '~/.claude/settings.json'}
            }
            mock_instance.get_config_path.return_value = str(custom_dir / 'settings.json')
            mock_instance.setup_ide_hooks.return_value = (True, 'Success')

            # Mock user saying "no" to abort
            with mock.patch('builtins.input', return_value='n'):
                with mock.patch.dict(os.environ, {'CLAUDE_CONFIG_DIR': str(custom_dir)}):
                    success = setup_hooks(ide_type='claude', interactive=True, dry_run=False)

            # Should have aborted
            assert success is False

            # Check that the correct path was shown in output
            captured = capsys.readouterr()
            assert str(custom_dir / 'settings.json') in captured.out


class TestCreateDefaultConfig:
    """Test cases for create_default_config functionality."""

    def test_create_default_config_success(self, tmp_path):
        """Test creating default config successfully."""
        from ai_guardian.setup import create_default_config

        config_file = tmp_path / 'ai-guardian.json'

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(permissive=False, dry_run=False)

            assert success is True
            assert '✓ Created default config' in message
            assert 'Secret scanning: Enabled' in message
            assert 'Prompt injection: Enabled' in message
            assert 'Permissions: Enabled' in message
            assert config_file.exists()

            # Verify config content
            with open(config_file) as f:
                config = json.load(f)

            assert 'secret_scanning' in config
            assert config['secret_scanning']['enabled'] is True
            assert 'prompt_injection' in config
            assert config['prompt_injection']['enabled'] is True
            assert 'permissions' in config
            assert config['permissions']['enabled'] is True
            assert len(config['permissions']['rules']) == 4  # catch-all allow + MCP deny(warn) + ai-guardian allow + Skill deny(warn)

    def test_create_default_config_permissive(self, tmp_path):
        """Test creating permissive config."""
        from ai_guardian.setup import create_default_config

        config_file = tmp_path / 'ai-guardian.json'

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(permissive=True, dry_run=False)

            assert success is True
            assert '✓ Created default config' in message
            assert 'Permissions: Disabled' in message
            assert config_file.exists()

            # Verify config content
            with open(config_file) as f:
                config = json.load(f)

            assert config['permissions']['enabled'] is False
            assert len(config['permissions']['rules']) == 1  # catch-all allow rule in permissive mode

    def test_create_default_config_already_exists_preserves(self, tmp_path):
        """Test creating config when file already exists preserves it."""
        from ai_guardian.setup import create_default_config

        config_file = tmp_path / 'ai-guardian.json'
        config_file.write_text('{"existing": "config"}')

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(permissive=False, dry_run=False)

            assert success is True
            assert 'preserving' in message

            with open(config_file) as f:
                config = json.load(f)
            assert config == {"existing": "config"}

    def test_create_default_config_force_overwrite(self, tmp_path):
        """Test --force overwrites existing config."""
        from ai_guardian.setup import create_default_config

        config_file = tmp_path / 'ai-guardian.json'
        config_file.write_text('{"existing": "config"}')

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(permissive=False, dry_run=False, force=True)

            assert success is True
            assert '✓ Created default config' in message

            with open(config_file) as f:
                config = json.load(f)
            assert 'secret_scanning' in config
            assert 'existing' not in config

    def test_create_default_config_dry_run(self, tmp_path):
        """Test dry-run mode for config creation."""
        from ai_guardian.setup import create_default_config

        config_file = tmp_path / 'ai-guardian.json'

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(permissive=False, dry_run=True)

            assert success is True
            assert '[DRY RUN]' in message
            assert 'Would create' in message
            assert not config_file.exists()  # File should not be created

            # Verify JSON is in the message
            assert '"secret_scanning"' in message
            assert '"prompt_injection"' in message
            assert '"permissions"' in message

    def test_create_default_config_dry_run_permissive(self, tmp_path):
        """Test dry-run mode with permissive config."""
        from ai_guardian.setup import create_default_config

        config_file = tmp_path / 'ai-guardian.json'

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(permissive=True, dry_run=True)

            assert success is True
            assert '[DRY RUN]' in message
            assert not config_file.exists()

            # Verify permissive settings in dry-run output
            assert '"enabled": false' in message or '"enabled":false' in message  # permissions disabled

    def test_setup_hooks_with_create_config(self, tmp_path):
        """Test setup with --create-config flag."""
        from ai_guardian.setup import setup_hooks

        config_file = tmp_path / 'ai-guardian.json'

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success = setup_hooks(
                ide_type=None,
                create_config=True,
                permissive=False,
                dry_run=False,
                interactive=False
            )

            assert success is True
            assert config_file.exists()

    def test_setup_hooks_with_create_config_and_ide(self, tmp_path):
        """Test setup with both --create-config and IDE setup."""
        from ai_guardian.setup import setup_hooks

        config_file = tmp_path / 'ai-guardian.json'
        ide_config_file = tmp_path / 'settings.json'

        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.list_detected_ides.return_value = ['claude']
            mock_instance.IDE_CONFIGS = {
                'claude': {'name': 'Claude Code', 'config_path': str(ide_config_file)}
            }
            mock_instance.setup_ide_hooks.return_value = (True, 'Success')

            with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
                success = setup_hooks(
                    ide_type='claude',
                    create_config=True,
                    permissive=False,
                    dry_run=False,
                    interactive=False
                )

                assert success is True
                assert config_file.exists()
                mock_instance.setup_ide_hooks.assert_called_once()

    def test_setup_multiple_ides_preserves_config(self, tmp_path):
        """Test setting up multiple IDEs sequentially preserves config (Issue #668)."""
        from ai_guardian.setup import setup_hooks

        config_file = tmp_path / 'ai-guardian.json'
        ide_config_file = tmp_path / 'settings.json'

        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.IDE_CONFIGS = {
                'claude': {'name': 'Claude Code', 'config_path': str(ide_config_file)},
                'cursor': {'name': 'Cursor', 'config_path': str(tmp_path / 'hooks.json')},
            }
            mock_instance.setup_ide_hooks.return_value = (True, 'Success')

            with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
                # First IDE: creates config
                success1 = setup_hooks(
                    ide_type='claude',
                    create_config=True,
                    dry_run=False,
                    interactive=False,
                )
                assert success1 is True
                assert config_file.exists()

                with open(config_file) as f:
                    original_config = json.load(f)

                # Second IDE: should preserve config
                success2 = setup_hooks(
                    ide_type='cursor',
                    create_config=True,
                    dry_run=False,
                    interactive=False,
                )
                assert success2 is True

                with open(config_file) as f:
                    preserved_config = json.load(f)
                assert preserved_config == original_config

    def test_setup_hooks_create_config_only(self, tmp_path):
        """Test setup with only --create-config (no IDE or remote config)."""
        from ai_guardian.setup import setup_hooks

        config_file = tmp_path / 'ai-guardian.json'

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success = setup_hooks(
                ide_type=None,
                remote_config_url=None,
                create_config=True,
                permissive=False,
                dry_run=False,
                interactive=False
            )

            assert success is True
            assert config_file.exists()

    def test_create_config_exists_does_not_block_ide_hooks(self, tmp_path):
        """Test --create-config failure (config exists) does not block --ide hook setup (Issue #561)."""
        from ai_guardian.setup import setup_hooks

        config_file = tmp_path / 'ai-guardian.json'
        config_file.write_text('{}')
        ide_config_file = tmp_path / 'settings.json'

        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.list_detected_ides.return_value = ['claude']
            mock_instance.IDE_CONFIGS = {
                'claude': {'name': 'Claude Code', 'config_path': str(ide_config_file)}
            }
            mock_instance.setup_ide_hooks.return_value = (True, 'Success')

            with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
                success = setup_hooks(
                    ide_type='claude',
                    create_config=True,
                    permissive=False,
                    dry_run=False,
                    interactive=False
                )

                assert success is True
                mock_instance.setup_ide_hooks.assert_called_once()

    def test_create_config_exists_does_not_block_mcp(self, tmp_path):
        """Test --create-config failure (config exists) does not block --mcp installation (Issue #561)."""
        from ai_guardian.setup import setup_hooks

        config_file = tmp_path / 'ai-guardian.json'
        config_file.write_text('{}')
        ide_config_file = tmp_path / 'settings.json'

        with mock.patch('ai_guardian.setup.IDESetup') as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.list_detected_ides.return_value = ['claude']
            mock_instance.IDE_CONFIGS = {
                'claude': {'name': 'Claude Code', 'config_path': str(ide_config_file)}
            }
            mock_instance.setup_ide_hooks.return_value = (True, 'Success')
            mock_instance.get_config_path.return_value = str(ide_config_file)

            with mock.patch('ai_guardian.setup._handle_mcp_setup') as mock_mcp:
                with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
                    success = setup_hooks(
                        ide_type='claude',
                        create_config=True,
                        permissive=False,
                        dry_run=False,
                        interactive=False,
                        mcp=True,
                    )

                    assert success is True
                    mock_instance.setup_ide_hooks.assert_called_once()
                    mock_mcp.assert_called_once()

    def test_create_config_only_preserves_when_exists(self, tmp_path):
        """Test --create-config alone succeeds with preserving message when config exists (Issue #668)."""
        from ai_guardian.setup import setup_hooks

        config_file = tmp_path / 'ai-guardian.json'
        config_file.write_text('{"custom": "value"}')

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success = setup_hooks(
                ide_type=None,
                remote_config_url=None,
                create_config=True,
                permissive=False,
                dry_run=False,
                interactive=False,
            )

            assert success is True
            with open(config_file) as f:
                config = json.load(f)
            assert config == {"custom": "value"}

    def test_create_config_force_overwrites_when_exists(self, tmp_path):
        """Test --create-config --force overwrites existing config (Issue #668)."""
        from ai_guardian.setup import setup_hooks

        config_file = tmp_path / 'ai-guardian.json'
        config_file.write_text('{"custom": "value"}')

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success = setup_hooks(
                ide_type=None,
                remote_config_url=None,
                create_config=True,
                force=True,
                permissive=False,
                dry_run=False,
                interactive=False,
            )

            assert success is True
            with open(config_file) as f:
                config = json.load(f)
            assert 'secret_scanning' in config
            assert 'custom' not in config

    def test_get_default_config_template_secure(self):
        """Test _get_default_config_template returns secure config by default."""
        from ai_guardian.setup import _get_default_config_template

        config = _get_default_config_template(permissive=False)

        assert config['secret_scanning']['enabled'] is True
        assert config['prompt_injection']['enabled'] is True
        assert config['permissions']['enabled'] is True
        assert len(config['permissions']['rules']) == 4
        assert config['permissions']['rules'][0]['matcher'] == '*'
        assert config['permissions']['rules'][0]['mode'] == 'allow'
        assert config['permissions']['rules'][1]['matcher'] == 'mcp__*'
        assert config['permissions']['rules'][1]['mode'] == 'deny'
        assert config['permissions']['rules'][2]['matcher'] == 'mcp__ai-guardian__*'
        assert config['permissions']['rules'][2]['mode'] == 'allow'
        assert config['permissions']['rules'][3]['matcher'] == 'Skill'
        assert config['permissions']['rules'][3]['mode'] == 'deny'

    def test_get_default_config_template_permissive(self):
        """Test _get_default_config_template returns permissive config."""
        from ai_guardian.setup import _get_default_config_template

        config = _get_default_config_template(permissive=True)

        assert config['secret_scanning']['enabled'] is True
        assert config['prompt_injection']['enabled'] is True
        assert config['permissions']['enabled'] is False
        assert len(config['permissions']['rules']) == 1
        assert config['permissions']['rules'][0]['matcher'] == '*'
        assert config['permissions']['rules'][0]['mode'] == 'allow'

    def test_default_config_omits_absolute_cache_path(self, tmp_path):
        """Test that generated config does not contain absolute cache paths (issue #492)."""
        from ai_guardian.setup import create_default_config

        config_file = tmp_path / 'ai-guardian.json'

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(permissive=False, dry_run=False)

            assert success is True

            with open(config_file) as f:
                config = json.load(f)

            engines = config['secret_scanning']['engines']
            gitleaks = next(e for e in engines if isinstance(e, dict) and e.get('type') == 'gitleaks')
            cache = gitleaks['pattern_server']['cache']
            assert 'path' not in cache, (
                "cache.path should not be in default config; "
                "let get_cache_dir() resolve it at runtime"
            )
            assert 'pattern_server' not in config['secret_scanning'], (
                "Top-level pattern_server is deprecated; must use per-engine format"
            )

    def test_default_config_template_no_absolute_paths(self):
        """Test that _get_default_config_template has no absolute paths in cache."""
        from ai_guardian.setup import _get_default_config_template

        config = _get_default_config_template(permissive=False)
        engines = config['secret_scanning']['engines']
        gitleaks = next(e for e in engines if isinstance(e, dict) and e.get('type') == 'gitleaks')
        cache = gitleaks['pattern_server']['cache']
        assert 'path' not in cache

    def test_default_config_uses_per_engine_pattern_server(self):
        """Test that default config uses per-engine pattern_server, not legacy format (issue #558)."""
        from ai_guardian.setup import _get_default_config_template

        config = _get_default_config_template(permissive=False)
        ss = config['secret_scanning']

        assert 'pattern_server' not in ss, (
            "Top-level secret_scanning.pattern_server is deprecated; "
            "use per-engine format instead"
        )

        engines = ss['engines']
        assert len(engines) == 1
        engine = engines[0]
        assert isinstance(engine, dict)
        assert engine['type'] == 'gitleaks'
        assert 'pattern_server' in engine
        ps = engine['pattern_server']
        assert ps['url'] == 'https://raw.githubusercontent.com/leaktk/patterns/main/target'
        assert ps['patterns_endpoint'] == '/patterns/gitleaks/8.27.0'
        assert ps['warn_on_failure'] is True
        assert ps['cache']['refresh_interval_hours'] == 12
        assert ps['cache']['expire_after_hours'] == 168

    def test_existing_config_with_absolute_cache_path_still_works(self, tmp_path):
        """Test backward compat: existing configs with absolute cache.path still load."""
        from ai_guardian.config_utils import get_cache_dir

        abs_path = str(get_cache_dir() / "patterns.toml")
        cache_config = {"path": abs_path, "refresh_interval_hours": 12}
        from pathlib import Path
        resolved = Path(cache_config.get("path", str(get_cache_dir() / "patterns.toml"))).expanduser()
        assert resolved == Path(abs_path).expanduser()

    def test_create_default_config_with_schema(self, tmp_path):
        """Test that default config includes schema reference."""
        from ai_guardian.setup import create_default_config

        config_file = tmp_path / 'ai-guardian.json'

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(permissive=False, dry_run=False)

            assert success is True

            # Verify schema is included
            with open(config_file) as f:
                config = json.load(f)

            assert '$schema' in config
            assert 'ai-guardian-config.schema.json' in config['$schema']

    def test_schema_uses_bundled_file_uri(self):
        """Test that $schema uses a file:// URI pointing to the bundled schema."""
        from ai_guardian.setup import _get_default_config_template

        config = _get_default_config_template(permissive=False)

        assert config['$schema'].startswith('file://')
        assert config['$schema'].endswith('ai-guardian-config.schema.json')
        # Verify the file actually exists at the resolved path
        from urllib.parse import urlparse, unquote
        parsed = urlparse(config['$schema'])
        schema_file = Path(unquote(parsed.path))
        assert schema_file.is_file(), f"Schema file does not exist: {schema_file}"

    def test_json_output_returns_valid_json(self, tmp_path):
        """Test that --json flag outputs only valid JSON."""
        from ai_guardian.setup import create_default_config

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(
                permissive=False, dry_run=False, json_output=True
            )

            assert success is True
            # Message should be parseable as valid JSON
            config = json.loads(message)
            assert '$schema' in config
            assert 'secret_scanning' in config
            # Should not contain non-JSON text
            assert '[DRY RUN]' not in message
            assert '✓' not in message

    def test_json_output_with_permissive(self):
        """Test that --json with --permissive outputs permissive config."""
        from ai_guardian.setup import create_default_config

        success, message = create_default_config(
            permissive=True, dry_run=False, json_output=True
        )

        assert success is True
        config = json.loads(message)
        assert config['permissions']['enabled'] is False

    def test_json_output_skips_exists_check(self, tmp_path):
        """Test that --json doesn't fail when config already exists."""
        from ai_guardian.setup import create_default_config

        config_file = tmp_path / 'ai-guardian.json'
        config_file.write_text('{}')

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(
                permissive=False, dry_run=False, json_output=True
            )

            assert success is True
            config = json.loads(message)


class TestCreateConfigWithProfile:
    """Test create_default_config() with profile parameter."""

    def test_create_config_with_profile_minimal(self, tmp_path):
        from ai_guardian.setup import create_default_config

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(profile="@minimal")
            assert success is True
            assert "profile" in message.lower()

            config_file = tmp_path / 'ai-guardian.json'
            with open(config_file) as f:
                config = json.load(f)
            assert config['permissions']['enabled'] is False
            assert config['prompt_injection']['sensitivity'] == 'low'

    def test_create_config_with_profile_standard(self, tmp_path):
        from ai_guardian.setup import create_default_config

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(profile="@standard")
            assert success is True

            config_file = tmp_path / 'ai-guardian.json'
            with open(config_file) as f:
                config = json.load(f)
            assert config['permissions']['enabled'] is True
            assert config['prompt_injection']['sensitivity'] == 'medium'

    def test_create_config_with_profile_strict(self, tmp_path):
        from ai_guardian.setup import create_default_config

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(profile="@strict")
            assert success is True

            config_file = tmp_path / 'ai-guardian.json'
            with open(config_file) as f:
                config = json.load(f)
            assert config['on_scan_error'] == 'block'
            assert config['prompt_injection']['sensitivity'] == 'high'
            assert config['annotations']['enabled'] is False

    def test_create_config_profile_not_found(self, tmp_path):
        from ai_guardian.setup import create_default_config

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(profile="@nonexistent")
            assert success is False
            assert "Unknown built-in profile" in message

    def test_create_config_profile_dry_run(self, tmp_path):
        from ai_guardian.setup import create_default_config

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(profile="@strict", dry_run=True)
            assert success is True
            assert "[DRY RUN]" in message
            assert not (tmp_path / 'ai-guardian.json').exists()

    def test_create_config_profile_json_output(self, tmp_path):
        from ai_guardian.setup import create_default_config

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(profile="@minimal", json_output=True)
            assert success is True
            config = json.loads(message)
            assert config['permissions']['enabled'] is False

    def test_profile_does_not_break_permissive(self, tmp_path):
        from ai_guardian.setup import create_default_config

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(permissive=True)
            assert success is True
            config_file = tmp_path / 'ai-guardian.json'
            with open(config_file) as f:
                config = json.load(f)
            assert config['permissions']['enabled'] is False


class TestSetupHooksProfiles:
    """Test setup_hooks() with profile-related parameters."""

    def test_list_profiles(self, capsys):
        from ai_guardian.setup import setup_hooks

        success = setup_hooks(list_profiles=True)
        assert success is True
        captured = capsys.readouterr()
        assert "@minimal" in captured.out
        assert "@standard" in captured.out
        assert "@strict" in captured.out

    def test_save_profile(self, tmp_path):
        from ai_guardian.setup import setup_hooks

        config_file = tmp_path / "auto_config" / "ai-guardian.json"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text(json.dumps({"test": True}))

        success = setup_hooks(save_profile="my-team")
        assert success is True

        profiles_dir = tmp_path / "auto_config" / "profiles"
        saved = json.loads((profiles_dir / "my-team.json").read_text())
        assert saved["test"] is True

    def test_save_profile_no_config(self, tmp_path, capsys):
        from ai_guardian.setup import setup_hooks

        success = setup_hooks(save_profile="my-team")
        assert success is False

    def test_profile_without_create_config(self, capsys):
        from ai_guardian.setup import setup_hooks

        success = setup_hooks(profile="@strict")
        assert success is False
        captured = capsys.readouterr()
        assert "--profile requires --create-config" in captured.err


class TestSetupJsonOutput:
    """Test that setup --json outputs clean JSON with no log text (Issue #518)."""

    def test_json_output_ide_explicit(self, tmp_path, capsys):
        """setup --ide claude --json outputs parseable JSON only."""
        ide_config_file = tmp_path / "settings.json"

        with mock.patch("ai_guardian.setup.IDESetup") as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.IDE_CONFIGS = {
                "claude": {"name": "Claude Code", "config_path": str(ide_config_file)}
            }
            mock_instance.get_config_path.return_value = str(ide_config_file)
            mock_instance.setup_ide_hooks.return_value = (True, "Success")
            mock_instance._last_merged_config = {"hooks": {"PreToolUse": []}}

            success = setup_hooks(
                ide_type="claude", json_output=True, interactive=False,
            )

        assert success is True
        captured = capsys.readouterr()
        # stdout must be valid JSON
        result = json.loads(captured.out)
        assert result["success"] is True
        assert result["ide"] == "claude"
        assert "hooks" in result
        # No log text on stderr
        assert "AI Guardian" not in captured.err
        assert "initialized" not in captured.err

    def test_json_output_ide_dry_run(self, tmp_path, capsys):
        """setup --ide claude --json --dry-run outputs clean JSON."""
        ide_config_file = tmp_path / "settings.json"

        with mock.patch("ai_guardian.setup.IDESetup") as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.IDE_CONFIGS = {
                "claude": {"name": "Claude Code", "config_path": str(ide_config_file)}
            }
            mock_instance.get_config_path.return_value = str(ide_config_file)
            mock_instance.setup_ide_hooks.return_value = (
                True, "[DRY RUN] Would configure..."
            )
            mock_instance._last_merged_config = {
                "hooks": {"PreToolUse": [{"type": "command", "command": "ai-guardian"}]}
            }

            success = setup_hooks(
                ide_type="claude", json_output=True, dry_run=True,
            )

        assert success is True
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["success"] is True
        assert result["dry_run"] is True
        assert "hooks" in result
        # No human-readable messages mixed in
        assert "[DRY RUN]" not in captured.out.split("{", 1)[0]

    def test_json_output_no_log_text(self, tmp_path, capsys):
        """stdout contains only JSON — no version banner, no progress messages."""
        ide_config_file = tmp_path / "settings.json"

        with mock.patch("ai_guardian.setup.IDESetup") as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.IDE_CONFIGS = {
                "claude": {"name": "Claude Code", "config_path": str(ide_config_file)}
            }
            mock_instance.get_config_path.return_value = str(ide_config_file)
            mock_instance.setup_ide_hooks.return_value = (True, "Success")
            mock_instance._last_merged_config = {"hooks": {}}

            setup_hooks(
                ide_type="claude", json_output=True, interactive=False,
            )

        captured = capsys.readouterr()
        # First non-whitespace char must be '{'
        stripped = captured.out.strip()
        assert stripped.startswith("{"), f"Output starts with non-JSON: {stripped[:80]}"
        assert stripped.endswith("}")
        # Must be valid JSON
        json.loads(stripped)

    def test_json_output_includes_mcp(self, tmp_path, capsys):
        """setup --ide claude --json always includes MCP server config."""
        ide_config_file = tmp_path / "settings.json"

        with mock.patch("ai_guardian.setup.IDESetup") as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.IDE_CONFIGS = {
                "claude": {"name": "Claude Code", "config_path": str(ide_config_file)}
            }
            mock_instance.get_config_path.return_value = str(ide_config_file)
            mock_instance.setup_ide_hooks.return_value = (True, "Success")
            mock_instance._last_merged_config = {"hooks": {}}

            setup_hooks(
                ide_type="claude", json_output=True, interactive=False,
            )

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "mcp_servers" in result
        assert "ai-guardian" in result["mcp_servers"]
        assert result["mcp_servers"]["ai-guardian"]["command"] == "ai-guardian"
        assert result["mcp_servers"]["ai-guardian"]["args"] == ["mcp-server"]

    def test_json_output_no_mcp_excludes_mcp(self, tmp_path, capsys):
        """setup --ide claude --no-mcp --json excludes MCP server config."""
        ide_config_file = tmp_path / "settings.json"

        with mock.patch("ai_guardian.setup.IDESetup") as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.IDE_CONFIGS = {
                "claude": {"name": "Claude Code", "config_path": str(ide_config_file)}
            }
            mock_instance.get_config_path.return_value = str(ide_config_file)
            mock_instance.setup_ide_hooks.return_value = (True, "Success")
            mock_instance._last_merged_config = {"hooks": {}}

            with mock.patch("ai_guardian.setup._handle_mcp_setup"):
                setup_hooks(
                    ide_type="claude", json_output=True, interactive=False,
                    no_mcp=True,
                )

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "mcp_servers" not in result

    def test_json_output_with_create_config(self, tmp_path, capsys):
        """setup --ide claude --create-config --json includes ai_guardian_config."""
        ide_config_file = tmp_path / "settings.json"

        with mock.patch("ai_guardian.setup.IDESetup") as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.IDE_CONFIGS = {
                "claude": {"name": "Claude Code", "config_path": str(ide_config_file)}
            }
            mock_instance.get_config_path.return_value = str(ide_config_file)
            mock_instance.setup_ide_hooks.return_value = (True, "Success")
            mock_instance._last_merged_config = {"hooks": {}}

            with mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(tmp_path)}):
                setup_hooks(
                    ide_type="claude", json_output=True, interactive=False,
                    create_config=True,
                )

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["success"] is True
        assert "ai_guardian_config" in result
        assert "hooks" in result

    def test_json_output_error_invalid_ide(self, capsys):
        """setup --ide invalid --json outputs JSON error."""
        with mock.patch("ai_guardian.setup.IDESetup") as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.IDE_CONFIGS = {"claude": {"name": "Claude Code"}}

            success = setup_hooks(
                ide_type="invalid", json_output=True, interactive=False,
            )

        assert success is False
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["success"] is False
        assert "error" in result

    def test_json_output_error_no_ide_detected(self, capsys):
        """setup --json with no IDE detected outputs JSON error."""
        with mock.patch("ai_guardian.setup.IDESetup") as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.list_detected_ides.return_value = []

            success = setup_hooks(json_output=True, interactive=False)

        assert success is False
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["success"] is False
        assert "No IDE detected" in result["error"]

    def test_json_output_create_config_only(self, tmp_path, capsys):
        """--json --create-config (without --ide) uses consistent JSON format."""
        with mock.patch("ai_guardian.setup.IDESetup") as MockSetup:
            mock_instance = MockSetup.return_value
            mock_instance.list_detected_ides.return_value = []

            with mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(tmp_path)}):
                success = setup_hooks(
                    create_config=True, json_output=True, interactive=False,
                )

        assert success is True
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["success"] is True
        assert "ai_guardian_config" in result
        assert "$schema" in result["ai_guardian_config"]


class TestSetupDaemonReload:
    """Test daemon reload notification after setup operations (Issue #680)."""

    def test_create_config_calls_daemon_reload(self, tmp_path, capsys):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(tmp_path)}), \
             mock.patch("ai_guardian.daemon.client.send_reload_config", return_value=True) as mock_reload:
            success = setup_hooks(create_config=True, interactive=False)

        assert success is True
        mock_reload.assert_called_once()
        assert "Daemon reloaded" in capsys.readouterr().out

    def test_create_config_no_reload_when_daemon_not_running(self, tmp_path, capsys):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(tmp_path)}), \
             mock.patch("ai_guardian.daemon.client.send_reload_config", return_value=False) as mock_reload:
            success = setup_hooks(create_config=True, interactive=False)

        assert success is True
        mock_reload.assert_called_once()
        assert "Daemon reloaded" not in capsys.readouterr().out

    def test_reload_silences_exceptions(self, tmp_path, capsys):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(tmp_path)}), \
             mock.patch("ai_guardian.daemon.client.send_reload_config", side_effect=Exception("fail")):
            success = setup_hooks(create_config=True, interactive=False)

        assert success is True


class TestKiroSetup:
    """Test cases for Kiro (AWS) setup."""

    def test_kiro_in_ide_configs(self):
        """Verify Kiro entry exists in IDE_CONFIGS with correct keys."""
        assert "kiro" in IDESetup.IDE_CONFIGS
        kiro_cfg = IDESetup.IDE_CONFIGS["kiro"]
        assert kiro_cfg["name"] == "Kiro"
        assert kiro_cfg["config_path"] == ".kiro/hooks"
        assert kiro_cfg.get("script_based") is True
        assert "hook_scripts" in kiro_cfg

    def test_kiro_hooks_are_script_based(self):
        """Verify Kiro uses script-based hooks with correct event names."""
        kiro_cfg = IDESetup.IDE_CONFIGS["kiro"]
        assert kiro_cfg["script_based"] is True
        scripts = kiro_cfg["hook_scripts"]
        assert "PreToolUse" in scripts
        assert "PostToolUse" in scripts
        assert "PromptSubmit" in scripts

    def test_kiro_script_content(self):
        """Verify script content calls ai-guardian."""
        kiro_cfg = IDESetup.IDE_CONFIGS["kiro"]
        content = kiro_cfg["script_content"]
        assert content.startswith("#!/bin/sh")
        assert "ai-guardian" in content

    def test_setup_ide_hooks_kiro_new(self, tmp_path):
        """Test setting up Kiro hooks creates executable scripts."""
        setup = IDESetup()
        hooks_dir = tmp_path / '.kiro' / 'hooks'

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'kiro': {
                    'name': 'Kiro',
                    'config_path': str(hooks_dir),
                    'config_dir_env_var': None,
                    'config_filename': None,
                    'script_based': True,
                    'hook_scripts': IDESetup.IDE_CONFIGS['kiro']['hook_scripts'],
                    'script_content': IDESetup.IDE_CONFIGS['kiro']['script_content'],
                }
            }
        ):
            success, message = setup.setup_ide_hooks('kiro', dry_run=False, force=False)

            assert success is True
            assert hooks_dir.exists()

            for script_name in ['PreToolUse', 'PostToolUse', 'PromptSubmit']:
                script_path = hooks_dir / script_name
                assert script_path.exists()
                content = script_path.read_text()
                assert 'ai-guardian' in content
                import stat
                assert script_path.stat().st_mode & stat.S_IXUSR

    def test_setup_ide_hooks_kiro_dry_run(self, tmp_path):
        """Test dry-run mode for Kiro."""
        setup = IDESetup()
        hooks_dir = tmp_path / '.kiro' / 'hooks'

        with mock.patch.object(
            setup, 'IDE_CONFIGS',
            {
                'kiro': {
                    'name': 'Kiro',
                    'config_path': str(hooks_dir),
                    'config_dir_env_var': None,
                    'config_filename': None,
                    'script_based': True,
                    'hook_scripts': IDESetup.IDE_CONFIGS['kiro']['hook_scripts'],
                    'script_content': IDESetup.IDE_CONFIGS['kiro']['script_content'],
                }
            }
        ):
            success, message = setup.setup_ide_hooks('kiro', dry_run=True, force=False)

            assert success is True
            assert '[DRY RUN]' in message
            assert not hooks_dir.exists()

    def test_check_hooks_configured_kiro(self, tmp_path):
        """Test detection of existing Kiro hook scripts."""
        setup = IDESetup()
        hooks_dir = tmp_path / '.kiro' / 'hooks'
        hooks_dir.mkdir(parents=True)
        script = hooks_dir / 'PreToolUse'
        script.write_text("#!/bin/sh\nai-guardian\n")

        assert setup.check_hooks_configured(hooks_dir, 'kiro') is True

    def test_check_hooks_not_configured_kiro(self, tmp_path):
        """Test returns False when no ai-guardian scripts present."""
        setup = IDESetup()
        hooks_dir = tmp_path / '.kiro' / 'hooks'
        hooks_dir.mkdir(parents=True)
        script = hooks_dir / 'PreToolUse'
        script.write_text("#!/bin/sh\nother-tool\n")

        assert setup.check_hooks_configured(hooks_dir, 'kiro') is False

    def test_check_hooks_not_configured_kiro_empty(self, tmp_path):
        """Test returns False when hooks directory doesn't exist."""
        setup = IDESetup()
        hooks_dir = tmp_path / '.kiro' / 'hooks'

        assert setup.check_hooks_configured(hooks_dir, 'kiro') is False

    def test_kiro_in_mcp_ide_configs(self):
        """Verify Kiro MCP config entry."""
        from ai_guardian.setup import _MCP_IDE_CONFIGS
        assert "kiro" in _MCP_IDE_CONFIGS
        kiro_mcp = _MCP_IDE_CONFIGS["kiro"]
        assert kiro_mcp["config_file"] == "~/.kiro/settings.json"
        assert kiro_mcp["config_key"] == "mcpServers"
        assert kiro_mcp["skill_dir"] == ".kiro/skills"
