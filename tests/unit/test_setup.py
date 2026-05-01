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
            assert len(config['permissions']['rules']) == 2  # Skill and MCP deny rules

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
            assert len(config['permissions']['rules']) == 0  # No deny rules in permissive mode

    def test_create_default_config_already_exists(self, tmp_path):
        """Test creating config when file already exists."""
        from ai_guardian.setup import create_default_config

        config_file = tmp_path / 'ai-guardian.json'
        config_file.write_text('{"existing": "config"}')

        with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(tmp_path)}):
            success, message = create_default_config(permissive=False, dry_run=False)

            assert success is False
            assert 'already exists' in message

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

    def test_get_default_config_template_secure(self):
        """Test _get_default_config_template returns secure config by default."""
        from ai_guardian.setup import _get_default_config_template

        config = _get_default_config_template(permissive=False)

        assert config['secret_scanning']['enabled'] is True
        assert config['prompt_injection']['enabled'] is True
        assert config['permissions']['enabled'] is True
        assert len(config['permissions']['rules']) == 2
        assert config['permissions']['rules'][0]['matcher'] == 'Skill'
        assert config['permissions']['rules'][0]['mode'] == 'deny'
        assert config['permissions']['rules'][1]['matcher'] == 'mcp__*'
        assert config['permissions']['rules'][1]['mode'] == 'deny'

    def test_get_default_config_template_permissive(self):
        """Test _get_default_config_template returns permissive config."""
        from ai_guardian.setup import _get_default_config_template

        config = _get_default_config_template(permissive=True)

        assert config['secret_scanning']['enabled'] is True
        assert config['prompt_injection']['enabled'] is True
        assert config['permissions']['enabled'] is False
        assert len(config['permissions']['rules']) == 0

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
