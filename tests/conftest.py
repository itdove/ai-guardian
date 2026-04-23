"""
Pytest configuration and fixtures for AI Guardian tests.

Provides test isolation for configuration directories and common test utilities.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest


@pytest.fixture
def isolated_config_dir(tmp_path):
    """
    Provide an isolated configuration directory for tests.

    Sets AI_GUARDIAN_CONFIG_DIR environment variable to a temporary directory,
    ensuring tests don't interfere with the user's actual configuration.

    Usage:
        def test_something(isolated_config_dir):
            # Test code here - config will be in temporary directory
            # isolated_config_dir is a Path object to the temp directory
            pass
    """
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True, exist_ok=True)

    # Set environment variable for AI Guardian
    with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': str(config_dir)}):
        yield config_dir


@pytest.fixture
def isolated_config_with_file(isolated_config_dir):
    """
    Provide an isolated config directory with a default config file.

    Creates a basic ai-guardian.json config file for tests that need one.

    Usage:
        def test_something(isolated_config_with_file):
            config_dir, config_file = isolated_config_with_file
            # config_file contains path to ai-guardian.json
            pass
    """
    config_file = isolated_config_dir / "ai-guardian.json"

    # Create a minimal default config
    default_config = {
        "secret_scanning": {
            "enabled": True,
            "scanner": "gitleaks"
        },
        "prompt_injection": {
            "enabled": True
        },
        "permissions": {
            "enabled": True,
            "rules": []
        }
    }

    with open(config_file, 'w') as f:
        json.dump(default_config, f, indent=2)

    return isolated_config_dir, config_file


@pytest.fixture
def mock_mcp_server():
    """
    Provide a fresh MockMCPServer instance for testing.

    The server is automatically reset before each test to ensure isolation.

    Usage:
        def test_something(mock_mcp_server):
            response = mock_mcp_server.notebook_create("Test Notebook")
            assert response["status"] == "success"
    """
    from tests.fixtures.mock_mcp_server import MockMCPServer

    server = MockMCPServer()
    server.reset()
    yield server
    # Cleanup after test
    server.reset()


@pytest.fixture
def attack_patterns():
    """
    Provide attack pattern constants for testing.

    Usage:
        def test_ssrf_detection(attack_patterns):
            assert "169.254.169.254" in attack_patterns.SSRF_AWS_METADATA
    """
    from tests.fixtures import attack_constants
    return attack_constants
