#!/usr/bin/env python3
"""
Configuration utilities for ai-guardian.

Shared utilities for configuration directory resolution.
"""

import os
from pathlib import Path


def get_config_dir() -> Path:
    """
    Get ai-guardian configuration directory.

    Priority order:
    1. AI_GUARDIAN_CONFIG_DIR (direct override)
    2. XDG_CONFIG_HOME/ai-guardian (XDG standard)
    3. ~/.config/ai-guardian (default)

    Returns:
        Path: Configuration directory path

    Examples:
        >>> os.environ['AI_GUARDIAN_CONFIG_DIR'] = '/custom/path'
        >>> get_config_dir()
        PosixPath('/custom/path')

        >>> del os.environ['AI_GUARDIAN_CONFIG_DIR']
        >>> os.environ['XDG_CONFIG_HOME'] = '/xdg/config'
        >>> get_config_dir()
        PosixPath('/xdg/config/ai-guardian')

        >>> del os.environ['XDG_CONFIG_HOME']
        >>> get_config_dir()
        PosixPath('~/.config/ai-guardian').expanduser()
    """
    # Priority 1: Check AI_GUARDIAN_CONFIG_DIR environment variable
    config_dir = os.environ.get("AI_GUARDIAN_CONFIG_DIR")
    if config_dir:
        return Path(config_dir).expanduser()

    # Priority 2: Check XDG_CONFIG_HOME
    config_home = os.environ.get("XDG_CONFIG_HOME")
    if config_home:
        return Path(config_home) / "ai-guardian"

    # Priority 3: Default fallback
    return Path("~/.config/ai-guardian").expanduser()
