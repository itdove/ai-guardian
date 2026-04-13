#!/usr/bin/env python3
"""
Configuration utilities for ai-guardian.

Shared utilities for configuration directory resolution and timestamp handling.
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


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


def parse_iso8601(timestamp_str: str) -> Optional[datetime]:
    """
    Parse ISO 8601 timestamp string to datetime object.

    Supports formats:
    - 2026-04-13T12:00:00Z (UTC with Z suffix)
    - 2026-04-13T12:00:00+00:00 (UTC with offset)
    - 2026-04-13T12:00:00 (assumed UTC if no timezone)

    Args:
        timestamp_str: ISO 8601 formatted timestamp string

    Returns:
        datetime object in UTC, or None if parsing fails

    Examples:
        >>> parse_iso8601("2026-04-13T12:00:00Z")
        datetime.datetime(2026, 4, 13, 12, 0, tzinfo=datetime.timezone.utc)

        >>> parse_iso8601("invalid")
        None
    """
    if not timestamp_str or not isinstance(timestamp_str, str):
        return None

    try:
        # Try parsing with fromisoformat (Python 3.7+)
        # Handle Z suffix (not supported by fromisoformat in Python < 3.11)
        if timestamp_str.endswith('Z'):
            timestamp_str = timestamp_str[:-1] + '+00:00'

        dt = datetime.fromisoformat(timestamp_str)

        # If no timezone info, assume UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        # Convert to UTC if in different timezone
        elif dt.tzinfo != timezone.utc:
            dt = dt.astimezone(timezone.utc)

        return dt

    except (ValueError, AttributeError) as e:
        logger.debug(f"Failed to parse timestamp '{timestamp_str}': {e}")
        return None


def is_expired(valid_until: str, current_time: Optional[datetime] = None) -> bool:
    """
    Check if a timestamp has expired.

    Args:
        valid_until: ISO 8601 timestamp string
        current_time: Optional current time for testing (defaults to now in UTC)

    Returns:
        True if expired (current_time >= valid_until), False otherwise
        Returns False on parsing errors (fail-safe)

    Examples:
        >>> is_expired("2020-01-01T00:00:00Z")  # Past timestamp
        True

        >>> is_expired("2099-12-31T23:59:59Z")  # Future timestamp
        False

        >>> is_expired("invalid-timestamp")  # Invalid format
        False
    """
    # Parse the valid_until timestamp
    valid_until_dt = parse_iso8601(valid_until)

    # Fail-safe: if parsing fails, treat as non-expired
    if valid_until_dt is None:
        logger.debug(f"Could not parse valid_until timestamp '{valid_until}', treating as non-expired")
        return False

    # Use current time or default to now (UTC)
    if current_time is None:
        current_time = datetime.now(timezone.utc)
    elif current_time.tzinfo is None:
        # Ensure current_time has timezone info
        current_time = current_time.replace(tzinfo=timezone.utc)

    # Check if expired: current_time >= valid_until
    return current_time >= valid_until_dt
