#!/usr/bin/env python3
"""
Configuration utilities for ai-guardian.

Shared utilities for configuration directory resolution and timestamp handling.
"""

import logging
import os
import re
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


def get_state_dir() -> Path:
    """
    Get ai-guardian state directory (logs, violations).

    Priority order:
    1. AI_GUARDIAN_STATE_DIR (direct override)
    2. XDG_STATE_HOME/ai-guardian (XDG standard)
    3. ~/.local/state/ai-guardian (default)

    Returns:
        Path: State directory path
    """
    state_dir = os.environ.get("AI_GUARDIAN_STATE_DIR")
    if state_dir:
        return Path(state_dir).expanduser()

    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return Path(state_home) / "ai-guardian"

    return Path("~/.local/state/ai-guardian").expanduser()


def get_cache_dir() -> Path:
    """
    Get ai-guardian cache directory.

    Priority order:
    1. AI_GUARDIAN_CACHE_DIR (direct override)
    2. XDG_CACHE_HOME/ai-guardian (XDG standard)
    3. ~/.cache/ai-guardian (default)

    Returns:
        Path: Cache directory path
    """
    cache_dir = os.environ.get("AI_GUARDIAN_CACHE_DIR")
    if cache_dir:
        return Path(cache_dir).expanduser()

    cache_home = os.environ.get("XDG_CACHE_HOME")
    if cache_home:
        return Path(cache_home) / "ai-guardian"

    return Path("~/.cache/ai-guardian").expanduser()


def migrate_state_files() -> None:
    """
    Migrate state files from old config dir to new state dir.

    For backward compatibility when users upgrade, checks if state files
    exist in the old location (config dir) and copies them to the new
    state dir if the new location doesn't have them yet.
    """
    import shutil

    config_dir = get_config_dir()
    state_dir = get_state_dir()

    if config_dir == state_dir:
        return

    state_files = ["violations.jsonl", "ai-guardian.log"]
    for filename in state_files:
        old_path = config_dir / filename
        new_path = state_dir / filename

        if old_path.exists() and not new_path.exists():
            try:
                state_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(old_path), str(new_path))
                logger.info(f"Migrated {filename} from {config_dir} to {state_dir}")
            except OSError as e:
                logger.warning(f"Failed to migrate {filename}: {e}")


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


def is_feature_enabled(feature_config, current_time: Optional[datetime] = None, default: bool = True) -> bool:
    """
    Check if a feature is enabled (not temporarily disabled).

    Supports both simple boolean format (permanent) and extended object format
    with time-based disabling.

    Args:
        feature_config: Feature configuration - can be:
            - bool: Simple enabled/disabled (permanent)
            - dict: Extended format with optional time-based disabling
            - None: Use default value
        current_time: Optional current time for testing (defaults to now in UTC)
        default: Default value if config is None or missing (default: True)

    Returns:
        bool: True if feature should be active, False if disabled

    Examples:
        Simple boolean format (backward compatible):
        >>> is_feature_enabled(True)
        True

        >>> is_feature_enabled(False)
        False

        Extended format without time-based disabling:
        >>> is_feature_enabled({"value": True})
        True

        Extended format with time-based disabling (active):
        >>> config = {"value": False, "disabled_until": "2099-12-31T23:59:59Z"}
        >>> is_feature_enabled(config)  # Still disabled (future date)
        False

        Extended format with expired disable period (auto-enabled):
        >>> config = {"value": False, "disabled_until": "2020-01-01T00:00:00Z"}
        >>> is_feature_enabled(config)  # Auto-enabled (past date)
        True

        Missing config uses default:
        >>> is_feature_enabled(None)
        True

        >>> is_feature_enabled(None, default=False)
        False
    """
    # Handle None - use default
    if feature_config is None:
        return default

    # Simple boolean format (backward compatible)
    if isinstance(feature_config, bool):
        return feature_config

    # Extended format with optional time-based disabling
    if isinstance(feature_config, dict):
        # Get the enabled value (default to True if missing)
        enabled_value = feature_config.get("value", default)

        # If currently disabled, check if it should be auto-re-enabled
        if not enabled_value:
            disabled_until = feature_config.get("disabled_until")
            if disabled_until:
                # Check if disable period has expired
                if is_expired(disabled_until, current_time):
                    # Temporary disable period has expired - re-enable
                    logger.info("Feature auto-enabled (disable period expired)")
                    return True
                else:
                    # Still within disable period
                    logger.debug("Feature disabled (within disable period)")
                    return False

        # Return the enabled value
        return enabled_value

    # Unknown format - fail-safe to default
    logger.warning(f"Unknown feature config format: {type(feature_config)}, using default: {default}")
    return default


def validate_regex_pattern(pattern: str, max_length: int = 500) -> bool:
    """
    Validate a regex pattern for safety before compilation.

    Prevents ReDoS (Regular Expression Denial of Service) attacks from
    untrusted pattern sources (e.g., network-sourced pattern servers).

    Args:
        pattern: Regex pattern string to validate
        max_length: Maximum allowed pattern length (default: 500)

    Returns:
        True if pattern is safe to compile, False if dangerous

    Security checks:
        - Length limit to prevent extremely complex patterns
        - Nested quantifiers detection (e.g., (a+)+, (a*)*) - common ReDoS vector
        - Valid regex syntax

    Examples:
        >>> validate_regex_pattern(r"[a-z]+@[a-z]+\\.com")
        True

        >>> validate_regex_pattern(r"(a+)+b")  # Nested quantifiers - ReDoS vector
        False

        >>> validate_regex_pattern("a" * 1000)  # Too long
        False

        >>> validate_regex_pattern(r"[invalid")  # Invalid syntax
        False
    """
    if not pattern or not isinstance(pattern, str):
        logger.warning("Invalid pattern type or empty pattern")
        return False

    # Check length limit
    if len(pattern) > max_length:
        logger.warning(f"Pattern too long: {len(pattern)} > {max_length}")
        return False

    # Detect nested quantifiers - common ReDoS pattern
    # Matches patterns like: (a+)+, (a*)*, (a?)+, [a-z]+*, etc.
    # These have a quantified expression inside a quantified group/class
    # We need to be careful NOT to match safe patterns like [a-z]+? (non-greedy after char class)
    # or [\s\S]+? (non-greedy match-all)
    # Pattern: closing paren/bracket ) or ] followed by quantifier then another quantifier
    # BUT: allow non-greedy quantifiers which end in ? (those are safe)
    nested_quantifier_patterns = [
        r'\)[+*][+*]',    # Consecutive quantifiers after closing paren like )++ or )+* (not greedy)
        r'\][+*][+*]',    # Consecutive quantifiers after closing bracket like ]++ or ]+* (not greedy)
        r'[+*?]\)[+*]',   # Quantifier before ) then non-greedy after, like +)+
    ]

    for nested_pattern in nested_quantifier_patterns:
        if re.search(nested_pattern, pattern):
            logger.warning(f"Nested quantifiers detected in pattern (potential ReDoS): {pattern[:100]}")
            return False

    # Validate regex syntax by attempting to compile
    try:
        re.compile(pattern)
        return True
    except re.error as e:
        logger.warning(f"Invalid regex syntax: {e}, pattern: {pattern[:100]}")
        return False
