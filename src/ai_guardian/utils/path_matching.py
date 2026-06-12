"""
Path matching utilities for ignore_files patterns.

This module provides glob pattern matching functions that properly handle
leading **/ patterns (e.g., **/.claude/skills/**).
"""

import fnmatch
import os
from pathlib import Path
from typing import List


def match_leading_doublestar_pattern(file_path, pattern):
    """
    Match a pattern starting with **/ against a file path.

    Patterns like **/.claude/skills/** should match paths containing
    .claude/skills/ anywhere in the filesystem.

    Args:
        file_path: Absolute file path to check
        pattern: Pattern starting with **/ (or **\\ on Windows)

    Returns:
        bool: True if pattern matches the path

    Examples:
        >>> match_leading_doublestar_pattern("/home/user/.claude/skills/test.md", "**/.claude/skills/**")
        True
        >>> match_leading_doublestar_pattern("/home/user/project/src/main.py", "**/.claude/skills/**")
        False
        >>> match_leading_doublestar_pattern("/home/user/docs/file.md", "**/docs/**")
        True
    """
    # Normalize separators to / for consistent matching
    pattern = pattern.replace("\\", "/")

    # Remove leading **/
    pattern_suffix = pattern[3:] if pattern.startswith("**/") else pattern[2:]

    # Split the pattern into parts
    # e.g., ".claude/skills/**" -> [".claude", "skills", "**"]
    pattern_parts = pattern_suffix.split("/")

    # Convert file path to parts
    file_parts = Path(file_path).parts

    # Try to find the pattern sequence in the file path
    pattern_without_trailing_star = []
    has_trailing_star = False

    for part in pattern_parts:
        if part == "**":
            has_trailing_star = True
            break
        pattern_without_trailing_star.append(part)

    if not pattern_without_trailing_star:
        # Pattern is just **/**, matches everything
        return True

    # Look for the pattern sequence in the file path
    pattern_len = len(pattern_without_trailing_star)

    for i in range(len(file_parts) - pattern_len + 1):
        # Check if pattern matches at this position
        match = True
        for j, pattern_part in enumerate(pattern_without_trailing_star):
            file_part = file_parts[i + j]
            # Use fnmatch for wildcard matching within parts
            if not fnmatch.fnmatch(file_part, pattern_part):
                match = False
                break

        if match:
            # Found the pattern sequence
            # If there's a trailing **, check if there are more parts after
            if has_trailing_star:
                # **/ at the end matches if there's at least one more part
                return i + pattern_len < len(file_parts)
            else:
                # No trailing **, must be exact match
                return i + pattern_len == len(file_parts)

    return False


def match_ignore_pattern(file_path, pattern):
    """
    Match an ignore pattern against a file path.

    Supports both leading **/ patterns and standard Path.match() patterns.

    Args:
        file_path: Absolute file path to check
        pattern: Glob pattern (may start with **/)

    Returns:
        bool: True if pattern matches the path

    Examples:
        >>> match_ignore_pattern("/home/user/.claude/skills/test.md", "**/.claude/skills/**")
        True
        >>> match_ignore_pattern("/home/user/project/.git/config", ".git/**")
        True
        >>> match_ignore_pattern("/home/user/project/src/main.py", "*.py")
        True
    """
    norm_pattern = pattern.replace("\\", "/")
    if norm_pattern.startswith("**/"):
        return match_leading_doublestar_pattern(file_path, norm_pattern)
    else:
        # Use Path.match() for other patterns
        return Path(file_path).match(pattern)


def matches_ignore_files(file_path: str, ignore_files: List[str]) -> bool:
    """Check if file_path matches any pattern in an ignore_files list.

    Supports ``**/`` leading patterns, standard globs via ``Path.match()``,
    and basename-only matching via ``fnmatch``.

    Args:
        file_path: Absolute or relative file path to check.
        ignore_files: List of glob patterns (e.g. ``["**/tests/**", "*.fixture"]``).

    Returns:
        True if the file should be ignored.
    """
    if not ignore_files or not file_path:
        return False
    for pattern in ignore_files:
        if match_ignore_pattern(file_path, pattern):
            return True
        if fnmatch.fnmatch(os.path.basename(file_path), pattern):
            return True
    return False
