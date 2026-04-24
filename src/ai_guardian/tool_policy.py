#!/usr/bin/env python3
"""
Tool Allow/Deny List Policy Checker

Permission system using matcher-based rules in JSON configuration:
- permissions: Array of {matcher, allow, deny} objects
- Matcher determines which tools the rule applies to
- Allow/deny patterns check against tool-specific values
- Auto-discovery via permissions_directories

Configuration file: ~/.config/ai-guardian/ai-guardian.json
"""

import fnmatch
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Union

try:
    from jsonschema import Draft7Validator, ValidationError as JsonSchemaValidationError
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False
    Draft7Validator = None
    JsonSchemaValidationError = None

from ai_guardian.config_utils import get_config_dir, is_expired

# Import violation logger
try:
    from ai_guardian.violation_logger import ViolationLogger
    HAS_VIOLATION_LOGGER = True
except ImportError:
    HAS_VIOLATION_LOGGER = False
    logging.debug("violation_logger module not available")

# Import SSRF protector
try:
    from ai_guardian.ssrf_protector import SSRFProtector
    HAS_SSRF_PROTECTOR = True
except ImportError:
    HAS_SSRF_PROTECTOR = False
    logging.debug("ssrf_protector module not available")

logger = logging.getLogger(__name__)

# Hardcoded critical protections - cannot be disabled or bypassed
#
# BYPASS BEHAVIOR (via _should_skip_immutable_protection):
# - Edit/Write on development source: BYPASSED (enables contributor workflow)
# - Edit/Write on config/hooks/cache/pip: ALWAYS blocked (no bypass)
# - Bash/PowerShell on anything: ALWAYS blocked (no bypass)
#
# These patterns are checked FIRST, before any user-configured permissions
IMMUTABLE_DENY_PATTERNS = {
    "Write": [
        # Config files - ALWAYS protected (even for repo owners)
        "*ai-guardian.json",
        "*/.config/ai-guardian/*",
        "*/.ai-guardian.json",

        # Cache files - ALWAYS protected (prevents cache poisoning)
        "*/.cache/ai-guardian/*",

        # IDE hooks - ALWAYS protected (prevents disabling ai-guardian)
        "*/.claude/settings.json",
        "*/.claude/hooks.json",
        "*/.cursor/hooks.json",
        "*/Claude/settings.json",    # Windows
        "*/Cursor/hooks.json",        # Windows

        # Package code - Pip ALWAYS protected, dev source bypassed for Write/Edit only
        "*/site-packages/ai_guardian/*",           # Pip-installed - always blocked
        "*/ai-guardian/src/ai_guardian/*",         # Dev source - bypassed for Write/Edit
        "*/ai-guardian/ai_guardian/*",             # Alternative layout

        # Directory markers - ALWAYS protected (prevents bypass of directory rules)
        "*/.ai-read-deny",
        "**/.ai-read-deny",
    ],

    "Edit": [
        # Config files - ALWAYS protected (even for repo owners)
        "*ai-guardian.json",
        "*/.config/ai-guardian/*",
        "*/.ai-guardian.json",

        # Cache files - ALWAYS protected (prevents cache poisoning)
        "*/.cache/ai-guardian/*",

        # IDE hooks - ALWAYS protected (prevents disabling ai-guardian)
        "*/.claude/settings.json",
        "*/.claude/hooks.json",
        "*/.cursor/hooks.json",
        "*/Claude/settings.json",
        "*/Cursor/hooks.json",

        # Package code - Pip ALWAYS protected, dev source bypassed for Write/Edit only
        "*/site-packages/ai_guardian/*",           # Pip-installed - always blocked
        "*/ai-guardian/src/ai_guardian/*",         # Dev source - bypassed for Write/Edit
        "*/ai-guardian/ai_guardian/*",             # Alternative layout

        # Directory markers - ALWAYS protected (prevents bypass of directory rules)
        "*/.ai-read-deny",
        "**/.ai-read-deny",
    ],

    "Bash": [
        # Block commands that could modify protected files
        # Note: NO BYPASS for Bash - always blocks even on dev source
        # (Prevents rm, mv, chmod, etc. on source code)
        # Patterns are path-specific to avoid blocking legitimate content mentioning "ai-guardian" (Issue #188)

        # sed protection - specific paths only
        "*sed*ai-guardian.json*", "*sed*.ai-guardian.json*",  # Config files
        "*sed*.config/ai-guardian/*",  # Config directory
        "*sed*site-packages/ai_guardian*", "*sed*ai-guardian/src/ai_guardian*", "*sed*ai-guardian/ai_guardian*",  # Package code
        "*sed*.claude/settings.json*",
        "*sed*.cursor/hooks.json*",

        # awk protection - specific paths only
        "*awk*ai-guardian.json*", "*awk*.ai-guardian.json*",  # Config files
        "*awk*.config/ai-guardian/*",  # Config directory
        "*awk*site-packages/ai_guardian*", "*awk*ai-guardian/src/ai_guardian*", "*awk*ai-guardian/ai_guardian*",  # Package code
        "*awk*.claude/settings.json*",
        "*awk*.cursor/hooks.json*",

        # vim/nano protection - specific paths only
        "*vim*ai-guardian.json*", "*vim*.ai-guardian.json*",  # Config files
        "*vim*.config/ai-guardian/*",  # Config directory
        "*vim*.claude/settings.json*",
        "*vim*.cursor/hooks.json*",
        "*nano*ai-guardian.json*", "*nano*.ai-guardian.json*",  # Config files
        "*nano*.config/ai-guardian/*",  # Config directory
        "*nano*.claude/settings.json*",
        "*nano*.cursor/hooks.json*",

        # chmod protection - specific paths only
        "*chmod*ai-guardian.json*", "*chmod*.ai-guardian.json*",  # Config files
        "*chmod*.config/ai-guardian/*",  # Config directory
        "*chmod*site-packages/ai_guardian*", "*chmod*ai-guardian/src/ai_guardian*", "*chmod*ai-guardian/ai_guardian*",  # Package code
        "*chmod*.claude/settings.json*",
        "*chmod*.cursor/hooks.json*",

        # chattr protection - specific paths only
        "*chattr*ai-guardian.json*", "*chattr*.ai-guardian.json*",  # Config files
        "*chattr*.config/ai-guardian/*",  # Config directory
        "*chattr*.claude*", "*chattr*.cursor*",

        # Redirect protection - specific paths only
        "*>*ai-guardian.json*", "*>*.ai-guardian.json*",  # Config files
        "*>*.config/ai-guardian/*",  # Config directory
        "*>*site-packages/ai_guardian*", "*>*ai-guardian/src/ai_guardian*", "*>*ai-guardian/ai_guardian*",  # Package code
        "*>*.claude/settings.json*",
        "*>*.cursor/hooks.json*",

        # rm/mv protection - specific paths only
        "*rm*ai-guardian.json*",
        "*rm*.claude/settings.json*",
        "*rm*.cursor/hooks.json*",
        "*mv*ai-guardian.json*",
        "*mv*.claude/settings.json*",
        "*mv*.cursor/hooks.json*",

        # Protect ai-guardian cache from manipulation (prevents cache poisoning)
        "*rm*.cache/ai-guardian/*",
        "*mv*.cache/ai-guardian/*",
        "*sed*.cache/ai-guardian/*",
        "*awk*.cache/ai-guardian/*",
        "*>*.cache/ai-guardian/*",
        "*chmod*.cache/ai-guardian/*",
        "*chattr*.cache/ai-guardian/*",
        "*vim*.cache/ai-guardian/*",
        "*nano*.cache/ai-guardian/*",

        # Protect .ai-read-deny marker files from bash manipulation
        "*rm*.ai-read-deny*",          # Block: rm .ai-read-deny
        "*rm*/.ai-read-deny*",         # Block: rm /path/.ai-read-deny
        "*mv*.ai-read-deny*",          # Block: mv .ai-read-deny
        "*sed*.ai-read-deny*",         # Block: sed on .ai-read-deny
        "*awk*.ai-read-deny*",         # Block: awk on .ai-read-deny
        "*>*.ai-read-deny*",           # Block: echo > .ai-read-deny
        "*chmod*.ai-read-deny*",       # Block: chmod .ai-read-deny
        "*chattr*.ai-read-deny*",      # Block: chattr .ai-read-deny
        "*vim*.ai-read-deny*",         # Block: vim .ai-read-deny
        "*nano*.ai-read-deny*",        # Block: nano .ai-read-deny
    ],

    "PowerShell": [
        # Note: NO BYPASS for PowerShell - always blocks even on dev source
        # (Prevents Remove-Item, Move-Item, etc. on source code)
        # Patterns are path-specific to avoid blocking legitimate content mentioning "ai-guardian" (Issue #188)

        # Protect ai-guardian config files - specific paths only
        "*Remove-Item*ai-guardian.json*", "*Remove-Item*.ai-guardian.json*",
        "*Remove-Item*.config/ai-guardian/*", "*Remove-Item*.config\\ai-guardian\\*",
        "*Move-Item*ai-guardian.json*", "*Move-Item*.ai-guardian.json*",
        "*Move-Item*.config/ai-guardian/*", "*Move-Item*.config\\ai-guardian\\*",
        "*Rename-Item*ai-guardian.json*", "*Rename-Item*.ai-guardian.json*",
        "*Rename-Item*.config/ai-guardian/*", "*Rename-Item*.config\\ai-guardian\\*",
        "*Set-Content*ai-guardian.json*", "*Set-Content*.ai-guardian.json*",
        "*Set-Content*.config/ai-guardian/*", "*Set-Content*.config\\ai-guardian\\*",
        "*Clear-Content*ai-guardian.json*", "*Clear-Content*.ai-guardian.json*",
        "*Clear-Content*.config/ai-guardian/*", "*Clear-Content*.config\\ai-guardian\\*",
        "*Out-File*ai-guardian.json*", "*Out-File*.ai-guardian.json*",
        "*Out-File*.config/ai-guardian/*", "*Out-File*.config\\ai-guardian\\*",
        "*Copy-Item*ai-guardian.json*", "*Copy-Item*.ai-guardian.json*",
        "*Copy-Item*.config/ai-guardian/*", "*Copy-Item*.config\\ai-guardian\\*",

        # Protect ai-guardian cache (prevents cache poisoning)
        "*Remove-Item*.cache/ai-guardian/*", "*Remove-Item*.cache\\ai-guardian\\*",
        "*Move-Item*.cache/ai-guardian/*", "*Move-Item*.cache\\ai-guardian\\*",
        "*Set-Content*.cache/ai-guardian/*", "*Set-Content*.cache\\ai-guardian\\*",
        "*Clear-Content*.cache/ai-guardian/*", "*Clear-Content*.cache\\ai-guardian\\*",
        "*Out-File*.cache/ai-guardian/*", "*Out-File*.cache\\ai-guardian\\*",
        "*>*.cache/ai-guardian/*", "*>*.cache\\ai-guardian\\*",

        # Protect IDE hook files (Unix paths)
        "*Remove-Item*.claude/settings.json*", "*Remove-Item*.cursor/hooks.json*",
        "*Remove-Item*Claude/settings.json*", "*Remove-Item*Cursor/hooks.json*",
        "*Move-Item*.claude/settings.json*", "*Move-Item*.cursor/hooks.json*",
        "*Move-Item*Claude/settings.json*", "*Move-Item*Cursor/hooks.json*",
        "*Rename-Item*.claude/settings.json*", "*Rename-Item*.cursor/hooks.json*",
        "*Rename-Item*Claude/settings.json*", "*Rename-Item*Cursor/hooks.json*",
        "*Set-Content*.claude/settings.json*", "*Set-Content*.cursor/hooks.json*",
        "*Set-Content*Claude/settings.json*", "*Set-Content*Cursor/hooks.json*",
        "*Clear-Content*.claude/settings.json*", "*Clear-Content*.cursor/hooks.json*",
        "*Clear-Content*Claude/settings.json*", "*Clear-Content*Cursor/hooks.json*",
        "*Out-File*.claude/settings.json*", "*Out-File*.cursor/hooks.json*",
        "*Out-File*Claude/settings.json*", "*Out-File*Cursor/hooks.json*",

        # Protect IDE hook files (Windows backslash paths)
        "*Remove-Item*Claude\\settings.json*", "*Remove-Item*Cursor\\hooks.json*",
        "*Move-Item*Claude\\settings.json*", "*Move-Item*Cursor\\hooks.json*",
        "*Rename-Item*Claude\\settings.json*", "*Rename-Item*Cursor\\hooks.json*",
        "*Set-Content*Claude\\settings.json*", "*Set-Content*Cursor\\settings.json*",
        "*Clear-Content*Claude\\settings.json*", "*Clear-Content*Cursor\\hooks.json*",
        "*Out-File*Claude\\settings.json*", "*Out-File*Cursor\\hooks.json*",

        # Protect ai-guardian package source
        "*Remove-Item*site-packages/ai_guardian/*", "*Remove-Item*site-packages\\ai_guardian\\*",
        "*Remove-Item*ai-guardian/src/ai_guardian/*", "*Remove-Item*ai-guardian\\src\\ai_guardian\\*",
        "*Remove-Item*ai-guardian/ai_guardian/*", "*Remove-Item*ai-guardian\\ai_guardian\\*",
        "*Set-Content*site-packages/ai_guardian/*", "*Set-Content*site-packages\\ai_guardian\\*",
        "*Set-Content*ai-guardian/src/ai_guardian/*", "*Set-Content*ai-guardian\\src\\ai_guardian\\*",
        "*Set-Content*ai-guardian/ai_guardian/*", "*Set-Content*ai-guardian\\ai_guardian\\*",
        "*Clear-Content*site-packages/ai_guardian/*", "*Clear-Content*site-packages\\ai_guardian\\*",
        "*Clear-Content*ai-guardian/src/ai_guardian/*", "*Clear-Content*ai-guardian\\src\\ai_guardian\\*",
        "*Clear-Content*ai-guardian/ai_guardian/*", "*Clear-Content*ai-guardian\\ai_guardian\\*",
        "*Out-File*site-packages/ai_guardian/*", "*Out-File*site-packages\\ai_guardian\\*",
        "*Out-File*ai-guardian/src/ai_guardian/*", "*Out-File*ai-guardian\\src\\ai_guardian\\*",
        "*Out-File*ai-guardian/ai_guardian/*", "*Out-File*ai-guardian\\ai_guardian\\*",

        # Protect against PowerShell redirections - specific paths only
        "*>*ai-guardian.json*", "*>*.ai-guardian.json*",
        "*>*.config/ai-guardian/*", "*>*.config\\ai-guardian\\*",
        "*>>*ai-guardian.json*", "*>>*.ai-guardian.json*",
        "*>>*.config/ai-guardian/*", "*>>*.config\\ai-guardian\\*",
        "*>*.claude/settings.json*", "*>*.cursor/hooks.json*",
        "*>*Claude/settings.json*", "*>*Cursor/hooks.json*",

        # Protect .ai-read-deny marker files from PowerShell manipulation
        "*Remove-Item*.ai-read-deny*",
        "*Move-Item*.ai-read-deny*",
        "*Rename-Item*.ai-read-deny*",
        "*Set-Content*.ai-read-deny*",
        "*Clear-Content*.ai-read-deny*",
        "*Out-File*.ai-read-deny*",
        "*Copy-Item*.ai-read-deny*",
        "*>*.ai-read-deny*",

        # PowerShell aliases (del, erase, rm, mv, etc.) - specific paths only
        "*del *ai-guardian.json*", "*del *.ai-guardian.json*", "*del *.config/ai-guardian/*", "*del *.config\\ai-guardian\\*",
        "*erase *ai-guardian.json*", "*erase *.ai-guardian.json*", "*erase *.config/ai-guardian/*", "*erase *.config\\ai-guardian\\*",
        "*rm *ai-guardian.json*", "*rm *.ai-guardian.json*", "*rm *.config/ai-guardian/*", "*rm *.config\\ai-guardian\\*",
        "*rmdir *ai-guardian.json*", "*rmdir *.ai-guardian.json*", "*rmdir *.config/ai-guardian/*", "*rmdir *.config\\ai-guardian\\*",
        "*mv *ai-guardian.json*", "*mv *.ai-guardian.json*", "*mv *.config/ai-guardian/*", "*mv *.config\\ai-guardian\\*",
        "*move *ai-guardian.json*", "*move *.ai-guardian.json*", "*move *.config/ai-guardian/*", "*move *.config\\ai-guardian\\*",
        "*ren *ai-guardian.json*", "*ren *.ai-guardian.json*", "*ren *.config/ai-guardian/*", "*ren *.config\\ai-guardian\\*",
        "*copy *ai-guardian.json*", "*copy *.ai-guardian.json*", "*copy *.config/ai-guardian/*", "*copy *.config\\ai-guardian\\*",
        "*rm *.claude/settings.json*", "*del *.claude/settings.json*",
        "*rm *.cursor/hooks.json*", "*del *.cursor/hooks.json*",
        "*rm *.ai-read-deny*", "*del *.ai-read-deny*",
        "*mv *.ai-read-deny*", "*move *.ai-read-deny*",
    ]
}


def _strip_bash_heredoc_content(command: str) -> str:
    """
    Strip heredoc content from bash commands for pattern matching.

    This prevents false positives when heredoc content contains protected
    keywords or patterns. Only the command structure is checked, not the
    heredoc data.

    Supports heredoc formats:
    - <<EOF ... EOF
    - <<'EOF' ... EOF (quoted)
    - <<"EOF" ... EOF (quoted)
    - <<-EOF ... EOF (dash format for tab stripping)

    Args:
        command: The bash command string (may be multi-line)

    Returns:
        Command with heredoc content replaced by placeholders

    Example:
        Input:  cat <<'EOF'\\nrm ai-guardian.json\\nEOF
        Output: cat <<'EOF'\\nEOF
    """
    if not command or '<<' not in command:
        return command

    # Pattern to match heredoc start
    # Groups: (1) optional dash, (2) quote if quoted, (3) delimiter if quoted, (4) delimiter if unquoted
    # Updated to support hyphenated delimiters (e.g., END-OF-FILE, MY-DELIMITER)
    heredoc_start_pattern = re.compile(
        r"<<(-)?(?:(['\"])([\w-]+)\2|([\w-]+))",
        re.MULTILINE
    )

    # Find all heredocs and their positions
    replacements = []

    for match in heredoc_start_pattern.finditer(command):
        # Extract delimiter (group 3 if quoted, group 4 if unquoted)
        delimiter = match.group(3) if match.group(3) else match.group(4)
        heredoc_start = match.end()  # Position after the delimiter

        # Find the first newline after the heredoc delimiter
        # The heredoc content starts AFTER this newline (commands can follow on same line)
        first_newline = command.find('\n', heredoc_start)
        if first_newline == -1:
            # No newline found, no heredoc content to strip
            continue

        content_start = first_newline  # Position of the newline before content

        # Find the end delimiter (must be on its own line)
        # Pattern: newline + optional whitespace + delimiter + end of line
        end_pattern = re.compile(
            rf'\n\s*{re.escape(delimiter)}\s*(?=\n|$)',
            re.MULTILINE
        )

        end_match = end_pattern.search(command, content_start)
        if end_match:
            # Mark this range for removal (content between newlines)
            # Remove from after the first newline to before the delimiter newline
            replacements.append((content_start, end_match.start()))

    # Apply replacements in reverse order to maintain positions
    result = command
    for start, end in reversed(replacements):
        result = result[:start] + result[end:]

    return result


class ToolPolicyChecker:
    """
    Check if tool invocations are allowed based on matcher-based permissions.

    Permission format (array of rules):
    [
      {
        "matcher": "Skill",      # Tool name pattern to match
        "allow": ["daf-*"],      # Patterns to allow
        "deny": []               # Patterns to deny
      }
    ]

    Default: deny-wins (deny patterns override allow patterns)
    """

    # Class-level schema validator (loaded once and cached)
    _schema_validator = None

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize policy checker.

        Args:
            config: Optional configuration dict. If None, loads from disk.
        """
        self.config = config or self._load_config()

    def _should_skip_immutable_protection(self, file_path: str, tool_name: str) -> bool:
        """
        Check if immutable protection should be bypassed for this file.

        Bypass allows:
        - Editing source code files IN the ai-guardian development repository
        - Does NOT allow editing config files, hooks, or cache (NEVER bypassed)
        - Does NOT allow editing pip-installed packages (production code)

        Security model:
        - Config/hooks/cache: ALWAYS protected (even for repo owners)
        - Pip-installed code: ALWAYS protected (production deployment)
        - Development source: ALLOWED for contributors (fork + PR workflow)
          - Changes only affect local development environment
          - Relies on PR review process for security
          - Enables standard open-source contribution workflow

        Args:
            file_path: Path to the file being accessed
            tool_name: Name of the tool being used

        Returns:
            bool: True if bypass should apply, False otherwise
        """
        # PRIORITY 1: Config/hook/cache files - NEVER bypass (even for repo owners)
        config_patterns = [
            "*ai-guardian.json",           # Config files
            "*/.ai-guardian.json",         # Project config
            "*/.config/ai-guardian/*",     # Config directory
            "*/.cache/ai-guardian/*",      # Cache files (prevents poisoning)
            "*/.claude/settings.json",     # IDE hooks
            "*/.claude/hooks.json",
            "*/.cursor/hooks.json",
            "*/Claude/settings.json",      # Windows
            "*/Cursor/hooks.json",
            "*/.ai-read-deny",             # Directory markers
            "**/.ai-read-deny",
        ]

        file_path_obj = Path(file_path)
        for pattern in config_patterns:
            # Use Path.match() for ** patterns, fnmatch for simple * patterns
            if "**" in pattern:
                matches = file_path_obj.match(pattern)
            else:
                matches = fnmatch.fnmatch(file_path, pattern)

            if matches:
                logger.debug(f"Config file always protected: {file_path}")
                return False  # Always protected, even for repo owners

        # PRIORITY 2: Is this a source code file IN the ai-guardian development repo?
        # Only applies to file-path tools (Edit, Write, Read), NOT command tools (Bash, PowerShell)
        # Command tools are checked by immutable patterns to prevent rm/Remove-Item/etc.
        is_file_path_tool = tool_name in ["Edit", "Write", "Read", "NotebookEdit"]

        if not is_file_path_tool:
            logger.debug(f"Command tool {tool_name} - not checking source patterns")
            return False  # Command tools always check immutable patterns

        source_patterns = [
            "*/ai-guardian/src/ai_guardian/*",    # Source directory
            "*/ai-guardian/tests/*",               # Tests
            "*/ai-guardian/*.md",                  # Documentation
            "*/ai-guardian/*.py",                  # Root Python files
            "*/ai-guardian/*.toml",                # Config files like pyproject.toml
            "*/ai-guardian/*.txt",                 # Requirements, etc.
            "*/ai-guardian/.github/*",             # GitHub workflows
            "*/ai-guardian/CHANGELOG.md",          # Changelog
            "*/ai-guardian/RELEASING.md",          # Release docs
        ]

        is_source_file = any(fnmatch.fnmatch(file_path, p) for p in source_patterns)
        if not is_source_file:
            logger.debug(f"Not a source file: {file_path}")
            return False  # Not a source file, keep protected

        # PRIORITY 3: Allow editing development source code with file-path tools
        # This enables standard open-source workflow (fork + PR + review)
        # Security relies on:
        # - PR review process (maintainers review all changes)
        # - CI/CD testing (detects behavior changes)
        # - Public review (community scrutiny)
        # - Pip-installed code still protected (production deployments)
        logger.info(f"✅ Development source file: allowing {tool_name} on {file_path}")
        logger.info("   Note: Changes affect local development only, not pip-installed versions")
        return True

    def check_tool_allowed(self, hook_data: Dict) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check if a tool invocation is allowed.

        Args:
            hook_data: Hook data from PreToolUse event

        Returns:
            tuple: (is_allowed: bool, error_message: str or None, tool_name: str or None)
        """
        try:
            # Extract tool name and parameters
            tool_name, tool_input = self._extract_tool_info(hook_data)
            if not tool_name:
                logger.warning("Could not extract tool name from hook data")
                # Fail-closed: block if we can't determine the tool (security-critical path)
                return False, "Policy check error: unable to determine tool name", None

            logger.info(f"Checking if tool '{tool_name}' is allowed...")

            # PRIORITY 0: Check SSRF protection (before all other checks)
            # Prevents accessing private networks, metadata endpoints, and dangerous URL schemes
            if HAS_SSRF_PROTECTOR:
                ssrf_config = self.config.get("ssrf_protection", {})
                if ssrf_config.get("enabled", True):  # Enabled by default
                    ssrf_protector = SSRFProtector(ssrf_config)
                    should_block, error_msg = ssrf_protector.check(tool_name, tool_input)

                    if should_block:
                        # SSRF detected and blocked
                        logger.error(f"🚨 BLOCKED: {tool_name} - SSRF attack detected")
                        self._log_violation(
                            tool_name=tool_name,
                            check_value=tool_input.get("command", str(tool_input)),
                            reason="SSRF attack detected",
                            matcher=tool_name,
                            hook_data=hook_data
                        )
                        return False, error_msg, tool_name

                    elif error_msg:
                        # Warning mode - log but allow
                        logger.warning(f"SSRF warning for {tool_name}: {error_msg}")
                        self._log_violation(
                            tool_name=tool_name,
                            check_value=tool_input.get("command", str(tool_input)),
                            reason="SSRF warning (allowed)",
                            matcher=tool_name,
                            hook_data=hook_data
                        )
                        # Continue to other checks (warning is logged, execution allowed)

            # PRIORITY 1: Check immutable deny patterns (cannot be overridden)
            # These protect ai-guardian config, IDE hooks, and pip-installed package code
            # EXCEPT: Development source code can be edited (fork + PR workflow)
            check_value = self._extract_check_value(tool_name, tool_input, tool_name)

            # For file-path tools (Edit/Write/Read/NotebookEdit), require check_value
            # If we can't extract file_path, fail-closed to prevent bypass (Issue #113)
            is_file_path_tool = tool_name in ["Write", "Read", "Edit", "NotebookEdit"]
            if is_file_path_tool and not check_value:
                error_msg = (
                    f"\n{'='*70}\n"
                    f"🚨 BLOCKED BY POLICY\n"
                    f"{'='*70}\n"
                    f"Tool: {tool_name}\n"
                    f"Reason: Missing required parameter (file_path)\n"
                    f"\n"
                    f"File-path tools require a file_path parameter for security checks.\n"
                    f"This operation has been blocked to prevent bypassing immutable\n"
                    f"file protections.\n"
                    f"{'='*70}\n"
                )
                logger.error(f"🚨 BLOCKED: {tool_name} - missing file_path parameter")
                self._log_violation(
                    tool_name=tool_name,
                    check_value="<missing file_path>",
                    reason="missing required parameter",
                    matcher=tool_name,
                    hook_data=hook_data
                )
                return False, error_msg, tool_name

            if check_value:
                # Check if this is development source code (allowed for contributors)
                if self._should_skip_immutable_protection(check_value, tool_name):
                    logger.info(f"✅ Development source code: allowing {tool_name} on {check_value}")
                    return True, None, tool_name

                immutable_denies = IMMUTABLE_DENY_PATTERNS.get(tool_name, [])
                # Use Path.match() for file path tools with ** patterns, fnmatch otherwise
                is_file_path_tool = tool_name in ["Write", "Read", "Edit", "NotebookEdit"]
                for pattern in immutable_denies:
                    # For file path tools with ** patterns: use Path.match()
                    # Otherwise: use fnmatch to match patterns within command strings or simple globs
                    if is_file_path_tool and "**" in pattern:
                        matches = Path(check_value).match(pattern)
                    else:
                        matches = fnmatch.fnmatch(check_value, pattern)

                    if matches:
                        error_msg = self._format_immutable_deny_message(check_value, tool_name, pattern)
                        self._log_violation(
                            tool_name=tool_name,
                            check_value=check_value,
                            reason=f"immutable deny: {pattern}",
                            matcher=tool_name,
                            hook_data=hook_data
                        )
                        return False, error_msg, tool_name

            # PRIORITY 2: Check user-configured permissions
            # Find all matching permission rules
            permission_rules = self._find_permission_rules(tool_name)

            if not permission_rules:
                # No rules found - check if this tool type requires explicit allow
                if self._requires_explicit_allow(tool_name):
                    logger.warning(f"Tool '{tool_name}' requires explicit permission but no rule found")

                    # Check default action (block by default when no rules)
                    # For tools requiring explicit allow, we block by default
                    error_msg = self._format_deny_message(
                        tool_name,
                        "no permission rule",
                        None,
                        tool_value=check_value if check_value else tool_name
                    )

                    # Log violation
                    self._log_violation(
                        tool_name=tool_name,
                        check_value=check_value if check_value else tool_name,
                        reason="no permission rule",
                        matcher=tool_name,
                        hook_data=hook_data
                    )

                    return False, error_msg, tool_name

                # No rule and doesn't require explicit allow - allow by default
                logger.info(f"✓ Tool '{tool_name}' is allowed by default (no matching rule)")
                return True, None, tool_name

            # Extract the value to check against patterns
            check_value = self._extract_check_value(tool_name, tool_input, permission_rules[0]["matcher"])
            if check_value is None:
                logger.warning(f"Could not extract value to check for tool '{tool_name}'")
                return True, None, tool_name

            logger.debug(f"Checking value '{check_value}' against {len(permission_rules)} rule(s)")

            # First pass: check all deny rules (deny wins)
            for rule in permission_rules:
                mode = rule.get("mode")
                patterns = rule.get("patterns", [])
                action = rule.get("action", "block")  # Default to block

                # Legacy format support
                if mode is None:
                    patterns = rule.get("deny", [])
                    mode = "deny" if patterns else None

                if mode == "deny":
                    # Use Path.match() for file path tools with ** patterns, fnmatch otherwise
                    is_file_path_tool = tool_name in ["Write", "Read", "Edit", "NotebookEdit"]
                    for pattern_entry in patterns:
                        # Extract pattern string from entry (supports both str and dict formats)
                        pattern_str = self._extract_pattern_string(pattern_entry)
                        # For file path tools with ** patterns: use Path.match()
                        # Otherwise: use fnmatch to match patterns within command strings or simple globs
                        if is_file_path_tool and "**" in pattern_str:
                            matches = Path(check_value).match(pattern_str)
                        else:
                            matches = fnmatch.fnmatch(check_value, pattern_str)

                        if matches:
                            # Log violation
                            self._log_violation(
                                tool_name=tool_name,
                                check_value=check_value,
                                reason=f"matched deny pattern: {pattern_str}",
                                matcher=rule["matcher"],
                                hook_data=hook_data
                            )

                            # Check action
                            if action == "warn":
                                logger.warning(f"Policy violation (warn mode): {tool_name} - {pattern_str} - execution allowed")
                                # Continue execution - logged for audit
                                # Return warning message to display to user via systemMessage
                                display_name = self._format_tool_display_name(tool_name, tool_input)
                                warn_msg = f"⚠️  Policy violation (warn mode): {display_name} matched deny pattern - execution allowed"
                                return True, warn_msg, tool_name
                            elif action == "log-only":
                                logger.warning(f"Policy violation (log-only mode): {tool_name} - {pattern_str} - execution allowed (silent)")
                                # Continue execution - logged for audit, NO warning to user
                                return True, None, tool_name
                            else:
                                # Block execution
                                logger.error(f"Tool '{tool_name}' matched deny pattern: {pattern_str}")
                                error_msg = self._format_deny_message(
                                    tool_name,
                                    f"matched deny pattern: {pattern_str}",
                                    rule["matcher"],
                                    tool_value=check_value
                                )
                                return False, error_msg, tool_name

            # Second pass: check allow rules
            has_allow_rules = False
            for rule in permission_rules:
                mode = rule.get("mode")
                patterns = rule.get("patterns", [])

                # Legacy format support
                if mode is None:
                    patterns = rule.get("allow", [])
                    mode = "allow" if patterns else None

                if mode == "allow":
                    has_allow_rules = True
                    # Use Path.match() for file path tools with ** patterns, fnmatch otherwise
                    is_file_path_tool = tool_name in ["Write", "Read", "Edit", "NotebookEdit"]
                    for pattern_entry in patterns:
                        # Extract pattern string from entry (supports both str and dict formats)
                        pattern_str = self._extract_pattern_string(pattern_entry)
                        # For file path tools with ** patterns: use Path.match()
                        # Otherwise: use fnmatch to match patterns within command strings or simple globs
                        if is_file_path_tool and "**" in pattern_str:
                            matches = Path(check_value).match(pattern_str)
                        else:
                            matches = fnmatch.fnmatch(check_value, pattern_str)

                        if matches:
                            logger.info(f"✓ Tool '{tool_name}' matched allow pattern: {pattern_str}")
                            return True, None, tool_name

            # If we have allow rules but no match, deny (or warn)
            if has_allow_rules:
                # Format tool details for logging
                tool_details = self._format_tool_log_details(tool_name, tool_input)
                logger.warning(f"Tool '{tool_name}'{tool_details} not in allow list")

                # Check enforcement level from the first allow rule
                action = permission_rules[0].get("action", "block")

                # Log violation
                self._log_violation(
                    tool_name=tool_name,
                    check_value=check_value,
                    reason="not in allow list",
                    matcher=permission_rules[0]["matcher"],
                    hook_data=hook_data
                )

                # Check action
                if action == "warn":
                    logger.warning(f"Policy violation (warn mode): {tool_name}{tool_details} not in allow list - execution allowed")
                    # Continue execution - logged for audit
                    # Return warning message to display to user via systemMessage
                    display_name = self._format_tool_display_name(tool_name, tool_input)
                    warn_msg = f"⚠️  Policy violation (warn mode): {display_name} not in allow list - execution allowed"
                    return True, warn_msg, tool_name
                elif action == "log-only":
                    logger.warning(f"Policy violation (log-only mode): {tool_name}{tool_details} not in allow list - execution allowed (silent)")
                    # Continue execution - logged for audit, NO warning to user
                    return True, None, tool_name
                else:
                    # Block execution
                    logger.error(f"Tool '{tool_name}'{tool_details} not in allow list")
                    error_msg = self._format_deny_message(
                        tool_name,
                        "not in allow list",
                        permission_rules[0]["matcher"],
                        tool_value=check_value
                    )
                    return False, error_msg, tool_name

            # No allow rules - allow by default (already passed deny check)
            logger.info(f"✓ Tool '{tool_name}' is allowed (no allow patterns in rules)")
            return True, None, tool_name

        except Exception as e:
            logger.error(f"Error checking tool policy: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Fail-closed: block on errors (security-critical path)
            return False, f"Policy check error: {e}", None

    def _extract_tool_info(self, hook_data: Dict) -> Tuple[Optional[str], Dict]:
        """
        Extract tool name and input from hook data.

        Returns:
            tuple: (tool_name, tool_input)
        """
        try:
            tool_name = None
            tool_input = {}

            # Claude Code format: tool_use.name + tool_use.input or tool_use.parameters
            if "tool_use" in hook_data and isinstance(hook_data["tool_use"], dict):
                tool_name = hook_data["tool_use"].get("name")
                # Try both "input" (PostToolUse) and "parameters" (PreToolUse)
                tool_input = hook_data["tool_use"].get("input") or hook_data["tool_use"].get("parameters", {})
            # Cursor format: tool.name
            elif "tool" in hook_data and isinstance(hook_data["tool"], dict):
                tool_name = hook_data["tool"].get("name")
                tool_input = hook_data.get("tool_input", {})
            # GitHub Copilot format: toolName + toolArgs (JSON string)
            elif "toolName" in hook_data:
                tool_name = hook_data["toolName"]
                # toolArgs is a JSON string in Copilot format
                if "toolArgs" in hook_data:
                    try:
                        tool_input = json.loads(hook_data["toolArgs"])
                    except (json.JSONDecodeError, TypeError):
                        tool_input = {}
            # Alternative: direct tool_name field
            elif "tool_name" in hook_data:
                tool_name = hook_data["tool_name"]
                tool_input = hook_data.get("tool_input", {})

            return tool_name, tool_input

        except Exception as e:
            logger.error(f"Error extracting tool info: {e}")
            return None, {}

    def _sanitize_for_logging(self, text: str) -> str:
        """
        Sanitize text to prevent secrets from leaking in logs.

        Redacts common secret patterns:
        - API keys, tokens, passwords
        - Environment variable values
        - Long alphanumeric strings (potential tokens)
        - Base64-encoded credentials

        Args:
            text: The text to sanitize

        Returns:
            Sanitized text with secrets redacted
        """
        import re

        # Redact common secret patterns (case-insensitive)
        # Pattern: key=value or key='value' or key="value"
        secret_patterns = [
            (r'(api[_-]?key|apikey|token|password|passwd|pwd|secret|auth|authorization|bearer)\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?', r'\1=***REDACTED***'),
            # Environment variables with common secret names
            (r'(API_KEY|TOKEN|PASSWORD|SECRET|GITHUB_TOKEN|AWS_SECRET|OPENAI_API_KEY)=([^\s]{8,})', r'\1=***REDACTED***'),
            # Long alphanumeric strings (potential tokens) - 32+ chars
            (r'\b([a-zA-Z0-9]{32,})\b', r'***REDACTED-TOKEN***'),
            # Base64-encoded strings (potential credentials) - must be 24+ chars and end with padding or not
            (r'\b([A-Za-z0-9+/]{24,}={0,2})\b', r'***REDACTED-BASE64***'),
        ]

        sanitized = text
        for pattern, replacement in secret_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        return sanitized

    def _format_tool_log_details(self, tool_name: str, tool_input: Dict) -> str:
        """
        Format detailed tool parameters for logging (full details for debugging).

        IMPORTANT: Sanitizes output to prevent secrets from leaking in logs.

        Args:
            tool_name: The tool name
            tool_input: The tool input parameters

        Returns:
            Formatted details string for logging (e.g., " (skill='daf-jira', args='view AAP-12345')")
        """
        if not tool_input:
            return ""

        # For Skill tool: show skill name and args (sanitized)
        if tool_name == "Skill" and "skill" in tool_input:
            skill_name = tool_input.get("skill", "unknown")
            skill_args = tool_input.get("args", "")
            # Sanitize args before truncating
            sanitized_args = self._sanitize_for_logging(skill_args)
            args_preview = sanitized_args[:50] + "..." if len(sanitized_args) > 50 else sanitized_args
            return f" (skill='{skill_name}', args='{args_preview}')"

        # For Read/Write/Edit: show full file path (already safe)
        if tool_name in ["Read", "Write", "Edit"] and "file_path" in tool_input:
            file_path = tool_input["file_path"]
            return f" (file_path='{file_path}')"

        # For Bash: show command preview (sanitized, first 100 chars)
        if tool_name == "Bash" and "command" in tool_input:
            command = tool_input["command"]
            # Sanitize command before truncating
            sanitized_cmd = self._sanitize_for_logging(command)
            cmd_preview = sanitized_cmd[:100] + "..." if len(sanitized_cmd) > 100 else sanitized_cmd
            return f" (command='{cmd_preview}')"

        return ""

    def _format_tool_display_name(self, tool_name: str, tool_input: Dict) -> str:
        """
        Format a user-friendly display name for a tool with its key parameters.

        Args:
            tool_name: The tool name (e.g., "Skill", "Read", "Bash")
            tool_input: The tool input parameters

        Returns:
            Formatted display name (e.g., "Skill(database-migration)", "Read(file.txt)", "Bash(ls -la)")
        """
        if not tool_input:
            return tool_name

        # For Skill tool: show skill name
        if tool_name == "Skill" and "skill" in tool_input:
            return f"Skill({tool_input['skill']})"

        # For Read/Write/Edit: show file path (basename only for brevity)
        if tool_name in ["Read", "Write", "Edit"] and "file_path" in tool_input:
            import os
            file_path = tool_input["file_path"]
            basename = os.path.basename(file_path) if file_path else "unknown"
            return f"{tool_name}({basename})"

        # For Bash: show first 40 chars of command
        if tool_name == "Bash" and "command" in tool_input:
            command = tool_input["command"]
            if len(command) > 40:
                command = command[:37] + "..."
            return f"Bash({command})"

        # For MCP tools: already have descriptive names like "mcp__server__tool"
        # Just return as-is
        return tool_name

    def _extract_pattern_string(self, pattern_entry: Union[str, Dict]) -> str:
        """
        Extract the pattern string from a pattern entry.

        Args:
            pattern_entry: Either a string pattern or dict with 'pattern' field

        Returns:
            str: The pattern string

        Examples:
            >>> self._extract_pattern_string("daf-*")
            "daf-*"

            >>> self._extract_pattern_string({"pattern": "debug-*", "valid_until": "2026-04-13T12:00:00Z"})
            "debug-*"
        """
        if isinstance(pattern_entry, str):
            return pattern_entry
        elif isinstance(pattern_entry, dict) and "pattern" in pattern_entry:
            return pattern_entry["pattern"]
        else:
            # Fallback - return string representation
            return str(pattern_entry)

    def _is_pattern_valid(self, pattern_entry: Union[str, Dict], current_time: Optional[datetime] = None) -> bool:
        """
        Check if a pattern entry is still valid (not expired).

        Supports both simple format (string) and extended format (dict with valid_until).

        Args:
            pattern_entry: Either a string pattern or dict with 'pattern' and 'valid_until'
            current_time: Optional current time for testing (defaults to now in UTC)

        Returns:
            bool: True if pattern is valid, False if expired

        Examples:
            >>> self._is_pattern_valid("daf-*")
            True

            >>> self._is_pattern_valid({"pattern": "debug-*", "valid_until": "2099-12-31T23:59:59Z"})
            True

            >>> self._is_pattern_valid({"pattern": "temp-*", "valid_until": "2020-01-01T00:00:00Z"})
            False
        """
        # Simple format (string) - never expires
        if isinstance(pattern_entry, str):
            return True

        # Extended format (dict) - check for valid_until field
        if isinstance(pattern_entry, dict):
            # No valid_until field - treat as non-expiring
            if "valid_until" not in pattern_entry:
                return True

            valid_until = pattern_entry.get("valid_until")
            if not valid_until:
                return True

            # Check if expired
            return not is_expired(valid_until, current_time)

        # Unknown format - treat as valid (fail-safe)
        logger.warning(f"Unknown pattern entry format: {type(pattern_entry)}")
        return True

    def _filter_valid_patterns(self, patterns: List[Union[str, Dict]], current_time: Optional[datetime] = None) -> List[Union[str, Dict]]:
        """
        Filter out expired patterns from a list.

        Args:
            patterns: List of pattern entries (strings or dicts)
            current_time: Optional current time for testing

        Returns:
            list: Filtered list with only valid (non-expired) patterns
        """
        valid_patterns = []
        for pattern_entry in patterns:
            if self._is_pattern_valid(pattern_entry, current_time):
                valid_patterns.append(pattern_entry)
            else:
                # Log when we skip an expired pattern
                pattern_str = pattern_entry.get("pattern") if isinstance(pattern_entry, dict) else str(pattern_entry)
                valid_until = pattern_entry.get("valid_until") if isinstance(pattern_entry, dict) else None
                logger.info(f"Skipping expired pattern '{pattern_str}' (expired: {valid_until})")

        return valid_patterns

    def _find_permission_rules(self, tool_name: str) -> List[Dict]:
        """
        Find all permission rules that match the tool name.

        Filters out expired patterns from the rules.

        Args:
            tool_name: Name of the tool (e.g., "Skill", "mcp__notebooklm__notebook_list")

        Returns:
            list: List of matching permission rules (may be empty)
        """
        permissions = self.config.get("permissions", {})

        # New unified format: object with enabled, immutable, rules
        if isinstance(permissions, dict):
            rules = permissions.get("rules", [])
        # Legacy format: array of rules directly (pre-v1.4.0)
        elif isinstance(permissions, list):
            logger.debug("Legacy permissions format detected (array) - consider updating to new structure")
            rules = permissions
        else:
            logger.warning(f"Invalid permissions format: {type(permissions)}")
            return []

        if not isinstance(rules, list):
            logger.warning(f"Invalid permissions.rules format: {type(rules)}")
            return []

        matching_rules = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue

            matcher = rule.get("matcher")
            if not matcher:
                continue

            # Check if tool_name matches the matcher pattern
            if fnmatch.fnmatch(tool_name, matcher):
                logger.debug(f"Found matching rule: {matcher}")

                # Filter expired patterns from the rule
                filtered_rule = rule.copy()
                if "patterns" in filtered_rule:
                    filtered_rule["patterns"] = self._filter_valid_patterns(filtered_rule["patterns"])

                # Legacy format support - filter allow/deny lists
                if "allow" in filtered_rule:
                    filtered_rule["allow"] = self._filter_valid_patterns(filtered_rule["allow"])
                if "deny" in filtered_rule:
                    filtered_rule["deny"] = self._filter_valid_patterns(filtered_rule["deny"])

                matching_rules.append(filtered_rule)

        return matching_rules

    def _extract_check_value(self, tool_name: str, tool_input: Dict, matcher: str) -> Optional[str]:
        """
        Extract the value to check against allow/deny patterns.

        Args:
            tool_name: Name of the tool
            tool_input: Tool input parameters
            matcher: The matcher pattern from the permission rule

        Returns:
            str or None: Value to check
        """
        # Skill: extract skill name from input
        if matcher == "Skill" or tool_name == "Skill":
            skill = tool_input.get("skill")
            return skill if skill else None

        # Bash/Shell/PowerShell: extract command from input
        if matcher == "Bash" or matcher == "Shell" or matcher == "PowerShell":
            command = tool_input.get("command")
            if not command:
                return None
            # For Bash/Shell, strip heredoc content to avoid false positives
            # PowerShell doesn't use heredocs, so we skip this for PowerShell
            if matcher in ["Bash", "Shell"]:
                return _strip_bash_heredoc_content(command)
            return command

        # Write: extract file_path from input
        if matcher == "Write":
            file_path = tool_input.get("file_path")
            return file_path if file_path else None

        # Read: extract file_path from input
        if matcher == "Read":
            file_path = tool_input.get("file_path")
            return file_path if file_path else None

        # Edit: extract file_path from input
        if matcher == "Edit":
            file_path = tool_input.get("file_path")
            return file_path if file_path else None

        # NotebookEdit: extract file_path from input
        if matcher == "NotebookEdit":
            file_path = tool_input.get("file_path")
            return file_path if file_path else None

        # MCP and other tools: use tool_name directly
        return tool_name

    def _requires_explicit_allow(self, tool_name: str) -> bool:
        """
        Check if a tool requires explicit allow list entry.

        Skills and MCP tools require explicit approval.
        Built-in tools are allowed by default.

        Args:
            tool_name: Name of the tool

        Returns:
            bool: True if requires explicit allow
        """
        # Skills require explicit allow
        if tool_name == "Skill":
            return True

        # MCP tools require explicit allow
        if tool_name.startswith("mcp__"):
            return True

        # Built-in tools allowed by default
        return False

    def _format_deny_message(self, tool_name: str, reason: str, matcher: Optional[str], tool_value: Optional[str] = None) -> str:
        """
        Format error message for denied tools.

        Args:
            tool_name: Name of the denied tool
            reason: Reason for denial (pattern that blocked it)
            matcher: The matcher from the permission rule (if found)
            tool_value: The specific value that was checked (e.g., skill name, file path)

        Returns:
            str: Formatted error message
        """
        # Generate suggested configuration
        suggested_matcher, suggested_patterns = self._suggest_permission_rule(tool_name)

        config_path = "~/.config/ai-guardian/ai-guardian.json"

        msg = (
            f"\n{'='*70}\n"
            f"🚨 BLOCKED BY POLICY\n"
            f"🚫 TOOL ACCESS DENIED\n"
            f"{'='*70}\n\n"
            f"Tool: {tool_name}\n"
        )

        # Show the specific value that was blocked (if available)
        if tool_value:
            # Determine the label based on tool type
            if tool_name == "Skill":
                label = "Skill Name"
            elif matcher == "Edit" or matcher == "Read" or matcher == "Write":
                label = "File Path"
            else:
                label = "Value"
            msg += f"{label}: {tool_value}\n"

        msg += f"Blocked by: {reason}\n"

        # Show matcher if available
        if matcher:
            msg += f"Matcher: {matcher}\n"

        msg += f"\nTo allow this tool, add to {config_path}:\n\n"

        # Show suggested configuration
        msg += '  {\n'
        msg += '    "permissions": [\n'
        msg += '      {\n'
        msg += f'        "matcher": "{suggested_matcher}",\n'
        msg += '        "mode": "allow",\n'
        msg += '        "patterns": [\n'

        # Show patterns with comments
        for i, pattern in enumerate(suggested_patterns):
            if i == 0:
                msg += f'          "{pattern["pattern"]}"  # {pattern["comment"]}\n'
            else:
                msg += f'          # "{pattern["pattern"]}"  # {pattern["comment"]}\n'

        msg += '        ]\n'
        msg += '      }\n'
        msg += '    ]\n'
        msg += '  }\n\n'
        msg += "Or ask your administrator to update the enterprise policy.\n\n"
        msg += "This permission rule is configured to protect your system.\n"
        msg += "DO NOT attempt workarounds - contact the system administrator if access is needed.\n"
        msg += f"{'='*70}\n"

        return msg


    def _format_immutable_deny_message(self, check_value: str, tool_name: str, matched_pattern: str = None) -> str:
        """
        Format error message for immutable deny (cannot be overridden).

        Args:
            check_value: The value that was blocked (file path, command, etc.)
            tool_name: The tool that was blocked
            matched_pattern: The specific immutable pattern that triggered the block

        Returns:
            str: Formatted error message
        """
        # Determine the appropriate label based on tool type
        if tool_name == "Bash":
            value_label = "Command"
            protection_context = "command pattern"
        elif tool_name == "Skill":
            value_label = "Skill"
            protection_context = "skill name"
        elif tool_name.startswith("mcp__"):
            value_label = "MCP Tool"
            protection_context = "tool name"
        else:
            value_label = "File"
            protection_context = "file path"

        # First, check if this is a config file (these are NEVER source files)
        config_patterns = [
            "*ai-guardian.json",
            "*/.ai-guardian.json",
            "*/.config/ai-guardian/*",
            "*/.cache/ai-guardian/*",
            "*/.claude/settings.json",
            "*/.claude/hooks.json",
            "*/.cursor/hooks.json",
            "*/Claude/settings.json",
            "*/Cursor/hooks.json",
        ]
        is_config_file = any(fnmatch.fnmatch(check_value, p) for p in config_patterns)

        # Check if this is ai-guardian source code (development or pip-installed)
        # ONLY if it's NOT a config file
        source_patterns = [
            # Development repository patterns
            "*/ai-guardian/src/ai_guardian/*",
            "*/ai-guardian/tests/*",
            "*/ai-guardian/*.md",
            "*/ai-guardian/*.py",
            "*/ai-guardian/*.toml",
            "*/ai-guardian/*.txt",
            "*/ai-guardian/.github/*",
            # Pip-installed package patterns
            "*/site-packages/ai_guardian/*",
        ]
        is_source_file = (not is_config_file) and any(fnmatch.fnmatch(check_value, p) for p in source_patterns)

        # Check if this is a .ai-read-deny marker file
        is_marker_file = (check_value.endswith('.ai-read-deny') or
                         '/.ai-read-deny' in check_value or
                         '\\.ai-read-deny' in check_value or
                         '.ai-read-deny' in check_value)

        # Check if this looks like documentation/discussion vs. actual config
        is_likely_documentation = (
            check_value.endswith('.md') or
            check_value.endswith('.txt') or
            '/docs/' in check_value or
            '/documentation/' in check_value or
            'README' in check_value.upper()
        )

        # Format base message with appropriate label
        if tool_name == "Bash":
            base_message = (
                f"\n{'='*70}\n"
                f"🚨 BLOCKED BY POLICY\n"
                f"🔒 CRITICAL COMMAND BLOCKED\n"
                f"{'='*70}\n\n"
                f"This command matches a protected pattern and cannot be executed.\n\n"
                f"{value_label}: {check_value}\n"
                f"Tool: {tool_name}\n"
            )
            if matched_pattern:
                base_message += f"Triggered Pattern: {matched_pattern}\n"
        else:
            base_message = (
                f"\n{'='*70}\n"
                f"🚨 BLOCKED BY POLICY\n"
                f"🔒 CRITICAL FILE PROTECTED\n"
                f"{'='*70}\n\n"
                f"This file is protected by ai-guardian and cannot be modified.\n\n"
                f"{value_label}: {check_value}\n"
                f"Tool: {tool_name}\n"
            )
            if matched_pattern:
                base_message += f"Triggered Pattern: {matched_pattern}\n"

        # Add diagnostic information for source files
        # Note: This should only be reached for pip-installed code (site-packages),
        # since development repo source files are allowed via _should_skip_immutable_protection
        if is_source_file:
            return base_message + (
                f"\nProtection Type: Pip-installed package source code (production deployment)\n\n"
                f"This file is part of the pip-installed ai-guardian package and cannot\n"
                f"be modified to prevent bypassing security controls in production.\n\n"
                f"If you're developing ai-guardian:\n"
                f"  1. Clone the repository: git clone https://github.com/itdove/ai-guardian\n"
                f"  2. Install in development mode: pip install -e .\n"
                f"  3. Edit source files in the cloned repository\n\n"
                f"Development source files CAN be edited - this protection only applies\n"
                f"to pip-installed production code.\n"
                f"{'='*70}\n"
            )

        # Add workaround tip if this looks like documentation mentioning the tool
        tip_message = ""
        check_value_lower = check_value.lower()
        mentions_tool = 'ai-guardian' in check_value_lower or 'ai_guardian' in check_value_lower
        if is_likely_documentation and mentions_tool:
            tip_message = (
                f"\n💡 TIP: If you're trying to write ABOUT the tool (not modify it):\n"
                f"   Use \"ai - guardian\" (with spaces) in your text to avoid triggering\n"
                f"   protection patterns. Example: \"The ai - guardian tool protects...\"\n"
                f"   \n"
                f"   This works because protection patterns look for \"ai-guardian\"\n"
                f"   (with hyphen, no spaces), not \"ai - guardian\" (with spaces).\n"
            )

        if is_marker_file:
            return base_message + tip_message + (
                f"\nProtection Type: Directory protection marker\n\n"
                f"Protected files:\n"
                f"  • ai-guardian configuration files\n"
                f"  • IDE hook configuration (Claude, Cursor)\n"
                f"  • ai-guardian package source code\n"
                f"  • .ai-read-deny marker files (directory protection)\n\n"
                f"This protection cannot be disabled via configuration.\n"
                f"It ensures directory protection cannot be bypassed by AI agents.\n\n"
                f"DO NOT attempt workarounds - the protection is intentional.\n\n"
                f"To remove directory protection, delete .ai-read-deny manually.\n"
                f"\n{'='*70}\n"
            )
        else:
            return base_message + tip_message + (
                f"\nProtection Type: Immutable file protection\n\n"
                f"Protected files:\n"
                f"  • ai-guardian configuration files\n"
                f"  • IDE hook configuration (Claude, Cursor)\n"
                f"  • ai-guardian package source code\n"
                f"  • .ai-read-deny marker files (directory protection)\n\n"
                f"This protection cannot be disabled via configuration.\n"
                f"It ensures ai-guardian cannot be bypassed by AI agents.\n\n"
                f"DO NOT attempt workarounds - the protection is intentional.\n\n"
                f"To edit these files, use your text editor manually.\n"
                f"\n{'='*70}\n"
            )

    def _suggest_permission_rule(self, tool_name: str) -> Tuple[str, List[Dict]]:
        """
        Suggest permission rule for a blocked tool.

        Args:
            tool_name: The blocked tool name

        Returns:
            tuple: (matcher, list of {pattern, comment} dicts)
        """
        # Skills
        if tool_name == "Skill":
            return "Skill", [
                {"pattern": "*", "comment": "Allow all skills"},
            ]

        # MCP tools
        if tool_name.startswith("mcp__"):
            parts = tool_name.split("__")
            patterns = [
                {"pattern": tool_name, "comment": "Allow only this tool"}
            ]
            if len(parts) >= 3:
                patterns.append({
                    "pattern": f"{parts[0]}__{parts[1]}__*",
                    "comment": "Or allow all tools from this server"
                })
            return "mcp__*", patterns

        # Other tools
        return tool_name, [
            {"pattern": "*", "comment": f"Allow all {tool_name} operations"}
        ]

    def _log_violation(
        self,
        tool_name: str,
        check_value: str,
        reason: str,
        matcher: str,
        hook_data: Dict
    ):
        """
        Log a tool permission violation.

        Args:
            tool_name: Name of the blocked tool
            check_value: Value that was checked against patterns
            reason: Reason for blocking
            matcher: Matcher pattern from the permission rule
            hook_data: Original hook data for context
        """
        if not HAS_VIOLATION_LOGGER:
            return

        try:
            # Detect IDE type from hook data
            ide_type = self._detect_ide_type(hook_data)

            # Generate suggested rule
            suggested_matcher, suggested_patterns = self._suggest_permission_rule(tool_name)

            # Create violation logger
            violation_logger = ViolationLogger()

            # Log the violation
            violation_logger.log_violation(
                violation_type="tool_permission",
                blocked={
                    "tool_name": tool_name,
                    "tool_value": check_value,
                    "matcher": matcher,
                    "reason": reason
                },
                context={
                    "ide_type": ide_type,
                    "hook_event": hook_data.get("hook_event_name"),
                    "project_path": os.getcwd()
                },
                suggestion={
                    "action": "add_allow_pattern",
                    "config_path": str(get_config_dir() / "ai-guardian.json"),
                    "rule": {
                        "matcher": suggested_matcher,
                        "mode": "allow",
                        "patterns": [p["pattern"] for p in suggested_patterns]
                    }
                },
                severity="warning"
            )

        except Exception as e:
            logger.debug(f"Failed to log violation: {e}")

    def _detect_ide_type(self, hook_data: Dict) -> str:
        """
        Detect IDE type from hook data.

        Args:
            hook_data: Hook data from PreToolUse event

        Returns:
            str: IDE type (claude_code, cursor, github_copilot, unknown)
        """
        # Check for environment variable override
        ide_override = os.environ.get("AI_GUARDIAN_IDE_TYPE", "").lower()
        if ide_override:
            return ide_override

        # GitHub Copilot detection
        if "toolName" in hook_data or ("timestamp" in hook_data and "cwd" in hook_data):
            return "github_copilot"

        # Cursor detection
        if "cursor_version" in hook_data or "hook_name" in hook_data:
            return "cursor"

        # Claude Code detection
        if "hook_event_name" in hook_data and hook_data.get("hook_event_name") in ["UserPromptSubmit", "PreToolUse"]:
            return "claude_code"

        return "unknown"

    def _load_config(self) -> Dict:
        """
        Load and merge tool policy configurations.

        Priority (highest to lowest):
        1. Remote configs (from remote_configs URLs)
        2. User global config
        3. Project local config
        4. Defaults

        Immutability enforcement:
        - Remote configs can mark sections/matchers as immutable
        - Local/user configs cannot override immutable sections or add rules for immutable matchers

        Returns:
            dict: Merged configuration
        """
        # Start with defaults
        config = self._get_defaults()

        # Load all configs first
        local_config, local_config_path = self._load_local_config()
        user_config, user_config_path = self._load_user_config()
        remote_configs = self._load_remote_configs(local_config, local_config_path, user_config, user_config_path)

        # Extract immutability constraints from remote configs
        immutable_matchers = self._get_immutable_matchers(remote_configs)
        immutable_sections = self._get_immutable_sections(remote_configs)

        # Merge project local config (with immutability filtering)
        if local_config:
            config = self._merge_configs(config, local_config, immutable_matchers, immutable_sections)

        # Merge user global config (with immutability filtering)
        if user_config:
            config = self._merge_configs(config, user_config, immutable_matchers, immutable_sections)

        # Merge remote configs (highest priority, no filtering needed)
        for remote_config in remote_configs:
            config = self._merge_configs(config, remote_config, set(), set())

        # Discover and add patterns from permissions_directories
        self._discover_from_directories(config)

        return config

    def _get_immutable_matchers(self, remote_configs: List[Dict]) -> Set[str]:
        """
        Extract set of matchers marked as immutable in remote configs.

        Args:
            remote_configs: List of remote configuration dictionaries

        Returns:
            set: Set of matcher names that are immutable (e.g., {"Skill", "Bash"})
        """
        immutable_matchers = set()

        for remote_config in remote_configs:
            permissions = remote_config.get("permissions", [])
            # Handle new unified structure (permissions is an object with rules)
            if isinstance(permissions, dict):
                rules = permissions.get("rules", [])
            else:
                # Legacy format (permissions is an array)
                rules = permissions

            for rule in rules:
                if rule.get("immutable", False):
                    matcher = rule.get("matcher")
                    if matcher:
                        immutable_matchers.add(matcher)
                        logger.debug(f"Matcher '{matcher}' marked as immutable in remote config")

        return immutable_matchers

    def _get_immutable_sections(self, remote_configs: List[Dict]) -> Set[str]:
        """
        Extract set of section names marked as immutable in remote configs.

        Args:
            remote_configs: List of remote configuration dictionaries

        Returns:
            set: Set of section names that are immutable (e.g., {"prompt_injection", "pattern_server"})
        """
        immutable_sections = set()

        # Sections that can be marked as immutable
        section_names = [
            "prompt_injection",
            "pattern_server",
            "secret_scanning",
            "directory_exclusions",
            "permissions"
        ]

        for remote_config in remote_configs:
            for section_name in section_names:
                section = remote_config.get(section_name)
                if isinstance(section, dict) and section.get("immutable", False):
                    immutable_sections.add(section_name)
                    logger.debug(f"Section '{section_name}' marked as immutable in remote config")

        return immutable_sections

    def _get_defaults(self) -> Dict:
        """Get default empty configuration."""
        return {
            "permissions": {
                "enabled": True,
                "immutable": False,
                "rules": []
            },
            "permissions_directories": {
                "deny": [],
                "allow": []
            },
            "remote_configs": [],
            "directory_exclusions": {
                "enabled": False,
                "paths": []
            }
        }

    def _load_local_config(self) -> Tuple[Optional[Dict], Optional[Path]]:
        """Load project local configuration from ai-guardian.json."""
        # Try to get project path from environment (Cursor might set this)
        project_path = os.environ.get("CURSOR_PROJECT_PATH") or os.environ.get("VSCODE_CWD")

        if project_path:
            logger.debug(f"Using project path from environment: {project_path}")
            config_path = Path(project_path) / "ai-guardian.json"
        else:
            config_path = Path.cwd() / "ai-guardian.json"
            logger.debug(f"Using current working directory: {Path.cwd()}")

        config = self._load_json_file(config_path, "project local")
        return config, config_path if config else None

    def _load_user_config(self) -> Tuple[Optional[Dict], Optional[Path]]:
        """Load user global configuration from ai-guardian config directory."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"
        config = self._load_json_file(config_path, "user global")
        return config, config_path if config else None

    @classmethod
    def _get_schema_validator(cls):
        """
        Get or create the JSON Schema validator (cached).

        Returns:
            Draft7Validator or None: Validator instance or None if jsonschema not available
        """
        if not HAS_JSONSCHEMA:
            return None

        if cls._schema_validator is None:
            try:
                # Load schema from package
                schema_path = Path(__file__).parent / "schemas" / "ai-guardian-config.schema.json"
                with open(schema_path, 'r') as f:
                    schema = json.load(f)

                # Create and cache validator
                cls._schema_validator = Draft7Validator(schema)
                logger.debug("JSON Schema validator loaded and cached")
            except Exception as e:
                logger.warning(f"Failed to load JSON Schema: {e}")
                return None

        return cls._schema_validator

    def _validate_config(self, config: Dict, source_name: str, path: Path) -> bool:
        """
        Validate configuration against JSON Schema.

        Args:
            config: Configuration dictionary to validate
            source_name: Human-readable source name for error messages
            path: Path to config file (for error messages)

        Returns:
            bool: True if valid (or validation skipped), False if invalid
        """
        validator = self._get_schema_validator()
        if not validator:
            # jsonschema not available or schema failed to load
            # Continue without validation (backwards compatible)
            return True

        try:
            validator.validate(config)
            logger.debug(f"{source_name} config passed schema validation")
            return True
        except JsonSchemaValidationError as e:
            # Format user-friendly error message
            error_path = " -> ".join(str(p) for p in e.absolute_path) if e.absolute_path else "root"
            error_msg = (
                f"\n{'='*70}\n"
                f"❌ CONFIGURATION ERROR: {source_name} config at {path}\n"
                f"{'='*70}\n"
                f"Location: {error_path}\n"
                f"Error: {e.message}\n"
                f"\n"
                f"Please fix the configuration file and try again.\n"
                f"See: https://github.com/itdove/ai-guardian#configuration\n"
                f"{'='*70}\n"
            )
            # Print to stderr so user sees it (logger might not be visible in all IDEs)
            print(error_msg, flush=True)
            return False

    def _load_json_file(self, path: Path, source_name: str) -> Optional[Dict]:
        """
        Load and parse a JSON configuration file.

        Args:
            path: Path to JSON file
            source_name: Human-readable source name for logging

        Returns:
            dict or None: Parsed JSON config or None if error/not found
        """
        try:
            if not path.exists():
                logger.debug(f"No {source_name} config found at {path}")
                return None

            logger.info(f"Loading {source_name} config from {path}")
            with open(path, 'r') as f:
                config = json.load(f)

            logger.debug(f"Loaded {source_name} config: {config}")

            # Validate against JSON Schema
            if not self._validate_config(config, source_name, path):
                # Validation failed - return None to block operation
                logger.error(f"Schema validation failed for {source_name} config")
                return None

            return config

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in {source_name} config at {path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error loading {source_name} config from {path}: {e}")
            return None

    def _merge_configs(
        self,
        base: Dict,
        override: Dict,
        immutable_matchers: Optional[Set[str]] = None,
        immutable_sections: Optional[Set[str]] = None
    ) -> Dict:
        """
        Merge two configuration dictionaries with immutability enforcement.

        For permissions array: concatenate (filtering immutable matchers)
        For other lists: concatenate
        For dicts: recursively merge
        For immutable sections: skip override entirely

        Args:
            base: Base configuration
            override: Override configuration (higher priority)
            immutable_matchers: Set of matchers that cannot be overridden (e.g., {"Skill", "Bash"})
            immutable_sections: Set of sections that cannot be overridden (e.g., {"prompt_injection"})

        Returns:
            dict: Merged configuration
        """
        if immutable_matchers is None:
            immutable_matchers = set()
        if immutable_sections is None:
            immutable_sections = set()

        result = base.copy()

        for key, value in override.items():
            # Skip immutable sections entirely
            if key in immutable_sections:
                logger.info(f"Skipping override of immutable section: {key}")
                continue

            if key == "permissions":
                # Special handling for permissions object with immutability filtering
                if isinstance(value, dict):
                    # New unified format: permissions is an object with enabled, immutable, rules
                    base_permissions = result.get(key, {})
                    if not isinstance(base_permissions, dict):
                        base_permissions = {"enabled": True, "immutable": False, "rules": []}

                    # Merge the object
                    merged_permissions = base_permissions.copy()

                    # Merge enabled field (if not immutable at section level)
                    if "enabled" in value and key not in immutable_sections:
                        merged_permissions["enabled"] = value["enabled"]

                    # Merge immutable field (always take from override)
                    if "immutable" in value:
                        merged_permissions["immutable"] = value["immutable"]

                    # Merge rules array with matcher-level immutability filtering
                    if "rules" in value:
                        override_rules = value["rules"]
                        if isinstance(override_rules, list):
                            # Filter out rules for immutable matchers
                            filtered_rules = []
                            for rule in override_rules:
                                matcher = rule.get("matcher")
                                if matcher in immutable_matchers:
                                    logger.info(f"Skipping override for immutable matcher: {matcher}")
                                else:
                                    filtered_rules.append(rule)

                            # Concatenate with existing rules
                            existing_rules = merged_permissions.get("rules", [])
                            if isinstance(existing_rules, list):
                                merged_permissions["rules"] = existing_rules + filtered_rules
                            else:
                                merged_permissions["rules"] = filtered_rules

                    result[key] = merged_permissions
                elif isinstance(value, list):
                    # Legacy format: permissions is array of rules directly (pre-v1.4.0)
                    logger.debug("Legacy permissions array format in override - converting to new structure")
                    # Filter out rules for immutable matchers
                    filtered_rules = []
                    for rule in value:
                        matcher = rule.get("matcher")
                        if matcher in immutable_matchers:
                            logger.info(f"Skipping override for immutable matcher: {matcher}")
                        else:
                            filtered_rules.append(rule)

                    # If base is new format (dict), merge into rules
                    if isinstance(result.get(key), dict):
                        base_permissions = result[key]
                        existing_rules = base_permissions.get("rules", [])
                        if isinstance(existing_rules, list):
                            base_permissions["rules"] = existing_rules + filtered_rules
                        else:
                            base_permissions["rules"] = filtered_rules
                        result[key] = base_permissions
                    # If base is also legacy format (list), just concatenate
                    elif isinstance(result.get(key), list):
                        result[key] = result[key] + filtered_rules
                    else:
                        # Base is missing or invalid - create new structure
                        result[key] = {"enabled": True, "immutable": False, "rules": filtered_rules}
                else:
                    result[key] = value
            elif key in result:
                # If both are lists, concatenate
                if isinstance(result[key], list) and isinstance(value, list):
                    result[key] = result[key] + value
                # If both are dicts, recursively merge (pass through immutability for nested merges)
                elif isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = self._merge_configs(result[key], value, set(), set())
                # Otherwise, override replaces base
                else:
                    result[key] = value
            else:
                result[key] = value

        return result

    def _load_remote_configs(
        self,
        local_config: Optional[Dict],
        local_config_path: Optional[Path],
        user_config: Optional[Dict],
        user_config_path: Optional[Path]
    ) -> List[Dict]:
        """Load remote configurations from URLs."""
        remote_configs = []

        # Collect remote URLs from both configs
        remote_entries = []

        if local_config and "remote_configs" in local_config:
            # Handle both formats: dict with urls key (new) or direct list (old)
            remote_config_data = local_config["remote_configs"]
            if isinstance(remote_config_data, dict):
                # New format: {"urls": [...], "refresh_interval_hours": 12, ...}
                urls = remote_config_data.get("urls", [])
                for entry in urls:
                    remote_entries.append((entry, local_config_path))
            else:
                # Old format: direct list
                for entry in remote_config_data:
                    remote_entries.append((entry, local_config_path))

        if user_config and "remote_configs" in user_config:
            # Handle both formats: dict with urls key (new) or direct list (old)
            remote_config_data = user_config["remote_configs"]
            if isinstance(remote_config_data, dict):
                # New format: {"urls": [...], "refresh_interval_hours": 12, ...}
                urls = remote_config_data.get("urls", [])
                for entry in urls:
                    remote_entries.append((entry, user_config_path))
            else:
                # Old format: direct list
                for entry in remote_config_data:
                    remote_entries.append((entry, user_config_path))

        # Load each remote config
        for entry, base_path in remote_entries:
            try:
                # Parse entry (string or dict with token_env)
                if isinstance(entry, str):
                    url = entry
                    token_env = None
                elif isinstance(entry, dict):
                    url = entry.get("url")
                    token_env = entry.get("token_env")
                else:
                    logger.warning(f"Invalid remote_configs entry: {entry}")
                    continue

                if not url:
                    continue

                config = self._load_remote_config(url, base_path, token_env)
                if config:
                    remote_configs.append(config)
            except Exception as e:
                logger.warning(f"Failed to load remote config: {e}")

        return remote_configs

    def _load_remote_config(self, url: str, base_config_path: Optional[Path], token_env: Optional[str]) -> Optional[Dict]:
        """
        Load a remote configuration from URL.

        Args:
            url: URL or file path
            base_config_path: Base config file path (for relative paths)
            token_env: Optional environment variable name for auth token

        Returns:
            dict or None: Parsed config or None if failed
        """
        try:
            if url.startswith("http://") or url.startswith("https://"):
                # Remote URL - use RemoteFetcher
                logger.info(f"Fetching remote config from: {url}")
                from ai_guardian.remote_fetcher import RemoteFetcher

                fetcher = RemoteFetcher()

                # Get token if token_env specified
                headers = {}
                if token_env:
                    token = os.environ.get(token_env)
                    if token:
                        headers["Authorization"] = f"Bearer {token}"
                        logger.debug(f"Using token from {token_env}")

                # Fetch config
                config = fetcher.fetch_config(url, headers=headers)

                if not config:
                    return None

                # Validate remote config against JSON schema
                if not self._validate_config(config, f"remote ({url})", Path(url)):
                    logger.error(f"Remote config validation failed: {url}")
                    return None

                # Security check: prevent remote configs from disabling security features
                # Remote configs MUST NOT be able to disable critical security enforcement
                security_critical_keys = [
                    ("secret_scanning", "enabled"),
                    ("prompt_injection", "enabled"),
                    ("permissions", "enabled"),
                ]

                for key_path in security_critical_keys:
                    # Navigate nested dict
                    current = config
                    for key in key_path[:-1]:
                        if key in current:
                            current = current[key]
                        else:
                            current = None
                            break

                    # Check if final key attempts to disable feature
                    if current is not None and key_path[-1] in current:
                        if current[key_path[-1]] is False:
                            logger.error(
                                f"Remote config {url} attempts to disable security feature: "
                                f"{'.'.join(key_path)}. This is not allowed. Skipping remote config."
                            )
                            return None

                logger.info(f"Remote config validated and passed security checks: {url}")
                return config
            else:
                # Local file path
                file_path = Path(url)
                if not file_path.is_absolute() and base_config_path:
                    file_path = base_config_path.parent / url

                logger.info(f"Loading remote config from local file: {file_path}")
                return self._load_json_file(file_path, f"remote ({url})")

        except Exception as e:
            logger.warning(f"Error loading remote config from {url}: {e}")
            return None

    def _discover_from_directories(self, config: Dict) -> None:
        """
        Discover patterns from permissions_directories and add to config.

        Supports both old format (allow/deny arrays) and new format (array with matcher/mode).

        Modifies config in-place by adding permission rules.

        Args:
            config: Configuration dict
        """
        try:
            from ai_guardian.skill_discovery import SkillDiscovery

            discovery = SkillDiscovery()
            cache_ttl = int(os.environ.get("AI_GUARDIAN_SKILL_CACHE_TTL_HOURS", "24"))

            permissions_dirs = config.get("permissions_directories", {})

            # New format: array with matcher/mode
            if isinstance(permissions_dirs, list):
                for dir_entry in permissions_dirs:
                    matcher = dir_entry.get("matcher", "Skill")
                    mode = dir_entry.get("mode", "allow")

                    discovered_items = self._discover_directory_items(discovery, dir_entry, cache_ttl)
                    if discovered_items:
                        self._add_to_permission_rule(config, matcher, mode, discovered_items)
                return

            # Old format: dict with allow/deny arrays (backward compatibility)
            # Process allow directories
            allow_dirs = permissions_dirs.get("allow", [])
            for dir_entry in allow_dirs:
                discovered_items = self._discover_directory_items(discovery, dir_entry, cache_ttl)
                if discovered_items:
                    matcher = dir_entry.get("matcher", "Skill")
                    self._add_to_permission_rule(config, matcher, "allow", discovered_items)

            # Process deny directories
            deny_dirs = permissions_dirs.get("deny", [])
            for dir_entry in deny_dirs:
                discovered_items = self._discover_directory_items(discovery, dir_entry, cache_ttl)
                if discovered_items:
                    matcher = dir_entry.get("matcher", "Skill")
                    self._add_to_permission_rule(config, matcher, "deny", discovered_items)

        except ImportError:
            logger.debug("Skill discovery not available")
        except Exception as e:
            logger.error(f"Error discovering from directories: {e}")

    def _discover_directory_items(self, discovery, dir_entry: Dict, cache_ttl: int) -> List[str]:
        """
        Discover items from a single directory entry.

        Args:
            discovery: SkillDiscovery instance
            dir_entry: Directory entry dict with url, matcher, token_env
            cache_ttl: Cache TTL in hours

        Returns:
            list: List of item names (without matcher prefix)
        """
        try:
            url = dir_entry.get("url")
            token_env = dir_entry.get("token_env")

            if not url:
                return []

            # Discover items from directory
            items = discovery.discover_skills(url, cache_ttl_hours=cache_ttl, token_env=token_env)

            # Extract just the names (remove category prefix if present)
            names = []
            for item in items:
                if ":" in item:
                    name = item.split(":", 1)[1]
                else:
                    name = item
                names.append(name)

            return names

        except Exception as e:
            logger.error(f"Error discovering items from {dir_entry}: {e}")
            return []

    def _add_to_permission_rule(self, config: Dict, matcher: str, list_type: str, items: List[str]) -> None:
        """
        Add items to a permission rule (or create one if needed).

        Args:
            config: Configuration dict
            matcher: Matcher pattern (e.g., "Skill", "mcp__*")
            list_type: "allow" or "deny"
            items: List of patterns to add
        """
        # Ensure permissions is the new unified structure
        if "permissions" not in config:
            config["permissions"] = {"enabled": True, "immutable": False, "rules": []}

        permissions = config["permissions"]

        # Handle new unified format
        if isinstance(permissions, dict):
            if "rules" not in permissions:
                permissions["rules"] = []
            rules = permissions["rules"]
        # Legacy format: array directly
        elif isinstance(permissions, list):
            rules = permissions
        else:
            # Invalid format - create new structure
            config["permissions"] = {"enabled": True, "immutable": False, "rules": []}
            rules = config["permissions"]["rules"]

        # Find existing rule with this matcher and mode
        mode = list_type  # "allow" or "deny"
        for rule in rules:
            if rule.get("matcher") == matcher and rule.get("mode") == mode:
                # Add to existing rule's patterns
                if "patterns" not in rule:
                    rule["patterns"] = []
                rule["patterns"].extend(items)
                return

        # No existing rule - create new one
        new_rule = {
            "matcher": matcher,
            "mode": mode,
            "patterns": items
        }
        rules.append(new_rule)
