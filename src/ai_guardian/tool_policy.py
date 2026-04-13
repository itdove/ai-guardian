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
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Union

from ai_guardian.config_utils import get_config_dir, is_expired

# Import violation logger
try:
    from ai_guardian.violation_logger import ViolationLogger
    HAS_VIOLATION_LOGGER = True
except ImportError:
    HAS_VIOLATION_LOGGER = False
    logging.debug("violation_logger module not available")

logger = logging.getLogger(__name__)

# Hardcoded critical protections - cannot be disabled or bypassed
# These patterns are checked FIRST, before any user-configured permissions
IMMUTABLE_DENY_PATTERNS = {
    "Write": [
        # Protect ai-guardian config files
        "*ai-guardian.json",
        "*/.config/ai-guardian/*",
        "*/.ai-guardian.json",

        # Protect IDE hook files (CRITICAL - prevents disabling ai-guardian)
        "*/.claude/settings.json",
        "*/.claude/hooks.json",
        "*/.cursor/hooks.json",
        "*/Claude/settings.json",    # Windows
        "*/Cursor/hooks.json",        # Windows

        # Protect ai-guardian package (self-protection)
        "*/site-packages/ai_guardian/*",           # Installed package
        "*/ai-guardian/src/ai_guardian/*",         # Source repo (with hyphen)
        "*/ai-guardian/ai_guardian/*",             # Alternative source layout

        # Protect .ai-read-deny marker files (directory protection)
        "*/.ai-read-deny",
        "**/.ai-read-deny",
    ],

    "Edit": [
        # Same patterns - protect from Edit tool
        "*ai-guardian.json",
        "*/.config/ai-guardian/*",
        "*/.ai-guardian.json",
        "*/.claude/settings.json",
        "*/.claude/hooks.json",
        "*/.cursor/hooks.json",
        "*/Claude/settings.json",
        "*/Cursor/hooks.json",
        "*/site-packages/ai_guardian/*",           # Installed package
        "*/ai-guardian/src/ai_guardian/*",         # Source repo (with hyphen)
        "*/ai-guardian/ai_guardian/*",             # Alternative source layout

        # Protect .ai-read-deny marker files (directory protection)
        "*/.ai-read-deny",
        "**/.ai-read-deny",
    ],

    "Bash": [
        # Block commands that could modify protected files
        "*sed*ai-guardian*",
        "*sed*site-packages/ai_guardian*", "*sed*ai-guardian/src/ai_guardian*", "*sed*ai-guardian/ai_guardian*",
        "*awk*ai-guardian*",
        "*awk*site-packages/ai_guardian*", "*awk*ai-guardian/src/ai_guardian*", "*awk*ai-guardian/ai_guardian*",
        "*sed*.claude/settings.json*",
        "*sed*.cursor/hooks.json*",
        "*awk*.claude/settings.json*",
        "*awk*.cursor/hooks.json*",
        "*vim*.claude/settings.json*",
        "*nano*.claude/settings.json*",
        "*vim*.cursor/hooks.json*",
        "*nano*.cursor/hooks.json*",
        "*chmod*ai-guardian*",
        "*chmod*site-packages/ai_guardian*", "*chmod*ai-guardian/src/ai_guardian*", "*chmod*ai-guardian/ai_guardian*",
        "*chmod*.claude/settings.json*",
        "*chmod*.cursor/hooks.json*",
        "*chattr*ai-guardian*",
        "*chattr*.claude*", "*chattr*.cursor*",
        "*>*ai-guardian*",
        "*>*site-packages/ai_guardian*", "*>*ai-guardian/src/ai_guardian*", "*>*ai-guardian/ai_guardian*",
        "*>*.claude/settings.json*",
        "*>*.cursor/hooks.json*",
        "*rm*ai-guardian.json*",
        "*rm*.claude/settings.json*",
        "*rm*.cursor/hooks.json*",
        "*mv*ai-guardian*",
        "*mv*.claude/settings.json*",
        "*mv*.cursor/hooks.json*",

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
        # Protect ai-guardian config files
        "*Remove-Item*ai-guardian*",
        "*Move-Item*ai-guardian*",
        "*Rename-Item*ai-guardian*",
        "*Set-Content*ai-guardian*",
        "*Clear-Content*ai-guardian*",
        "*Out-File*ai-guardian*",
        "*Copy-Item*ai-guardian*",

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

        # Protect against PowerShell redirections
        "*>*ai-guardian*", "*>>*ai-guardian*",
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

        # PowerShell aliases (del, erase, rm, mv, etc.)
        "*del *ai-guardian*", "*erase *ai-guardian*",
        "*rm *ai-guardian*", "*rmdir *ai-guardian*",
        "*mv *ai-guardian*", "*move *ai-guardian*",
        "*ren *ai-guardian*", "*copy *ai-guardian*",
        "*rm *.claude/settings.json*", "*del *.claude/settings.json*",
        "*rm *.cursor/hooks.json*", "*del *.cursor/hooks.json*",
        "*rm *.ai-read-deny*", "*del *.ai-read-deny*",
        "*mv *.ai-read-deny*", "*move *.ai-read-deny*",
    ]
}


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

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize policy checker.

        Args:
            config: Optional configuration dict. If None, loads from disk.
        """
        self.config = config or self._load_config()

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
                # Fail-open: allow if we can't determine the tool
                return True, None, None

            logger.info(f"Checking if tool '{tool_name}' is allowed...")

            # PRIORITY 1: Check immutable deny patterns (cannot be overridden)
            # These protect ai-guardian config, IDE hooks, and package source code
            check_value = self._extract_check_value(tool_name, tool_input, tool_name)
            if check_value:
                immutable_denies = IMMUTABLE_DENY_PATTERNS.get(tool_name, [])
                for pattern in immutable_denies:
                    if fnmatch.fnmatch(check_value, pattern):
                        error_msg = self._format_immutable_deny_message(check_value, tool_name)
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

                # Legacy format support
                if mode is None:
                    patterns = rule.get("deny", [])
                    mode = "deny" if patterns else None

                if mode == "deny":
                    for pattern_entry in patterns:
                        # Extract pattern string from entry (supports both str and dict formats)
                        pattern_str = self._extract_pattern_string(pattern_entry)
                        if fnmatch.fnmatch(check_value, pattern_str):
                            logger.warning(f"Tool '{tool_name}' matched deny pattern: {pattern_str}")
                            error_msg = self._format_deny_message(
                                tool_name,
                                f"matched deny pattern: {pattern_str}",
                                rule["matcher"],
                                tool_value=check_value
                            )

                            # Log violation
                            self._log_violation(
                                tool_name=tool_name,
                                check_value=check_value,
                                reason=f"matched deny pattern: {pattern_str}",
                                matcher=rule["matcher"],
                                hook_data=hook_data
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
                    for pattern_entry in patterns:
                        # Extract pattern string from entry (supports both str and dict formats)
                        pattern_str = self._extract_pattern_string(pattern_entry)
                        if fnmatch.fnmatch(check_value, pattern_str):
                            logger.info(f"✓ Tool '{tool_name}' matched allow pattern: {pattern_str}")
                            return True, None, tool_name

            # If we have allow rules but no match, deny
            if has_allow_rules:
                logger.warning(f"Tool '{tool_name}' not in allow list")
                error_msg = self._format_deny_message(
                    tool_name,
                    "not in allow list",
                    permission_rules[0]["matcher"],
                    tool_value=check_value
                )

                # Log violation
                self._log_violation(
                    tool_name=tool_name,
                    check_value=check_value,
                    reason="not in allow list",
                    matcher=permission_rules[0]["matcher"],
                    hook_data=hook_data
                )

                return False, error_msg, tool_name

            # No allow rules - allow by default (already passed deny check)
            logger.info(f"✓ Tool '{tool_name}' is allowed (no allow patterns in rules)")
            return True, None, tool_name

        except Exception as e:
            logger.error(f"Error checking tool policy: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Fail-open: allow on errors
            return True, None, None

    def _extract_tool_info(self, hook_data: Dict) -> Tuple[Optional[str], Dict]:
        """
        Extract tool name and input from hook data.

        Returns:
            tuple: (tool_name, tool_input)
        """
        try:
            tool_name = None
            tool_input = {}

            # Claude Code format: tool_use.name
            if "tool_use" in hook_data and isinstance(hook_data["tool_use"], dict):
                tool_name = hook_data["tool_use"].get("name")
                tool_input = hook_data["tool_use"].get("input", {})
            # Cursor format: tool.name
            elif "tool" in hook_data and isinstance(hook_data["tool"], dict):
                tool_name = hook_data["tool"].get("name")
                tool_input = hook_data.get("tool_input", {})
            # Alternative: direct tool_name field
            elif "tool_name" in hook_data:
                tool_name = hook_data["tool_name"]
                tool_input = hook_data.get("tool_input", {})

            return tool_name, tool_input

        except Exception as e:
            logger.error(f"Error extracting tool info: {e}")
            return None, {}

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
        permissions = self.config.get("permissions", [])

        # Handle old format (dict with deny/allow) - convert to new format
        if isinstance(permissions, dict):
            logger.debug("Converting old permissions format to new array format")
            # Create a catch-all rule
            return [{
                "matcher": "*",
                "allow": permissions.get("allow", []),
                "deny": permissions.get("deny", [])
            }]

        # New format: array of rules
        if not isinstance(permissions, list):
            logger.warning(f"Invalid permissions format: {type(permissions)}")
            return []

        matching_rules = []
        for rule in permissions:
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
            return command if command else None

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
        msg += "Or ask your administrator to update the enterprise policy.\n"
        msg += f"{'='*70}\n"

        return msg

    def _format_immutable_deny_message(self, file_path: str, tool_name: str) -> str:
        """
        Format error message for immutable deny (cannot be overridden).

        Args:
            file_path: The file path that was blocked
            tool_name: The tool that was blocked

        Returns:
            str: Formatted error message
        """
        # Check if this is a .ai-read-deny marker file (check both Unix and Windows paths)
        is_marker_file = (file_path.endswith('.ai-read-deny') or
                         '/.ai-read-deny' in file_path or
                         '\\.ai-read-deny' in file_path or
                         '.ai-read-deny' in file_path)

        base_message = (
            f"\n{'='*70}\n"
            f"🔒 CRITICAL FILE PROTECTED\n"
            f"{'='*70}\n\n"
            f"This file is protected by ai-guardian and cannot be modified.\n\n"
            f"File: {file_path}\n"
            f"Tool: {tool_name}\n"
        )

        if is_marker_file:
            return base_message + (
                f"Reason: Directory protection marker\n\n"
                f"Protected files:\n"
                f"  • ai-guardian configuration files\n"
                f"  • IDE hook configuration (Claude, Cursor)\n"
                f"  • ai-guardian package source code\n"
                f"  • .ai-read-deny marker files (directory protection)\n\n"
                f"This protection cannot be disabled via configuration.\n"
                f"It ensures directory protection cannot be bypassed by AI agents.\n\n"
                f"To remove directory protection, delete .ai-read-deny manually.\n"
                f"\n{'='*70}\n"
            )
        else:
            return base_message + (
                f"Reason: Critical security configuration\n\n"
                f"Protected files:\n"
                f"  • ai-guardian configuration files\n"
                f"  • IDE hook configuration (Claude, Cursor)\n"
                f"  • ai-guardian package source code\n"
                f"  • .ai-read-deny marker files (directory protection)\n\n"
                f"This protection cannot be disabled via configuration.\n"
                f"It ensures ai-guardian cannot be bypassed by AI agents.\n\n"
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

        Returns:
            dict: Merged configuration
        """
        # Start with defaults
        config = self._get_defaults()

        # Load project local config
        local_config, local_config_path = self._load_local_config()
        if local_config:
            config = self._merge_configs(config, local_config)

        # Load user global config
        user_config, user_config_path = self._load_user_config()
        if user_config:
            config = self._merge_configs(config, user_config)

        # Load remote configs (highest priority)
        remote_configs = self._load_remote_configs(local_config, local_config_path, user_config, user_config_path)
        for remote_config in remote_configs:
            config = self._merge_configs(config, remote_config)

        # Discover and add patterns from permissions_directories
        self._discover_from_directories(config)

        return config

    def _get_defaults(self) -> Dict:
        """Get default empty configuration."""
        return {
            "permissions": [],
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
            return config

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in {source_name} config at {path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error loading {source_name} config from {path}: {e}")
            return None

    def _merge_configs(self, base: Dict, override: Dict) -> Dict:
        """
        Merge two configuration dictionaries.

        For permissions array: concatenate
        For other lists: concatenate
        For dicts: recursively merge

        Args:
            base: Base configuration
            override: Override configuration (higher priority)

        Returns:
            dict: Merged configuration
        """
        result = base.copy()

        for key, value in override.items():
            if key == "permissions":
                # Special handling for permissions array
                if isinstance(result.get(key), list) and isinstance(value, list):
                    result[key] = result[key] + value
                else:
                    result[key] = value
            elif key in result:
                # If both are lists, concatenate
                if isinstance(result[key], list) and isinstance(value, list):
                    result[key] = result[key] + value
                # If both are dicts, recursively merge
                elif isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = self._merge_configs(result[key], value)
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
            for entry in local_config["remote_configs"]:
                remote_entries.append((entry, local_config_path))

        if user_config and "remote_configs" in user_config:
            for entry in user_config["remote_configs"]:
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
                    matcher = dir_entry.get("category", "Skill")
                    self._add_to_permission_rule(config, matcher, "allow", discovered_items)

            # Process deny directories
            deny_dirs = permissions_dirs.get("deny", [])
            for dir_entry in deny_dirs:
                discovered_items = self._discover_directory_items(discovery, dir_entry, cache_ttl)
                if discovered_items:
                    matcher = dir_entry.get("category", "Skill")
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
            dir_entry: Directory entry dict with url, category, token_env
            cache_ttl: Cache TTL in hours

        Returns:
            list: List of item names (without category prefix)
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
        # Ensure permissions is a list
        if "permissions" not in config or not isinstance(config["permissions"], list):
            config["permissions"] = []

        # Find existing rule with this matcher and mode
        mode = list_type  # "allow" or "deny"
        for rule in config["permissions"]:
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
        config["permissions"].append(new_rule)
