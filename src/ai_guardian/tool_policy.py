#!/usr/bin/env python3
"""
Tool Allow/Deny List Policy Checker

Permission system using JSON configuration format:
- permissions.deny / permissions.allow
- Pattern prefix detection: Skill(...), Bash(...), mcp__*
- Bash command content inspection
- Auto-discovery via permissions_directories

Configuration file: ~/.config/ai-guardian/ai-guardian.json
"""

import fnmatch
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

logger = logging.getLogger(__name__)


class ToolPolicyChecker:
    """
    Check if tool invocations are allowed based on unified permissions.

    Pattern format:
    - Skill(pattern) - Match skill invocations
    - Bash(pattern) - Inspect bash command content
    - mcp__* - Match MCP tool names
    - Read(...), Write(...) - Match built-in tools

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

            # Check against deny patterns first (deny wins)
            deny_patterns = self.config.get("permissions", {}).get("deny", [])
            for pattern in deny_patterns:
                if self._matches_pattern(tool_name, tool_input, pattern):
                    logger.warning(f"Tool '{tool_name}' matched deny pattern: {pattern}")
                    error_msg = self._format_deny_message(tool_name, pattern)
                    return False, error_msg, tool_name

            # Check allow patterns
            allow_patterns = self.config.get("permissions", {}).get("allow", [])

            # If no allow patterns specified, allow by default (unless denied)
            if not allow_patterns:
                logger.info(f"✓ Tool '{tool_name}' is allowed (no allow patterns configured)")
                return True, None, tool_name

            # Check if tool matches any allow pattern
            for pattern in allow_patterns:
                if self._matches_pattern(tool_name, tool_input, pattern):
                    logger.info(f"✓ Tool '{tool_name}' matched allow pattern: {pattern}")
                    return True, None, tool_name

            # Not in allow list - check if this requires explicit allow
            if self._requires_explicit_allow(tool_name):
                logger.warning(f"Tool '{tool_name}' not in allow list (requires explicit approval)")
                error_msg = self._format_deny_message(tool_name, "not in allow list")
                return False, error_msg, tool_name

            # Default: allow (for built-in tools not requiring explicit approval)
            logger.info(f"✓ Tool '{tool_name}' is allowed by default")
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

            # For Skill tool, construct "Skill(skill-name)" format
            if tool_name == "Skill" and isinstance(tool_input, dict):
                skill_name = tool_input.get("skill")
                if skill_name:
                    tool_name = f"Skill({skill_name})"

            return tool_name, tool_input

        except Exception as e:
            logger.error(f"Error extracting tool info: {e}")
            return None, {}

    def _matches_pattern(self, tool_name: str, tool_input: Dict, pattern: str) -> bool:
        """
        Check if tool matches a permission pattern.

        IDE-agnostic pattern matching:
        - Skill(pattern) - Checks if tool has 'skill' parameter matching pattern
        - Bash(pattern) or Shell(pattern) - Checks if tool has 'command' parameter matching pattern
        - mcp__* - Direct tool name matching
        - Other patterns - Direct tool name matching

        Args:
            tool_name: Name of the tool (e.g., "Bash", "Shell", "Skill(daf-active)")
            tool_input: Tool input parameters
            pattern: Permission pattern

        Returns:
            bool: True if matches
        """
        # Skill pattern: Skill(pattern)
        # Checks if tool has a 'skill' parameter that matches
        if pattern.startswith("Skill(") and pattern.endswith(")"):
            inner_pattern = pattern[6:-1]  # Extract pattern between Skill( and )

            # Claude Code format: tool_name = "Skill(skill-name)"
            if tool_name.startswith("Skill(") and tool_name.endswith(")"):
                skill_name = tool_name[6:-1]  # Extract skill name
                return fnmatch.fnmatch(skill_name, inner_pattern)

            # Check if tool input has a 'skill' parameter
            skill_param = tool_input.get("skill")
            if skill_param:
                return fnmatch.fnmatch(skill_param, inner_pattern)

            return False

        # Bash/Shell pattern: Bash(pattern) or Shell(pattern)
        # Checks if tool has a 'command' parameter that matches
        # Works with both Claude Code (Bash) and Cursor (Shell)
        elif (pattern.startswith("Bash(") or pattern.startswith("Shell(")) and pattern.endswith(")"):
            # Extract pattern (handle both "Bash(" and "Shell(")
            if pattern.startswith("Bash("):
                command_pattern = pattern[5:-1]
            else:  # Shell(
                command_pattern = pattern[6:-1]

            # Check if tool has a 'command' parameter
            command = tool_input.get("command", "")
            if command:
                return fnmatch.fnmatch(command, command_pattern)

            return False

        # Direct tool name matching (mcp__*, Read, Write, etc.)
        else:
            return fnmatch.fnmatch(tool_name, pattern)

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
        if tool_name.startswith("Skill("):
            return True

        # MCP tools require explicit allow
        if tool_name.startswith("mcp__"):
            return True

        # Built-in tools allowed by default
        return False

    def _format_deny_message(self, tool_name: str, pattern: str) -> str:
        """
        Format error message for denied tools.

        Args:
            tool_name: Name of the denied tool
            pattern: Pattern that blocked it

        Returns:
            str: Formatted error message
        """
        return (
            f"\n{'='*70}\n"
            f"🚫 TOOL ACCESS DENIED\n"
            f"{'='*70}\n\n"
            f"Tool: {tool_name}\n"
            f"Blocked by: {pattern}\n\n"
            f"This tool is not allowed by your security policy.\n\n"
            f"To allow this tool:\n"
            f"1. Add it to ai-guardian.json in your project:\n"
            f'   "permissions": {{\n'
            f'     "allow": ["{tool_name}"]\n'
            f'   }}\n\n'
            f"2. Or ask your administrator to update the enterprise policy\n"
            f"\n{'='*70}\n"
        )

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
            "permissions": {
                "deny": [],
                "allow": []
            },
            "permissions_directories": {
                "deny": [],
                "allow": []
            },
            "remote_configs": []
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
        """Load user global configuration from ~/.config/ai-guardian/ai-guardian.json."""
        config_home = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
        config_path = Path(config_home) / "ai-guardian" / "ai-guardian.json"
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
                # JSON5 would support comments, but for now just parse strict JSON
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

        Lists are concatenated (not replaced).
        Dicts are recursively merged.

        Args:
            base: Base configuration
            override: Override configuration (higher priority)

        Returns:
            dict: Merged configuration
        """
        result = base.copy()

        for key, value in override.items():
            if key in result:
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

                # Fetch config (RemoteFetcher needs to be updated to support headers)
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

        Modifies config in-place.

        Args:
            config: Configuration dict
        """
        try:
            from ai_guardian.skill_discovery import SkillDiscovery

            discovery = SkillDiscovery()
            cache_ttl = int(os.environ.get("AI_GUARDIAN_SKILL_CACHE_TTL_HOURS", "24"))

            permissions_dirs = config.get("permissions_directories", {})

            # Process deny directories
            deny_dirs = permissions_dirs.get("deny", [])
            for dir_entry in deny_dirs:
                patterns = self._discover_directory_patterns(discovery, dir_entry, cache_ttl)
                if patterns:
                    config["permissions"]["deny"].extend(patterns)

            # Process allow directories
            allow_dirs = permissions_dirs.get("allow", [])
            for dir_entry in allow_dirs:
                patterns = self._discover_directory_patterns(discovery, dir_entry, cache_ttl)
                if patterns:
                    config["permissions"]["allow"].extend(patterns)

        except ImportError:
            logger.debug("Skill discovery not available")
        except Exception as e:
            logger.error(f"Error discovering from directories: {e}")

    def _discover_directory_patterns(self, discovery, dir_entry: Dict, cache_ttl: int) -> List[str]:
        """
        Discover patterns from a single directory entry.

        Args:
            discovery: SkillDiscovery instance
            dir_entry: Directory entry dict with url, category, token_env
            cache_ttl: Cache TTL in hours

        Returns:
            list: List of patterns (e.g., ["Skill(arc)", "Skill(foo)"])
        """
        try:
            url = dir_entry.get("url")
            category = dir_entry.get("category", "Skill")
            token_env = dir_entry.get("token_env")

            if not url:
                return []

            # Discover items from directory
            items = discovery.discover_skills(url, cache_ttl_hours=cache_ttl, token_env=token_env)

            # Convert items to patterns with category prefix
            patterns = []
            for item in items:
                # Items come back as "Skill:name", extract name
                if ":" in item:
                    name = item.split(":", 1)[1]
                else:
                    name = item

                # Format as category(name)
                pattern = f"{category}({name})"
                patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.error(f"Error discovering patterns from {dir_entry}: {e}")
            return []
