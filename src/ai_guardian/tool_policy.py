#!/usr/bin/env python3
"""
Tool Allow/Deny List Policy Checker

This module implements allow/deny list checking for AI tool invocations,
supporting:
- Built-in tools (Read, Write, Bash, etc.)
- Skills (Skill:*)
- MCP tools (mcp__*)

Configuration sources (merged with priority):
1. Remote configs (enterprise policy)
2. User global config
3. Project local config
4. Hardcoded defaults

Default behavior:
- Built-in tools: ALLOW ALL (only deny if in deny list)
- Skills: BLOCK ALL (must be in allow list)
- MCP tools: BLOCK ALL (must be in allow list)
"""

import fnmatch
import json
import logging
import os
import time
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """Tool categories with different default behaviors."""
    BUILTIN = "builtin"  # Core Claude tools - allow by default
    SKILL = "skill"      # User extensions - block by default
    MCP = "mcp"          # External services - block by default
    UNKNOWN = "unknown"  # Unknown tools - block by default


class ToolPolicyChecker:
    """
    Check if tool invocations are allowed based on configured policies.

    Handles:
    - Category detection (builtin/skill/mcp)
    - Pattern matching for allow/deny lists
    - Configuration loading and merging
    - Default behavior per category
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
            # Extract tool name from hook data
            tool_name = self._extract_tool_name(hook_data)
            if not tool_name:
                logger.warning("Could not extract tool name from hook data")
                # Fail-open: allow if we can't determine the tool
                return True, None, None

            logger.info(f"Checking if tool '{tool_name}' is allowed...")

            # Determine tool category
            category = self._categorize_tool(tool_name)
            logger.debug(f"Tool '{tool_name}' categorized as: {category.value}")

            # Check if tool is allowed based on category and patterns
            is_allowed = self._is_tool_allowed(tool_name, category)

            if not is_allowed:
                error_msg = self._format_deny_message(tool_name, category)
                logger.warning(f"Tool '{tool_name}' is not allowed")
                return False, error_msg, tool_name

            logger.info(f"✓ Tool '{tool_name}' is allowed")
            return True, None, tool_name

        except Exception as e:
            logger.error(f"Error checking tool policy: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Fail-open: allow on errors
            return True, None, None

    def _extract_tool_name(self, hook_data: Dict) -> Optional[str]:
        """
        Extract tool name from hook data.

        Supports:
        - Claude Code: tool_use.name
        - Cursor: tool.name or tool_name
        - Skills: Constructs "Skill:skill-name" format
        """
        try:
            tool_name = None

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
            else:
                return None

            # For Skill tool, append the skill name to create "Skill:skill-name"
            if tool_name == "Skill" and isinstance(tool_input, dict):
                skill_name = tool_input.get("skill")
                if skill_name:
                    tool_name = f"Skill:{skill_name}"
                    logger.debug(f"Constructed skill tool name: {tool_name}")

            return tool_name

        except Exception as e:
            logger.error(f"Error extracting tool name: {e}")
            return None

    def _categorize_tool(self, tool_name: str) -> ToolCategory:
        """
        Determine which category a tool belongs to.

        Args:
            tool_name: Name of the tool

        Returns:
            ToolCategory enum value
        """
        # Skills start with "Skill:"
        if tool_name.startswith("Skill:"):
            return ToolCategory.SKILL

        # MCP tools start with "mcp__"
        if tool_name.startswith("mcp__"):
            return ToolCategory.MCP

        # Known built-in tools (not exhaustive - new tools work by default)
        builtin_tools = {
            "Read", "Write", "Edit", "Glob", "Grep", "Bash",
            "WebFetch", "WebSearch", "Agent", "AskUserQuestion",
            "TaskCreate", "TaskUpdate", "TaskGet", "TaskList",
            "NotebookEdit", "LSP", "CronCreate", "CronList", "CronDelete",
            "EnterWorktree", "ExitWorktree", "EnterPlanMode", "ExitPlanMode"
        }

        if tool_name in builtin_tools:
            return ToolCategory.BUILTIN

        # Default to BUILTIN for unknown tools (future-proof)
        # This means new Claude tools will work without config updates
        logger.debug(f"Unknown tool '{tool_name}' - treating as BUILTIN (allow by default)")
        return ToolCategory.BUILTIN

    def _is_tool_allowed(self, tool_name: str, category: ToolCategory) -> bool:
        """
        Check if a tool is allowed based on category and patterns.

        Logic:
        1. Check deny patterns first (deny wins)
        2. For built-ins: allow by default (only block if in deny list)
        3. For skills/mcp: block by default (only allow if in allow list)

        Args:
            tool_name: Name of the tool
            category: Tool category

        Returns:
            bool: True if allowed, False if blocked
        """
        if category == ToolCategory.BUILTIN:
            return self._check_builtin_allowed(tool_name)
        elif category == ToolCategory.SKILL:
            return self._check_skill_allowed(tool_name)
        elif category == ToolCategory.MCP:
            return self._check_mcp_allowed(tool_name)
        else:
            # Unknown category - block by default
            logger.warning(f"Unknown category for tool '{tool_name}' - blocking")
            return False

    def _check_builtin_allowed(self, tool_name: str) -> bool:
        """
        Check if a built-in tool is allowed.

        Default: ALLOW ALL (only deny if in deny list)

        Args:
            tool_name: Name of the tool

        Returns:
            bool: True if allowed, False if blocked
        """
        deny_patterns = self.config.get("builtin_deny_patterns", [])

        # Check if tool matches any deny pattern
        for pattern in deny_patterns:
            if fnmatch.fnmatch(tool_name, pattern):
                logger.debug(f"Built-in tool '{tool_name}' matched deny pattern: {pattern}")
                return False

        # Default: allow
        return True

    def _check_skill_allowed(self, tool_name: str) -> bool:
        """
        Check if a skill is allowed.

        Default: BLOCK ALL (must be in allow list)

        Args:
            tool_name: Name of the skill (includes "Skill:" prefix)

        Returns:
            bool: True if allowed, False if blocked
        """
        allow_patterns = self.config.get("skill_allowed_patterns", [])
        deny_patterns = self.config.get("skill_deny_patterns", [])

        # Check deny patterns first (deny wins)
        for pattern in deny_patterns:
            if fnmatch.fnmatch(tool_name, pattern):
                logger.debug(f"Skill '{tool_name}' matched deny pattern: {pattern}")
                return False

        # Check allow patterns
        for pattern in allow_patterns:
            if fnmatch.fnmatch(tool_name, pattern):
                logger.debug(f"Skill '{tool_name}' matched allow pattern: {pattern}")
                return True

        # Default: block
        logger.debug(f"Skill '{tool_name}' not in allow list - blocking")
        return False

    def _check_mcp_allowed(self, tool_name: str) -> bool:
        """
        Check if an MCP tool is allowed.

        Default: BLOCK ALL (must be in allow list)

        Args:
            tool_name: Name of the MCP tool (includes "mcp__" prefix)

        Returns:
            bool: True if allowed, False if blocked
        """
        allow_patterns = self.config.get("mcp_allowed_patterns", [])
        deny_patterns = self.config.get("mcp_deny_patterns", [])

        # Check deny patterns first (deny wins)
        for pattern in deny_patterns:
            if fnmatch.fnmatch(tool_name, pattern):
                logger.debug(f"MCP tool '{tool_name}' matched deny pattern: {pattern}")
                return False

        # Check allow patterns
        for pattern in allow_patterns:
            if fnmatch.fnmatch(tool_name, pattern):
                logger.debug(f"MCP tool '{tool_name}' matched allow pattern: {pattern}")
                return True

        # Default: block
        logger.debug(f"MCP tool '{tool_name}' not in allow list - blocking")
        return False

    def _format_deny_message(self, tool_name: str, category: ToolCategory) -> str:
        """
        Format error message for denied tools.

        Args:
            tool_name: Name of the denied tool
            category: Tool category

        Returns:
            str: Formatted error message
        """
        if category == ToolCategory.SKILL:
            return (
                f"\n{'='*70}\n"
                f"🚫 TOOL ACCESS DENIED - Skill Not Allowed\n"
                f"{'='*70}\n\n"
                f"The skill '{tool_name}' is not in the allow list.\n\n"
                f"Skills must be explicitly approved before use.\n\n"
                f"To allow this skill:\n"
                f"1. Add it to .allowed-tools.toml in your project\n"
                f"2. Or ask your administrator to add it to the enterprise policy\n\n"
                f"Example configuration:\n"
                f"  skill_allowed_patterns = [\n"
                f"      \"{tool_name}\",\n"
                f"  ]\n"
                f"\n{'='*70}\n"
            )
        elif category == ToolCategory.MCP:
            return (
                f"\n{'='*70}\n"
                f"🚫 TOOL ACCESS DENIED - MCP Tool Not Allowed\n"
                f"{'='*70}\n\n"
                f"The MCP tool '{tool_name}' is not in the allow list.\n\n"
                f"MCP tools access external services and must be explicitly approved.\n\n"
                f"To allow this tool:\n"
                f"1. Add it to .allowed-tools.toml in your project\n"
                f"2. Or ask your administrator to add it to the enterprise policy\n\n"
                f"Example configuration:\n"
                f"  mcp_allowed_patterns = [\n"
                f"      \"{tool_name}\",\n"
                f"  ]\n"
                f"\n{'='*70}\n"
            )
        else:
            return (
                f"\n{'='*70}\n"
                f"🚫 TOOL ACCESS DENIED - Tool Blocked\n"
                f"{'='*70}\n\n"
                f"The tool '{tool_name}' has been blocked by policy.\n\n"
                f"Contact your administrator if you believe this is an error.\n"
                f"\n{'='*70}\n"
            )

    def _load_config(self) -> Dict:
        """
        Load and merge tool policy configurations.

        Priority (highest to lowest):
        1. Remote configs (from remote_configs URLs)
        2. User global config
        3. Project local config
        4. Hardcoded defaults

        Returns:
            dict: Merged configuration
        """
        # Start with empty config
        config = {}

        # Load project local config
        local_config, local_config_path = self._load_local_config()
        if local_config:
            config = self._merge_configs(config, local_config)

        # Load user global config
        user_config, user_config_path = self._load_user_config()
        if user_config:
            config = self._merge_configs(config, user_config)

        # Load remote configs (if specified in local or user configs)
        # Remote configs have HIGHEST priority, so load them last
        remote_configs = self._load_remote_configs(local_config, local_config_path, user_config, user_config_path)
        for remote_config in remote_configs:
            config = self._merge_configs(config, remote_config)

        # Discover skills from directories (if specified)
        self._discover_skills_from_directories(config)

        # Apply defaults for missing values
        config = self._apply_defaults(config)

        return config

    def _load_local_config(self) -> Tuple[Optional[Dict], Optional[Path]]:
        """
        Load project local configuration from .allowed-tools.toml.

        Returns:
            tuple: (config dict or None, config path or None)
        """
        config_path = Path.cwd() / ".allowed-tools.toml"
        config = self._load_toml_file(config_path, "project local")
        return config, config_path if config else None

    def _load_user_config(self) -> Tuple[Optional[Dict], Optional[Path]]:
        """
        Load user global configuration from ~/.config/ai-guardian/allowed-tools.toml.

        Returns:
            tuple: (config dict or None, config path or None)
        """
        # Use XDG_CONFIG_HOME if set, otherwise ~/.config
        config_home = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
        config_path = Path(config_home) / "ai-guardian" / "allowed-tools.toml"
        config = self._load_toml_file(config_path, "user global")
        return config, config_path if config else None

    def _load_toml_file(self, path: Path, source_name: str) -> Optional[Dict]:
        """
        Load and parse a TOML configuration file.

        Args:
            path: Path to TOML file
            source_name: Human-readable source name for logging

        Returns:
            dict or None: Parsed TOML config or None if error/not found
        """
        try:
            if not path.exists():
                logger.debug(f"No {source_name} config found at {path}")
                return None

            # Import toml library
            try:
                import toml
            except ImportError:
                logger.warning("toml library not installed - cannot load TOML configs")
                return None

            logger.info(f"Loading {source_name} config from {path}")
            with open(path, 'r') as f:
                config = toml.load(f)

            logger.debug(f"Loaded {source_name} config: {config}")
            return config

        except Exception as e:
            logger.warning(f"Error loading {source_name} config from {path}: {e}")
            return None

    def _merge_configs(self, base: Dict, override: Dict) -> Dict:
        """
        Merge two configuration dictionaries.

        Override values take precedence over base values.
        Lists are concatenated (not replaced).

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

    def _apply_defaults(self, config: Dict) -> Dict:
        """
        Apply default values for missing configuration keys.

        Args:
            config: Configuration dict

        Returns:
            dict: Configuration with defaults applied
        """
        defaults = {
            "builtin_deny_patterns": [],
            "skill_allowed_patterns": [],
            "skill_deny_patterns": [],
            "mcp_allowed_patterns": [],
            "mcp_deny_patterns": [],
            "allowed_skill_directories": [],
            "deny_skill_directories": [],
        }

        for key, value in defaults.items():
            if key not in config:
                config[key] = value

        return config

    def _discover_skills_from_directories(self, config: Dict) -> None:
        """
        Discover skills from directory URLs and add to config.

        Modifies config in-place by adding discovered skills to:
        - skill_allowed_patterns (from allowed_skill_directories)
        - skill_deny_patterns (from deny_skill_directories)

        Supports both formats:
        - Simple string: "https://github.com/org/repo/tree/main/skills"
        - Dict with token: {"url": "...", "token_env": "GITHUB_AI_SKILL_TOKEN"}

        Args:
            config: Configuration dict
        """
        try:
            from ai_guardian.skill_discovery import SkillDiscovery

            discovery = SkillDiscovery()

            # Get cache TTL from environment or default
            cache_ttl = int(os.environ.get("AI_GUARDIAN_SKILL_CACHE_TTL_HOURS", "24"))

            # Discover allowed skills
            allowed_dirs = config.get("allowed_skill_directories", [])
            if allowed_dirs:
                logger.info(f"Discovering skills from {len(allowed_dirs)} allowed directories")
                for dir_entry in allowed_dirs:
                    # Parse directory entry (string or dict)
                    dir_url, token_env = self._parse_directory_entry(dir_entry)
                    if not dir_url:
                        continue

                    skills = discovery.discover_skills(dir_url, cache_ttl_hours=cache_ttl, token_env=token_env)
                    if skills:
                        logger.info(f"Discovered {len(skills)} skills from {dir_url}")
                        # Add discovered skills to allowed patterns
                        if "skill_allowed_patterns" not in config:
                            config["skill_allowed_patterns"] = []
                        # Convert to list if set, add discovered skills
                        existing = set(config["skill_allowed_patterns"])
                        existing.update(skills)
                        config["skill_allowed_patterns"] = list(existing)

            # Discover denied skills
            deny_dirs = config.get("deny_skill_directories", [])
            if deny_dirs:
                logger.info(f"Discovering skills from {len(deny_dirs)} deny directories")
                for dir_entry in deny_dirs:
                    # Parse directory entry (string or dict)
                    dir_url, token_env = self._parse_directory_entry(dir_entry)
                    if not dir_url:
                        continue

                    skills = discovery.discover_skills(dir_url, cache_ttl_hours=cache_ttl, token_env=token_env)
                    if skills:
                        logger.info(f"Discovered {len(skills)} skills to deny from {dir_url}")
                        # Add discovered skills to deny patterns
                        if "skill_deny_patterns" not in config:
                            config["skill_deny_patterns"] = []
                        # Convert to list if set, add discovered skills
                        existing = set(config["skill_deny_patterns"])
                        existing.update(skills)
                        config["skill_deny_patterns"] = list(existing)

        except ImportError:
            logger.debug("Skill discovery not available (missing dependencies)")
        except Exception as e:
            logger.error(f"Error discovering skills from directories: {e}")
            # Fail-open: continue without discovered skills

    def _parse_directory_entry(self, entry) -> Tuple[Optional[str], Optional[str]]:
        """
        Parse a directory entry from config.

        Supports:
        - Simple string: "https://github.com/org/repo/tree/main/skills"
        - Dict: {"url": "...", "token_env": "GITHUB_AI_SKILL_TOKEN"}

        Args:
            entry: Directory entry (string or dict)

        Returns:
            tuple: (url, token_env) or (None, None) if invalid
        """
        try:
            if isinstance(entry, str):
                # Simple string format
                return entry, None
            elif isinstance(entry, dict):
                # Dict format with optional token_env
                url = entry.get("url")
                token_env = entry.get("token_env")
                if url:
                    return url, token_env
                else:
                    logger.warning(f"Directory entry missing 'url' field: {entry}")
                    return None, None
            else:
                logger.warning(f"Invalid directory entry format (expected string or dict): {entry}")
                return None, None
        except Exception as e:
            logger.error(f"Error parsing directory entry: {e}")
            return None, None

    def _load_remote_configs(
        self,
        local_config: Optional[Dict],
        local_config_path: Optional[Path],
        user_config: Optional[Dict],
        user_config_path: Optional[Path]
    ) -> List[Dict]:
        """
        Load remote configurations from URLs specified in local/user configs.

        Supports:
        - https:// and http:// URLs (remote)
        - file:// URLs (local files)
        - Plain paths (absolute or relative)

        Relative paths are resolved relative to the config file that references them.

        Args:
            local_config: Project local config dict
            local_config_path: Path to project local config file
            user_config: User global config dict
            user_config_path: Path to user global config file

        Returns:
            list: List of loaded remote config dicts
        """
        remote_configs = []

        # Collect remote URLs from both configs
        remote_urls = []

        # Get URLs from project local config
        if local_config and "remote_configs" in local_config:
            urls = local_config["remote_configs"]
            if isinstance(urls, list):
                for url in urls:
                    remote_urls.append((url, local_config_path))

        # Get URLs from user global config
        if user_config and "remote_configs" in user_config:
            urls = user_config["remote_configs"]
            if isinstance(urls, list):
                for url in urls:
                    remote_urls.append((url, user_config_path))

        # Load each remote config
        for url, base_config_path in remote_urls:
            try:
                config = self._load_remote_config(url, base_config_path)
                if config:
                    remote_configs.append(config)
            except Exception as e:
                logger.warning(f"Failed to load remote config from {url}: {e}")
                # Continue with other configs (fail-open for individual remote configs)

        return remote_configs

    def _load_remote_config(self, url: str, base_config_path: Optional[Path]) -> Optional[Dict]:
        """
        Load a remote configuration from a URL or file path.

        Supports:
        - https://example.com/config.toml (remote HTTPS)
        - http://example.com/config.toml (remote HTTP)
        - file:///path/to/config.toml (local file URL)
        - /absolute/path/to/config.toml (absolute path)
        - relative/path/to/config.toml (relative to base_config_path)

        Args:
            url: URL or file path to load
            base_config_path: Base config file path (for resolving relative paths)

        Returns:
            dict or None: Parsed config or None if failed
        """
        try:
            # Resolve the actual file path
            resolved_path = self._resolve_config_url(url, base_config_path)

            if resolved_path.startswith("http://") or resolved_path.startswith("https://"):
                # Remote URL - use RemoteFetcher
                logger.info(f"Fetching remote config from: {resolved_path}")
                from ai_guardian.remote_fetcher import RemoteFetcher

                # Get cache settings from environment or defaults
                refresh_interval = int(os.environ.get("AI_GUARDIAN_REFRESH_INTERVAL_HOURS", "12"))
                expire_after = int(os.environ.get("AI_GUARDIAN_EXPIRE_AFTER_HOURS", "168"))

                fetcher = RemoteFetcher()
                config = fetcher.fetch_config(
                    resolved_path,
                    refresh_interval_hours=refresh_interval,
                    expire_after_hours=expire_after
                )

                if config is None:
                    logger.warning(f"Failed to fetch remote config from {resolved_path} - skipping")

                return config
            else:
                # Local file path
                file_path = Path(resolved_path)
                logger.info(f"Loading remote config from local file: {file_path}")
                return self._load_toml_file(file_path, f"remote ({url})")

        except Exception as e:
            logger.warning(f"Error loading remote config from {url}: {e}")
            return None

    def _resolve_config_url(self, url: str, base_config_path: Optional[Path]) -> str:
        """
        Resolve a config URL to an actual path.

        Handles:
        - file:// URLs -> convert to local path
        - Absolute paths -> use as-is
        - Relative paths -> resolve relative to base_config_path directory

        Args:
            url: URL or path string
            base_config_path: Base config file path for relative resolution

        Returns:
            str: Resolved path or URL
        """
        # Handle file:// URLs
        if url.startswith("file://"):
            # Remove file:// prefix
            path_str = url[7:]  # len("file://") == 7
            return os.path.abspath(os.path.expanduser(path_str))

        # Handle http:// and https:// URLs
        if url.startswith("http://") or url.startswith("https://"):
            return url

        # Handle local paths (absolute or relative)
        path_str = os.path.expanduser(url)  # Expand ~ to home directory

        # Check if absolute path
        if os.path.isabs(path_str):
            return path_str

        # Relative path - resolve relative to base_config_path directory
        if base_config_path:
            base_dir = base_config_path.parent
            resolved = base_dir / path_str
            return str(resolved.absolute())

        # No base path - resolve relative to current directory
        return str(Path(path_str).absolute())
