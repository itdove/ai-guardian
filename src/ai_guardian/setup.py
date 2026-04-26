#!/usr/bin/env python3
"""
Setup Command for ai-guardian

Automatically configures IDE hooks for Claude Code and Cursor,
with support for remote configuration URLs.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ai_guardian.config_utils import get_config_dir


class IDESetup:
    """Handle IDE hook setup and configuration."""

    # IDE configuration paths (base config)
    # Each IDE can specify:
    # - config_path: Default path to config file
    # - config_dir_env_var: Optional environment variable for custom config directory
    # - config_filename: Filename to use with custom config directory
    IDE_CONFIGS = {
        "claude": {
            "name": "Claude Code",
            "config_path": "~/.claude/settings.json",
            "config_dir_env_var": "CLAUDE_CONFIG_DIR",  # Respects this env var
            "config_filename": "settings.json",
            # CRITICAL: ai-guardian MUST be the FIRST PostToolUse hook.
            # Claude Code only displays the first hook's systemMessage field.
            # Log mode warnings are displayed in PostToolUse - if ai-guardian is not first, warnings are suppressed.
            # See docs/HOOK_ORDERING.md for details.
            "hooks": {
                "UserPromptSubmit": [
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "ai-guardian",
                                "statusMessage": "🛡️ Scanning prompt..."
                            }
                        ]
                    }
                ],
                "PreToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "ai-guardian",
                                "statusMessage": "🛡️ Checking tool permissions..."
                            }
                        ]
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "ai-guardian",
                                "statusMessage": "🛡️ Scanning tool output..."
                            }
                        ]
                    }
                ]
            }
        },
        "cursor": {
            "name": "Cursor IDE",
            "config_path": "~/.cursor/hooks.json",
            "config_dir_env_var": None,  # No known env var for Cursor yet
            "config_filename": "hooks.json",
            "hooks": {
                "version": 1,
                "beforeSubmitPrompt": [
                    {
                        "command": "ai-guardian"
                    }
                ],
                "beforeReadFile": [
                    {
                        "command": "ai-guardian"
                    }
                ],
                "beforeShellExecution": [
                    {
                        "command": "ai-guardian"
                    }
                ],
                "afterShellExecution": [
                    {
                        "command": "ai-guardian"
                    }
                ],
                "postToolUse": [
                    {
                        "command": "ai-guardian"
                    }
                ]
            }
        },
        "copilot": {
            "name": "GitHub Copilot",
            "config_path": "~/.github/hooks/hooks.json",
            "config_dir_env_var": None,
            "config_filename": "hooks.json",
            "hooks": {
                "userPromptSubmitted": [
                    {
                        "command": "ai-guardian"
                    }
                ],
                "preToolUse": [
                    {
                        "command": "ai-guardian"
                    }
                ]
            }
        }
    }

    @staticmethod
    def get_claude_config_path() -> str:
        """
        Get Claude Code config path, respecting CLAUDE_CONFIG_DIR environment variable.

        Returns:
            str: Path to Claude Code settings.json
        """
        claude_config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
        if claude_config_dir:
            return os.path.join(claude_config_dir, "settings.json")
        return "~/.claude/settings.json"

    def get_config_path(self, ide_type: str) -> str:
        """
        Get IDE config path, respecting IDE-specific environment variables.

        This method checks for IDE-specific environment variables that allow users
        to customize the config directory location (e.g., CLAUDE_CONFIG_DIR).

        Args:
            ide_type: IDE type ('claude' or 'cursor')

        Returns:
            str: Path to IDE config file, or None if IDE type unknown
        """
        if ide_type not in self.IDE_CONFIGS:
            return None

        ide_config = self.IDE_CONFIGS[ide_type]
        base_config_path = ide_config["config_path"]

        # Check if this IDE supports a custom config directory via env var
        # Only use env var if the config_path is still the default value
        env_var_name = ide_config.get("config_dir_env_var")
        if env_var_name:
            default_path = ide_config["config_path"]
            if base_config_path == default_path:
                # Check environment variable
                custom_config_dir = os.environ.get(env_var_name)
                if custom_config_dir:
                    config_filename = ide_config.get("config_filename", "settings.json")
                    return os.path.join(custom_config_dir, config_filename)

        return base_config_path

    def __init__(self):
        """Initialize IDE setup manager."""
        pass

    def verify_gitleaks_installed(self) -> Tuple[bool, str]:
        """
        Check if Gitleaks binary is installed and accessible.

        Returns:
            tuple: (success: bool, message: str)
                - success: True if Gitleaks is installed, False otherwise
                - message: Status message with details or installation instructions
        """
        try:
            result = subprocess.run(
                ['gitleaks', 'version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Extract version from output (first line typically contains version)
                version_line = result.stdout.strip().split('\n')[0] if result.stdout else "unknown version"
                return True, f"✓ Gitleaks is installed: {version_line}"
            else:
                return False, "❌ Gitleaks command failed - please reinstall"
        except FileNotFoundError:
            return False, (
                "❌ Gitleaks not found\n"
                "   Install from: https://github.com/gitleaks/gitleaks#installing\n"
                "   Or use: brew install gitleaks (macOS)"
            )
        except subprocess.TimeoutExpired:
            return False, "❌ Gitleaks check timed out - installation may be corrupted"
        except Exception as e:
            return False, f"❌ Error checking Gitleaks: {e}"

    def detect_ide(self) -> Optional[str]:
        """
        Auto-detect installed IDE based on config files.

        Returns:
            str or None: IDE type ('claude' or 'cursor') or None if not detected
        """
        detected_ides = []

        for ide_type in self.IDE_CONFIGS.keys():
            config_path = Path(self.get_config_path(ide_type)).expanduser()
            if config_path.parent.exists():
                detected_ides.append(ide_type)

        if not detected_ides:
            return None
        elif len(detected_ides) == 1:
            return detected_ides[0]
        else:
            # Multiple IDEs detected - return None to prompt user
            return None

    def list_detected_ides(self) -> List[str]:
        """
        List all detected IDEs.

        Returns:
            list: List of detected IDE types
        """
        detected = []
        for ide_type in self.IDE_CONFIGS.keys():
            config_path = Path(self.get_config_path(ide_type)).expanduser()
            if config_path.parent.exists():
                detected.append(ide_type)
        return detected

    def backup_config(self, config_path: Path) -> Optional[Path]:
        """
        Create backup of existing config file.

        Args:
            config_path: Path to config file

        Returns:
            Path or None: Path to backup file or None if failed
        """
        try:
            if not config_path.exists():
                return None

            backup_path = config_path.with_suffix(config_path.suffix + '.backup')

            # Read and write to create backup
            with open(config_path, 'r', encoding='utf-8') as src:
                content = src.read()

            with open(backup_path, 'w', encoding='utf-8') as dst:
                dst.write(content)

            return backup_path

        except Exception as e:
            print(f"Error creating backup: {e}", file=sys.stderr)
            return None

    def merge_hooks(self, existing_config: Dict, ai_guardian_hooks: Dict, ide_type: str) -> Tuple[Dict, List[str]]:
        """
        Merge ai-guardian hooks into existing config, ensuring ai-guardian is first.

        CRITICAL: ai-guardian MUST be first in PostToolUse for log mode warning visibility.
        Recommended first in UserPromptSubmit/PreToolUse for consistency.

        Args:
            existing_config: Existing IDE configuration
            ai_guardian_hooks: AI Guardian hooks to add
            ide_type: IDE type ('claude' or 'cursor')

        Returns:
            tuple: (merged_config: dict, warnings: list of str)
                - merged_config: Updated configuration
                - warnings: List of warning messages if multiple hooks detected
        """
        warnings = []

        if ide_type == "claude":
            # Claude Code: merge into hooks section
            if "hooks" not in existing_config:
                existing_config["hooks"] = {}

            # Merge UserPromptSubmit, PreToolUse, and PostToolUse hooks
            for hook_name in ["UserPromptSubmit", "PreToolUse", "PostToolUse"]:
                if hook_name not in ai_guardian_hooks:
                    continue

                # Get or create the hook type array
                if hook_name not in existing_config["hooks"]:
                    existing_config["hooks"][hook_name] = []

                # Find or create the "*" matcher entry
                hook_list = existing_config["hooks"][hook_name]
                star_matcher = None
                star_matcher_idx = -1

                for idx, entry in enumerate(hook_list):
                    if isinstance(entry, dict) and entry.get("matcher") == "*":
                        star_matcher = entry
                        star_matcher_idx = idx
                        break

                # If no "*" matcher exists, create it from ai_guardian_hooks
                if star_matcher is None:
                    # Use the template from ai_guardian_hooks
                    existing_config["hooks"][hook_name] = ai_guardian_hooks[hook_name]
                    continue

                # Get or create hooks array within the matcher
                if "hooks" not in star_matcher:
                    star_matcher["hooks"] = []

                hooks_array = star_matcher["hooks"]

                # Find other hooks (not ai-guardian)
                ai_guardian_exists = False
                other_hooks = []

                for idx, hook in enumerate(hooks_array):
                    if isinstance(hook, dict) and hook.get("command") == "ai-guardian":
                        ai_guardian_exists = True
                    else:
                        other_hooks.append(hook)

                # Always use the ai-guardian hook from template for consistency
                template_matcher = ai_guardian_hooks[hook_name][0]
                ai_guardian_hook = template_matcher["hooks"][0]

                # Check if there are other hooks (warn user about ordering)
                if other_hooks:
                    hook_names = []
                    for h in other_hooks:
                        if isinstance(h, dict):
                            cmd = h.get("command", "unknown")
                            hook_names.append(cmd)

                    warnings.append(
                        f"⚠️  {hook_name}: Found other hooks [{', '.join(hook_names)}]. "
                        f"ai-guardian has been placed first to ensure warnings display correctly."
                    )

                # Rebuild hooks array with ai-guardian first
                star_matcher["hooks"] = [ai_guardian_hook] + other_hooks
                existing_config["hooks"][hook_name][star_matcher_idx] = star_matcher

            return existing_config, warnings

        elif ide_type == "cursor":
            # Cursor: merge hooks at top level
            if "hooks" not in existing_config:
                existing_config["hooks"] = {}

            # Ensure version is set
            if "version" not in existing_config:
                existing_config["version"] = 1

            # Merge all Cursor hooks
            for hook_name in ["beforeSubmitPrompt", "beforeReadFile", "beforeShellExecution",
                             "afterShellExecution", "postToolUse"]:
                if hook_name in ai_guardian_hooks:
                    existing_config["hooks"][hook_name] = ai_guardian_hooks[hook_name]

            return existing_config, warnings

        return existing_config, warnings

    def check_hooks_configured(self, config_path: Path, ide_type: str) -> bool:
        """
        Check if ai-guardian hooks are already configured.

        Args:
            config_path: Path to IDE config file
            ide_type: IDE type ('claude' or 'cursor')

        Returns:
            bool: True if hooks already configured
        """
        try:
            if not config_path.exists():
                return False

            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            if ide_type == "claude":
                hooks = config.get("hooks", {})
                # Check if UserPromptSubmit, PreToolUse, or PostToolUse hooks contain ai-guardian
                for hook_name in ["UserPromptSubmit", "PreToolUse", "PostToolUse"]:
                    if hook_name in hooks:
                        hook_list = hooks[hook_name]
                        if isinstance(hook_list, list):
                            for hook_entry in hook_list:
                                if isinstance(hook_entry, dict) and "hooks" in hook_entry:
                                    for h in hook_entry["hooks"]:
                                        if isinstance(h, dict) and h.get("command") == "ai-guardian":
                                            return True

            elif ide_type == "cursor":
                hooks = config.get("hooks", {})
                # Check if any Cursor hooks contain ai-guardian
                for hook_name in ["beforeSubmitPrompt", "beforeReadFile", "beforeShellExecution",
                                 "afterShellExecution", "postToolUse"]:
                    if hook_name in hooks:
                        hook_list = hooks[hook_name]
                        if isinstance(hook_list, list):
                            for h in hook_list:
                                if isinstance(h, dict) and h.get("command") == "ai-guardian":
                                    return True

            return False

        except Exception:
            return False

    def setup_ide_hooks(
        self,
        ide_type: str,
        dry_run: bool = False,
        force: bool = False
    ) -> Tuple[bool, str]:
        """
        Setup IDE hooks for the specified IDE.

        Args:
            ide_type: IDE type ('claude' or 'cursor')
            dry_run: If True, show what would be changed without applying
            force: If True, overwrite existing hooks

        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            if ide_type not in self.IDE_CONFIGS:
                return False, f"Unknown IDE type: {ide_type}"

            ide_config = self.IDE_CONFIGS[ide_type]
            config_path = Path(self.get_config_path(ide_type)).expanduser()
            ide_name = ide_config["name"]

            # Check if hooks already configured
            if not force and self.check_hooks_configured(config_path, ide_type):
                return False, f"ai-guardian hooks already configured for {ide_name}. Use --force to overwrite."

            # Load existing config or create new
            existing_config = {}
            if config_path.exists():
                try:
                    with open(config_path, 'r', encoding='utf-8') as f:
                        existing_config = json.load(f)
                except json.JSONDecodeError as e:
                    return False, f"Invalid JSON in {config_path}: {e}"

            # Merge hooks
            hook_warnings = []
            if ide_type == "claude":
                merged_config, hook_warnings = self.merge_hooks(existing_config, ide_config["hooks"], ide_type)
            elif ide_type == "cursor":
                # For Cursor, we need to merge differently
                merged_config = existing_config.copy()
                if "version" not in merged_config:
                    merged_config["version"] = ide_config["hooks"]["version"]
                if "hooks" not in merged_config:
                    merged_config["hooks"] = {}
                merged_config["hooks"]["beforeSubmitPrompt"] = ide_config["hooks"]["beforeSubmitPrompt"]
                merged_config["hooks"]["beforeReadFile"] = ide_config["hooks"]["beforeReadFile"]
            elif ide_type == "copilot":
                # GitHub Copilot: merge hooks at top level
                merged_config = existing_config.copy()
                merged_config["userPromptSubmitted"] = ide_config["hooks"]["userPromptSubmitted"]
                merged_config["preToolUse"] = ide_config["hooks"]["preToolUse"]
                # Fall through to common config-write path (don't return early)

            if dry_run:
                # Show what would be changed
                message = f"[DRY RUN] Would configure {ide_name} hooks at {config_path}:\n"
                message += json.dumps(merged_config, indent=2)
                return True, message

            # Create backup if file exists
            if config_path.exists():
                backup_path = self.backup_config(config_path)
                if backup_path:
                    print(f"✓ Backup created: {backup_path}", file=sys.stderr)

            # Ensure parent directory exists
            config_path.parent.mkdir(parents=True, exist_ok=True)

            # Write merged config
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(merged_config, f, indent=2)
                f.write('\n')  # Add trailing newline

            # Verify Gitleaks installation
            gitleaks_installed, gitleaks_message = self.verify_gitleaks_installed()

            message = f"✓ Successfully configured {ide_name} hooks at {config_path}\n"
            message += f"\n  {gitleaks_message}\n"

            # Display hook ordering warnings if any
            if hook_warnings:
                message += "\n  Hook Ordering:\n"
                for warning in hook_warnings:
                    message += f"  {warning}\n"
                message += (
                    "\n  📚 For more information about hook ordering, see:\n"
                    "     https://github.com/itdove/ai-guardian/blob/main/docs/HOOK_ORDERING.md\n"
                )

            if not gitleaks_installed:
                message += (
                    "\n  ⚠️  WARNING: Secret scanning will be disabled without Gitleaks!\n"
                    "      AI Guardian requires Gitleaks for secret detection.\n"
                )

            message += f"\n  Next steps:\n"
            if not gitleaks_installed:
                message += f"  1. Install Gitleaks (see above)\n"
                message += f"  2. Restart {ide_name} for changes to take effect\n"
                message += f"  3. Test with: echo '{{\"prompt\": \"test\"}}' | ai-guardian\n"
            else:
                message += f"  1. Restart {ide_name} for changes to take effect\n"
                message += f"  2. Test with: echo '{{\"prompt\": \"test\"}}' | ai-guardian\n"

            return True, message

        except Exception as e:
            return False, f"Error setting up IDE hooks: {e}"

    def migrate_pattern_server_config(self, config: Dict) -> Tuple[bool, Dict]:
        """
        Migrate old root-level pattern_server config to new nested structure.

        NEW in v1.7.0: pattern_server should be nested under secret_scanning.

        Args:
            config: Configuration dictionary to migrate

        Returns:
            tuple: (migrated: bool, updated_config: dict)
                - migrated: True if migration was performed, False if no migration needed
                - updated_config: Migrated configuration
        """
        # Check if old root-level pattern_server exists
        if "pattern_server" not in config:
            return False, config

        # Check if already migrated (nested under secret_scanning)
        secret_scanning = config.get("secret_scanning", {})
        if "pattern_server" in secret_scanning:
            # Already has new structure, remove old root-level one
            old_pattern_server = config.pop("pattern_server")
            return True, config

        # Perform migration: move to secret_scanning.pattern_server
        old_pattern_server = config.pop("pattern_server")

        # Remove deprecated 'enabled' field
        if isinstance(old_pattern_server, dict) and "enabled" in old_pattern_server:
            enabled = old_pattern_server.pop("enabled")
            # If it was explicitly disabled, set to null instead
            if not enabled:
                old_pattern_server = None

        # Ensure secret_scanning section exists
        if "secret_scanning" not in config:
            config["secret_scanning"] = {}

        # Move pattern_server under secret_scanning
        config["secret_scanning"]["pattern_server"] = old_pattern_server

        return True, config

    def setup_remote_config(self, url: str, dry_run: bool = False) -> Tuple[bool, str]:
        """
        Add remote config URL to ai-guardian config.

        Args:
            url: Remote config URL to add
            dry_run: If True, show what would be changed without applying

        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            # Get config path
            config_dir = get_config_dir()
            config_path = config_dir / "ai-guardian.json"

            # Load existing config or create new
            config = {}
            if config_path.exists():
                try:
                    with open(config_path, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                except json.JSONDecodeError as e:
                    return False, f"Invalid JSON in {config_path}: {e}"

            # Check if remote_configs section exists
            if "remote_configs" not in config:
                config["remote_configs"] = {"urls": []}
            elif "urls" not in config["remote_configs"]:
                config["remote_configs"]["urls"] = []

            # Check if URL already exists
            existing_urls = [entry.get('url') if isinstance(entry, dict) else entry
                           for entry in config["remote_configs"]["urls"]]
            if url in existing_urls:
                return False, f"Remote config URL already exists: {url}"

            # Add new URL with enabled flag
            new_entry = {"url": url, "enabled": True}
            config["remote_configs"]["urls"].append(new_entry)

            if dry_run:
                message = f"[DRY RUN] Would add remote config to {config_path}:\n"
                message += json.dumps(config, indent=2)
                return True, message

            # Ensure parent directory exists
            config_path.parent.mkdir(parents=True, exist_ok=True)

            # Create backup if file exists
            if config_path.exists():
                backup_path = self.backup_config(config_path)
                if backup_path:
                    print(f"✓ Backup created: {backup_path}", file=sys.stderr)

            # Write config
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
                f.write('\n')  # Add trailing newline

            message = f"✓ Successfully added remote config URL to {config_path}\n"
            message += f"  URL: {url}\n"

            return True, message

        except Exception as e:
            return False, f"Error setting up remote config: {e}"

    def check_and_migrate_pattern_server(
        self,
        dry_run: bool = False,
        interactive: bool = True
    ) -> Tuple[bool, str]:
        """
        Check for old pattern_server config and offer to migrate.

        Args:
            dry_run: If True, show what would be changed without applying
            interactive: If True, prompt user for confirmation

        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            # Get config path
            config_dir = get_config_dir()
            config_path = config_dir / "ai-guardian.json"

            # Check if config exists
            if not config_path.exists():
                return True, "No ai-guardian.json found - nothing to migrate"

            # Load config
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            except json.JSONDecodeError as e:
                return False, f"Invalid JSON in {config_path}: {e}"

            # Check if migration needed
            migrated, updated_config = self.migrate_pattern_server_config(config)

            if not migrated:
                return True, "✓ Configuration already using new structure (v1.7.0+)"

            # Show what will change
            message = f"Found deprecated pattern_server configuration at root level.\n"
            message += f"Will migrate to new structure (v1.7.0+): secret_scanning.pattern_server\n\n"

            if dry_run:
                message += f"[DRY RUN] Would update {config_path}:\n"
                message += json.dumps(updated_config, indent=2)
                return True, message

            # Confirm with user if interactive
            if interactive:
                print(message)
                print(f"Config file: {config_path}")
                try:
                    response = input("\nMigrate now? [y/N]: ")
                    if response.lower() not in ['y', 'yes']:
                        return False, "Migration cancelled"
                except KeyboardInterrupt:
                    return False, "\nMigration cancelled"

            # Create backup
            backup_path = self.backup_config(config_path)
            if backup_path:
                print(f"✓ Backup created: {backup_path}", file=sys.stderr)

            # Write migrated config
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(updated_config, f, indent=2)
                f.write('\n')  # Add trailing newline

            message = f"✓ Successfully migrated pattern_server configuration\n"
            message += f"  Config file: {config_path}\n"
            message += f"  Backup: {backup_path}\n"
            message += f"\n  Changes:\n"
            message += f"  • Moved pattern_server from root level to secret_scanning.pattern_server\n"
            message += f"  • Removed deprecated 'enabled' field (presence = enabled)\n"

            return True, message

        except Exception as e:
            return False, f"Error migrating pattern_server config: {e}"


def create_default_config(
    permissive: bool = False,
    dry_run: bool = False
) -> Tuple[bool, str]:
    """
    Create default ai-guardian.json config file.

    Args:
        permissive: If True, use permissive config (permissions disabled)
        dry_run: If True, show what would be created without writing

    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        # Check if config already exists
        if config_path.exists() and not dry_run:
            return False, f"Config already exists: {config_path}"

        # Generate config based on mode
        config = _get_default_config_template(permissive)

        if dry_run:
            message = f"[DRY RUN] Would create {config_path}:\n\n"
            message += json.dumps(config, indent=2)
            return True, message

        # Ensure directory exists
        config_dir.mkdir(parents=True, exist_ok=True)

        # Write config
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
            f.write('\n')

        message = f"✓ Created default config: {config_path}\n"
        message += f"\n  Security settings:\n"
        message += f"  • Secret scanning: Enabled (LeakTK patterns)\n"
        message += f"  • Prompt injection: Enabled (medium sensitivity)\n"
        message += f"  • SSRF protection: Enabled (blocks private IPs, metadata endpoints)\n"

        if permissive:
            message += f"  • Permissions: Disabled (all tools allowed)\n"
        else:
            message += f"  • Permissions: Enabled (Skills/MCP blocked by default)\n"
            message += f"\n  Next steps:\n"
            message += f"  1. Run 'ai-guardian tui' to configure allowed skills\n"
            message += f"  2. Or edit {config_path} manually\n"

        return True, message

    except Exception as e:
        return False, f"Error creating default config: {e}"


def _get_default_config_template(permissive: bool = False) -> Dict:
    """
    Get default config template based on mode.

    Args:
        permissive: If True, return permissive config (permissions disabled)

    Returns:
        dict: Default configuration
    """
    config = {
        "$schema": "https://raw.githubusercontent.com/itdove/ai-guardian/main/src/ai_guardian/schemas/ai-guardian-config.schema.json",

        "_comment_secret_scanning": "Scan for secrets (API keys, tokens, passwords) using Gitleaks patterns",
        "secret_scanning": {
            "enabled": True,
            "pattern_server": {
                "url": "https://raw.githubusercontent.com/leaktk/patterns/main/target",
                "patterns_endpoint": "/patterns/gitleaks/8.27.0",
                "warn_on_failure": True,
                "cache": {
                    "path": "~/.cache/ai-guardian/patterns.toml",
                    "refresh_interval_hours": 12,
                    "expire_after_hours": 168
                }
            }
        },

        "_comment_prompt_injection": "Detect and block prompt injection attacks that try to manipulate AI behavior",
        "prompt_injection": {
            "enabled": True,
            "detector": "heuristic",
            "sensitivity": "medium",
            "max_score_threshold": 0.75,
            "allowlist_patterns": [],
            "custom_patterns": [],
            "ignore_tools": [],
            "ignore_files": [],
            "unicode_detection": {
                "enabled": True,
                "detect_zero_width": True,
                "detect_bidi_override": True,
                "detect_tag_chars": True,
                "detect_homoglyphs": True,
                "allow_rtl_languages": True,
                "allow_emoji": True
            }
        },

        "_comment_secret_redaction": "Redact secrets from tool outputs instead of blocking (NEW in v1.5.0, Phase 4)",
        "secret_redaction": {
            "enabled": True,
            "action": "warn",
            "preserve_format": True,
            "log_redactions": True,
            "additional_patterns": []
        },

        "_comment_ssrf_protection": "Prevent SSRF attacks by blocking access to private networks, metadata endpoints, and dangerous URL schemes (NEW in v1.5.0)",
        "ssrf_protection": {
            "enabled": True,
            "action": "block",
            "additional_blocked_ips": [],
            "additional_blocked_domains": [],
            "allow_localhost": False,
            "allowed_domains": []
        },

        "_comment_config_file_scanning": "Detect credential exfiltration commands in AI config files (CLAUDE.md, AGENTS.md, etc.) - Phase 3 of Hermes integration (NEW in v1.5.0)",
        "config_file_scanning": {
            "enabled": True,
            "action": "block",
            "additional_files": [],
            "ignore_files": [],
            "additional_patterns": []
        },

        "_comment_permissions": "Control which tools (Skills, MCP servers, Bash, etc.) are allowed to run",
        "permissions": {
            "enabled": not permissive,
            "rules": [] if permissive else [
                {
                    "_comment": "Skills - Blocked by default. Add allow rules via TUI.",
                    "matcher": "Skill",
                    "mode": "deny",
                    "patterns": ["*"]
                },
                {
                    "_comment": "MCP Servers - Blocked by default. Add allow rules via TUI.",
                    "matcher": "mcp__*",
                    "mode": "deny",
                    "patterns": ["*"]
                }
            ]
        },

        "_comment_permissions_directories": "OPTIONAL/ADVANCED: Auto-discover tool permissions from directories/GitHub repos. Scans for permission files and merges discovered rules into permissions.rules. Most users should use remote_configs instead.",
        "_permissions_directories_example": [
            {
                "_comment": "Example: scan local skills directory to auto-allow discovered skills",
                "matcher": "Skill",
                "mode": "allow",
                "url": "~/.claude/skills"
            },
            {
                "_comment": "Example: scan GitHub repository for skills",
                "matcher": "Skill",
                "mode": "allow",
                "url": "https://github.com/your-org/skills/tree/main/skills",
                "token_env": "GITHUB_TOKEN"
            }
        ],

        "_comment_directory_rules": "OPTIONAL: Control AI access to specific directories (e.g., block ~/.ssh). See ai-guardian-example.json for examples.",
        "_directory_rules_example": {
            "action": "block",
            "rules": [
                {
                    "mode": "deny",
                    "paths": ["~/.ssh/**", "~/.aws/**"]
                }
            ]
        },

        "_comment_remote_configs": "Load additional policies from remote URLs (for enterprise/team policies)",
        "remote_configs": {
            "urls": []
        },

        "_comment_violation_logging": "Log blocked operations for audit and review (NEW in v1.1.0)",
        "violation_logging": {
            "enabled": True,
            "max_entries": 1000,
            "retention_days": 30,
            "log_types": ["tool_permission", "directory_blocking", "secret_detected", "secret_redaction", "prompt_injection"]
        }
    }

    return config


def _auto_install_hook(git_root_path: Path, hooks_dir: Path, git_template: Path, yaml_template: Path) -> Tuple[bool, str]:
    """
    Automatically install pre-commit hook.

    Only called when allow_auto_install=True and no existing hooks detected.

    Args:
        git_root_path: Git repository root
        hooks_dir: .git/hooks directory
        git_template: Path to git hook template
        yaml_template: Path to YAML template

    Returns:
        Tuple of (success, message)
    """
    import shutil

    # Check if pre-commit framework is available
    try:
        subprocess.run(["pre-commit", "--version"], capture_output=True, check=True)
        has_precommit_framework = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        has_precommit_framework = False

    try:
        if has_precommit_framework:
            # Install pre-commit framework config
            dest = git_root_path / ".pre-commit-config.yaml"
            shutil.copy(yaml_template, dest)

            # Run pre-commit install
            try:
                subprocess.run(["pre-commit", "install"], cwd=git_root_path, check=True, capture_output=True)
                return True, (
                    f"✅ Auto-installed pre-commit framework hook!\n"
                    f"  Config: {dest}\n"
                    f"\n"
                    f"The hook will run automatically on 'git commit'.\n"
                    f"To skip: git commit --no-verify"
                )
            except subprocess.CalledProcessError as e:
                return True, (
                    f"✅ Created {dest}\n"
                    f"⚠️  Run 'pre-commit install' to activate\n"
                    f"Error: {e}"
                )
        else:
            # Install git hook
            dest = hooks_dir / "pre-commit"
            shutil.copy(git_template, dest)
            os.chmod(dest, 0o755)

            return True, (
                f"✅ Auto-installed git hook!\n"
                f"  Location: {dest}\n"
                f"\n"
                f"The hook will run automatically on 'git commit'.\n"
                f"To skip: git commit --no-verify"
            )
    except Exception as e:
        return False, f"Error auto-installing hook: {e}"


def uninstall_precommit_hooks(dry_run: bool = False, interactive: bool = True) -> Tuple[bool, str]:
    """
    Remove AI Guardian pre-commit hooks.

    Only removes hooks that were installed by AI Guardian.
    For integrated hooks, shows instructions for manual removal.

    Args:
        dry_run: If True, show what would be removed without doing it
        interactive: If True, prompt for confirmation

    Returns:
        Tuple of (success, message)
    """
    # Find git root
    try:
        git_root = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False, "Error: Not in a git repository"

    git_root_path = Path(git_root)
    hooks_dir = git_root_path / ".git" / "hooks"
    git_hook = hooks_dir / "pre-commit"
    yaml_config = git_root_path / ".pre-commit-config.yaml"

    removed = []
    cannot_remove = []

    # Check git hook
    if git_hook.exists():
        try:
            with open(git_hook, 'r') as f:
                content = f.read()
                # Check if this is our hook
                if 'AI Guardian pre-commit hook' in content or 'ai-guardian scan' in content:
                    if interactive and not dry_run:
                        response = input(f"Remove git hook at {git_hook}? [y/N]: ")
                        if response.lower() != 'y':
                            return False, "Removal cancelled"

                    if not dry_run:
                        git_hook.unlink()
                        removed.append(f"Git hook: {git_hook}")
                    else:
                        removed.append(f"Would remove git hook: {git_hook}")
                else:
                    cannot_remove.append(
                        f"Git hook at {git_hook} doesn't appear to be AI Guardian's.\n"
                        f"  To remove AI Guardian from this hook, manually edit and remove:\n"
                        f"  'ai-guardian scan --exit-code .'"
                    )
        except Exception as e:
            cannot_remove.append(f"Error checking git hook: {e}")

    # Check pre-commit config
    if yaml_config.exists():
        try:
            with open(yaml_config, 'r') as f:
                content = f.read()
                # Check if this is entirely our config or mixed
                if '# AI Guardian pre-commit hook configuration' in content:
                    # This is our file
                    if interactive and not dry_run:
                        response = input(f"Remove pre-commit config at {yaml_config}? [y/N]: ")
                        if response.lower() != 'y':
                            return False, "Removal cancelled"

                    if not dry_run:
                        yaml_config.unlink()
                        removed.append(f"Pre-commit config: {yaml_config}")
                    else:
                        removed.append(f"Would remove config: {yaml_config}")
                elif 'ai-guardian' in content.lower():
                    cannot_remove.append(
                        f"Found ai-guardian in {yaml_config}\n"
                        f"  This appears to be a mixed configuration.\n"
                        f"  To remove AI Guardian, manually edit {yaml_config} and remove the ai-guardian entry."
                    )
        except Exception as e:
            cannot_remove.append(f"Error checking pre-commit config: {e}")

    # Build message
    if not removed and not cannot_remove:
        return True, "No AI Guardian pre-commit hooks found."

    message = []
    if removed:
        message.append("✅ Removed AI Guardian hooks:\n")
        for item in removed:
            message.append(f"  • {item}")
        message.append("")

    if cannot_remove:
        message.append("⚠️  Manual removal required:\n")
        for item in cannot_remove:
            message.append(f"  {item}\n")

    return True, "\n".join(message)


def install_precommit_hooks(dry_run: bool = False, interactive: bool = True, allow_auto_install: bool = False) -> Tuple[bool, str]:
    """
    Show pre-commit hook templates and integration instructions.

    By default, does NOT auto-install to avoid conflicts with existing company hooks.
    Instead, provides templates and instructions for manual integration.

    Auto-install can be enabled with allow_auto_install=True (e.g., from config file).

    Args:
        dry_run: If True, show what would be done without checking files
        interactive: If True, show interactive prompts for warnings
        allow_auto_install: If True, allow automatic installation (default: False for safety)

    Returns:
        Tuple of (success, message)
    """
    # Find git root
    try:
        git_root = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False, "Error: Not in a git repository"

    git_root_path = Path(git_root)
    hooks_dir = git_root_path / ".git" / "hooks"

    if not hooks_dir.exists():
        return False, f"Error: Git hooks directory not found: {hooks_dir}"

    # Get template paths
    import ai_guardian
    # Templates are in the repo root, not in the package
    package_dir = Path(ai_guardian.__file__).parent
    # Go up to find templates (handles both dev and installed scenarios)
    for parent_level in ["..", "../..", "../../.."]:
        potential_template_dir = (package_dir / parent_level / "templates").resolve()
        if potential_template_dir.exists():
            template_dir = potential_template_dir
            break
    else:
        # Fallback: check if templates are next to the package
        template_dir = package_dir.parent / "templates"

    git_template = template_dir / "pre-commit.sh"
    yaml_template = template_dir / ".pre-commit-config.yaml"

    if not git_template.exists() or not yaml_template.exists():
        return False, f"Error: Templates not found in {package_dir / 'templates'}"

    # Check for existing hooks (ignore .sample files from git init)
    existing_git_hook = hooks_dir / "pre-commit"
    existing_yaml_config = git_root_path / ".pre-commit-config.yaml"

    warnings = []
    has_existing_hooks = False
    if existing_git_hook.exists() and not existing_git_hook.is_symlink():
        # Check if it's a real hook (not just the sample)
        try:
            with open(existing_git_hook, 'r') as f:
                content = f.read()
                # Git's sample hooks start with a shebang and contain "sample"
                if content.strip() and not (content.startswith('#!/bin/sh') and 'sample' in content.lower() and len(content) < 500):
                    warnings.append(f"⚠️  Existing git hook found: {existing_git_hook}")
                    has_existing_hooks = True
        except Exception:
            # If we can't read it, assume it's real
            warnings.append(f"⚠️  Existing git hook found: {existing_git_hook}")
            has_existing_hooks = True
    if existing_yaml_config.exists():
        warnings.append(f"⚠️  Existing pre-commit config found: {existing_yaml_config}")
        has_existing_hooks = True

    # If auto-install is enabled and no existing hooks, perform installation
    if allow_auto_install and not has_existing_hooks and not dry_run:
        return _auto_install_hook(git_root_path, hooks_dir, git_template, yaml_template)

    # Check if pre-commit framework is available
    try:
        subprocess.run(
            ["pre-commit", "--version"],
            capture_output=True,
            check=True
        )
        has_precommit_framework = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        has_precommit_framework = False

    # Build informational message
    message = [
        "📋 AI Guardian Pre-commit Hook Templates",
        "",
        "Templates are available at:",
        f"  • Git hook: {git_template}",
        f"  • pre-commit framework: {yaml_template}",
        "",
    ]

    if allow_auto_install and has_existing_hooks:
        message.extend([
            "ℹ️  Auto-install flag provided, but existing hooks detected.",
            "   Showing manual integration instructions to avoid conflicts.",
            "",
        ])

    if warnings:
        message.extend(warnings)
        message.extend([
            "",
            "❌ Auto-install disabled - existing hooks detected!",
            "",
            "To avoid conflicts with company/existing hooks, AI Guardian",
            "does NOT auto-install. Instead, manually integrate:",
            "",
        ])
    else:
        message.extend([
            "No existing hooks detected.",
            "",
            "Choose your integration method:",
            "",
        ])

    # Option 1: Git hook (always available)
    message.extend([
        "Option 1: Git Hook (Direct Integration)",
        "──────────────────────────────────────",
        f"  cp {git_template} {existing_git_hook}",
        f"  chmod +x {existing_git_hook}",
        "",
        "  Or if you have existing hooks, add this to your hook:",
        "  ┌─────────────────────────────────────────┐",
        "  │ ai-guardian scan --exit-code .          │",
        "  └─────────────────────────────────────────┘",
        "",
    ])

    # Option 2: pre-commit framework (if available)
    if has_precommit_framework:
        message.extend([
            "Option 2: pre-commit Framework (Recommended)",
            "─────────────────────────────────────────────",
        ])
        if existing_yaml_config.exists():
            message.extend([
                f"  Add to existing {existing_yaml_config}:",
                "  ┌─────────────────────────────────────────┐",
                "  │ repos:                                  │",
                "  │   - repo: local                         │",
                "  │     hooks:                              │",
                "  │       - id: ai-guardian                 │",
                "  │         name: AI Guardian Security Scan │",
                "  │         entry: ai-guardian scan --exit-code │",
                "  │         language: system                │",
                "  │         pass_filenames: false           │",
                "  └─────────────────────────────────────────┘",
            ])
        else:
            message.extend([
                f"  cp {yaml_template} {existing_yaml_config}",
                "  pre-commit install",
            ])
        message.extend(["", "  Then test: pre-commit run --all-files", ""])
    else:
        message.extend([
            "Option 2: pre-commit Framework",
            "──────────────────────────────",
            "  Not installed. Install with:",
            "    pip install pre-commit",
            "",
            f"  Then: cp {yaml_template} {existing_yaml_config}",
            "        pre-commit install",
            "",
        ])

    # Footer
    message.extend([
        "Testing:",
        "  git commit      # Hook runs automatically",
        "  git commit --no-verify  # Skip hook (not recommended)",
        "",
        "Need help? See templates for full examples.",
    ])

    return True, "\n".join(message)


def setup_hooks(
    ide_type: Optional[str] = None,
    remote_config_url: Optional[str] = None,
    dry_run: bool = False,
    force: bool = False,
    interactive: bool = True,
    migrate_pattern_server: bool = False,
    create_config: bool = False,
    permissive: bool = False,
    pre_commit: bool = False,
    auto_install_hooks: bool = False,
    uninstall_hooks: bool = False,
    install_scanner: Optional[str] = None
) -> bool:
    """
    Setup IDE hooks with optional remote config and default config creation.

    Args:
        ide_type: IDE type ('claude' or 'cursor') or None for auto-detect
        remote_config_url: Optional remote config URL to add
        dry_run: If True, show what would be changed without applying
        force: If True, overwrite existing hooks
        interactive: If True, prompt user for confirmation
        migrate_pattern_server: If True, check and migrate old pattern_server config
        create_config: If True, create default ai-guardian.json config
        permissive: If True with create_config, use permissive config (permissions disabled)
        pre_commit: If True, install pre-commit hooks for git
        auto_install_hooks: If True, allow automatic hook installation (default: False for safety)
        uninstall_hooks: If True, remove AI Guardian pre-commit hooks
        install_scanner: Optional scanner name to install (gitleaks, betterleaks, or leaktk)

    Returns:
        bool: True if successful, False otherwise
    """
    setup = IDESetup()

    # Handle scanner installation if requested (NEW in v1.6.0)
    if install_scanner:
        if dry_run:
            print(f"[DRY RUN] Would install scanner: {install_scanner}")
        else:
            try:
                from ai_guardian.scanner_installer import ScannerInstaller

                print(f"\n🛡️  Installing {install_scanner} scanner...\n")
                installer = ScannerInstaller()

                success = installer.install(install_scanner)

                if success:
                    # Verify installation
                    if installer.verify_installation(install_scanner):
                        print(f"\n✓ {install_scanner} is ready to use\n")
                    else:
                        print(f"\n⚠  Installation completed but {install_scanner} verification failed")
                        print("Make sure ~/.local/bin is in your PATH\n")
                        if interactive:
                            response = input("Continue with IDE setup anyway? (y/n): ")
                            if response.lower() != 'y':
                                return False
                else:
                    print(f"\n✗ Failed to install {install_scanner}\n")
                    if interactive:
                        response = input("Continue with IDE setup anyway? (y/n): ")
                        if response.lower() != 'y':
                            return False

            except Exception as e:
                print(f"Error installing scanner: {e}")
                if interactive:
                    response = input("Continue with IDE setup anyway? (y/n): ")
                    if response.lower() != 'y':
                        return False

    # Handle pre-commit hook uninstallation if requested
    if pre_commit and uninstall_hooks:
        success, message = uninstall_precommit_hooks(
            dry_run=dry_run,
            interactive=interactive
        )
        print(message)
        return success

    # Handle pre-commit hook installation if requested
    if pre_commit:
        success, message = install_precommit_hooks(
            dry_run=dry_run,
            interactive=interactive,
            allow_auto_install=auto_install_hooks
        )
        print(message)
        if not success:
            return False
        # If only installing pre-commit (no IDE setup or config), return early
        if ide_type is None and not remote_config_url and not migrate_pattern_server and not create_config:
            return success

    # Handle default config creation if requested
    if create_config:
        success, message = create_default_config(permissive=permissive, dry_run=dry_run)
        print(message)
        if not success:
            return False
        # If only creating config (no IDE setup or remote config), return early
        if ide_type is None and not remote_config_url and not migrate_pattern_server:
            return success

    # Handle pattern_server migration if requested
    if migrate_pattern_server:
        success, message = setup.check_and_migrate_pattern_server(
            dry_run=dry_run,
            interactive=interactive
        )
        print(message)
        if not success and not message.endswith("cancelled"):
            return False
        # If only migrating (no IDE setup or remote config), return early
        if ide_type is None and not remote_config_url:
            return success

    # Handle remote config setup if requested
    if remote_config_url:
        success, message = setup.setup_remote_config(remote_config_url, dry_run=dry_run)
        print(message)
        if not success:
            return False
        # If only setting up remote config (no IDE setup), return early
        if ide_type is None and not migrate_pattern_server:
            return success

    # Auto-detect IDE if not specified
    if not ide_type:
        detected_ides = setup.list_detected_ides()

        if not detected_ides:
            print("Error: No IDE detected. Please install Claude Code or Cursor IDE.", file=sys.stderr)
            print("\nSupported IDEs:", file=sys.stderr)
            print("  - Claude Code: https://claude.ai/code", file=sys.stderr)
            print("  - Cursor: https://cursor.sh", file=sys.stderr)
            return False

        elif len(detected_ides) == 1:
            ide_type = detected_ides[0]
            print(f"Detected IDE: {setup.IDE_CONFIGS[ide_type]['name']}")

        else:
            # Multiple IDEs detected
            print("Multiple IDEs detected:")
            for i, ide in enumerate(detected_ides, 1):
                print(f"  {i}. {setup.IDE_CONFIGS[ide]['name']}")

            if interactive and not dry_run:
                try:
                    choice = input("\nSelect IDE (1-{}): ".format(len(detected_ides)))
                    idx = int(choice) - 1
                    if 0 <= idx < len(detected_ides):
                        ide_type = detected_ides[idx]
                    else:
                        print("Error: Invalid selection", file=sys.stderr)
                        return False
                except (ValueError, KeyboardInterrupt):
                    print("\nError: Invalid input", file=sys.stderr)
                    return False
            else:
                print("\nError: Multiple IDEs detected. Please specify with --ide flag.", file=sys.stderr)
                return False

    # Validate IDE type
    if ide_type not in setup.IDE_CONFIGS:
        print(f"Error: Unknown IDE type: {ide_type}", file=sys.stderr)
        print(f"Supported IDEs: {', '.join(setup.IDE_CONFIGS.keys())}", file=sys.stderr)
        return False

    # Confirm with user if interactive
    if interactive and not dry_run and not force:
        ide_name = setup.IDE_CONFIGS[ide_type]['name']
        config_path = setup.get_config_path(ide_type)

        print(f"\nThis will configure ai-guardian hooks for {ide_name}")
        print(f"Config file: {config_path}")

        try:
            response = input("\nContinue? [y/N]: ")
            if response.lower() not in ['y', 'yes']:
                print("Aborted.")
                return False
        except KeyboardInterrupt:
            print("\nAborted.")
            return False

    # Setup IDE hooks
    success, message = setup.setup_ide_hooks(ide_type, dry_run=dry_run, force=force)
    print(message)

    return success
