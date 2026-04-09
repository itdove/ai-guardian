#!/usr/bin/env python3
"""
Setup Command for ai-guardian

Automatically configures IDE hooks for Claude Code and Cursor,
with support for remote configuration URLs.
"""

import json
import os
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

    def merge_hooks(self, existing_config: Dict, ai_guardian_hooks: Dict, ide_type: str) -> Dict:
        """
        Merge ai-guardian hooks into existing config.

        Args:
            existing_config: Existing IDE configuration
            ai_guardian_hooks: AI Guardian hooks to add
            ide_type: IDE type ('claude' or 'cursor')

        Returns:
            dict: Merged configuration
        """
        if ide_type == "claude":
            # Claude Code: merge into hooks section
            if "hooks" not in existing_config:
                existing_config["hooks"] = {}

            # Merge UserPromptSubmit, PreToolUse, and PostToolUse hooks
            for hook_name in ["UserPromptSubmit", "PreToolUse", "PostToolUse"]:
                if hook_name in ai_guardian_hooks:
                    existing_config["hooks"][hook_name] = ai_guardian_hooks[hook_name]

            return existing_config

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

            return existing_config

        return existing_config

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
            if ide_type == "claude":
                merged_config = self.merge_hooks(existing_config, ide_config["hooks"], ide_type)
            elif ide_type == "cursor":
                # For Cursor, we need to merge differently
                merged_config = existing_config.copy()
                if "version" not in merged_config:
                    merged_config["version"] = ide_config["hooks"]["version"]
                if "hooks" not in merged_config:
                    merged_config["hooks"] = {}
                merged_config["hooks"]["beforeSubmitPrompt"] = ide_config["hooks"]["beforeSubmitPrompt"]
                merged_config["hooks"]["beforeReadFile"] = ide_config["hooks"]["beforeReadFile"]

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

            message = f"✓ Successfully configured {ide_name} hooks at {config_path}\n"
            message += f"\n  Next steps:\n"
            message += f"  1. Restart {ide_name} for changes to take effect\n"
            message += f"  2. Test with: echo '{{\"prompt\": \"test\"}}' | ai-guardian\n"

            return True, message

        except Exception as e:
            return False, f"Error setting up IDE hooks: {e}"

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


def setup_hooks(
    ide_type: Optional[str] = None,
    remote_config_url: Optional[str] = None,
    dry_run: bool = False,
    force: bool = False,
    interactive: bool = True
) -> bool:
    """
    Setup IDE hooks with optional remote config.

    Args:
        ide_type: IDE type ('claude' or 'cursor') or None for auto-detect
        remote_config_url: Optional remote config URL to add
        dry_run: If True, show what would be changed without applying
        force: If True, overwrite existing hooks
        interactive: If True, prompt user for confirmation

    Returns:
        bool: True if successful, False otherwise
    """
    setup = IDESetup()

    # Handle remote config setup if requested
    if remote_config_url:
        success, message = setup.setup_remote_config(remote_config_url, dry_run=dry_run)
        print(message)
        if not success:
            return False

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
