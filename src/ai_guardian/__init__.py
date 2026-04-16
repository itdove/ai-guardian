#!/usr/bin/env python3
"""
AI IDE Security Hook

AI Guardian provides multi-layered protection for AI IDE interactions:
- Directory blocking with .ai-read-deny markers
- Secret scanning using Gitleaks
- Multi-IDE support (Claude Code, Cursor, VS Code Claude)

Automatically detects IDE type and uses appropriate response format.
"""

__version__ = "1.3.0"

import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, Optional

from ai_guardian.config_utils import get_config_dir, is_feature_enabled

# Import tool policy checker for MCP/Skill permissions
try:
    from ai_guardian.tool_policy import ToolPolicyChecker
    HAS_TOOL_POLICY = True
except ImportError:
    HAS_TOOL_POLICY = False
    logging.warning("tool_policy module not available - MCP/Skill permissions disabled")

# Import pattern server for enhanced secret detection
try:
    from ai_guardian.pattern_server import PatternServerClient
    HAS_PATTERN_SERVER = True
except ImportError:
    HAS_PATTERN_SERVER = False
    logging.debug("pattern_server module not available")

# Import prompt injection detector
try:
    from ai_guardian.prompt_injection import check_prompt_injection
    HAS_PROMPT_INJECTION = True
except ImportError:
    HAS_PROMPT_INJECTION = False
    logging.debug("prompt_injection module not available")

# Import violation logger
try:
    from ai_guardian.violation_logger import ViolationLogger
    HAS_VIOLATION_LOGGER = True
except ImportError:
    HAS_VIOLATION_LOGGER = False
    logging.debug("violation_logger module not available")

# Configure logging - will be disabled for Cursor hooks
# Set up file handler with rotation
_log_file = get_config_dir() / "ai-guardian.log"
_log_file.parent.mkdir(parents=True, exist_ok=True)

_file_handler = RotatingFileHandler(
    _log_file,
    maxBytes=5*1024*1024,  # 5 MB
    backupCount=3,
    encoding='utf-8'
)
_file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

# Configure root logger with both stderr and file handlers
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",  # Simple format for stderr
    handlers=[
        logging.StreamHandler(sys.stderr),  # Keep stderr output for IDE compatibility
        _file_handler  # Add file output
    ]
)

# Global logger instance
logger = logging.getLogger(__name__)


class IDEType(Enum):
    """Supported IDE types with different output formats."""
    CLAUDE_CODE = "claude_code"  # Exit codes: 0=allow, 2=block
    CURSOR = "cursor"  # JSON: {"continue": bool, "user_message": str}
    GITHUB_COPILOT = "github_copilot"  # JSON: {"permissionDecision": "allow"|"deny"}
    UNKNOWN = "unknown"  # Default to Claude Code format


def detect_ide_type(hook_data):
    """
    Detect which IDE is calling the hook based on input format.

    Args:
        hook_data: Parsed JSON input from the IDE

    Returns:
        IDEType: The detected IDE type
    """
    # Check for environment variable override
    ide_override = os.environ.get("AI_GUARDIAN_IDE_TYPE", "").lower()
    if ide_override == "cursor":
        return IDEType.CURSOR
    elif ide_override == "claude":
        return IDEType.CLAUDE_CODE
    elif ide_override == "github_copilot" or ide_override == "copilot":
        return IDEType.GITHUB_COPILOT

    # Auto-detect based on input structure
    # GitHub Copilot detection - check for toolName field (most specific)
    if "toolName" in hook_data:
        return IDEType.GITHUB_COPILOT

    # GitHub Copilot detection - timestamp + cwd + prompt pattern
    if "timestamp" in hook_data and "cwd" in hook_data:
        return IDEType.GITHUB_COPILOT

    # Cursor sends cursor_version field
    if "cursor_version" in hook_data:
        return IDEType.CURSOR

    # Cursor typically sends hook_name or beforeSubmitPrompt event
    if "hook_name" in hook_data or (
        "hook_event_name" in hook_data and
        hook_data.get("hook_event_name") in ["beforeSubmitPrompt", "preToolUse"]
    ):
        return IDEType.CURSOR

    # Claude Code sends UserPromptSubmit or PreToolUse
    if "hook_event_name" in hook_data and hook_data.get("hook_event_name") in ["UserPromptSubmit", "PreToolUse"]:
        return IDEType.CLAUDE_CODE

    # Default to Claude Code format (exit codes)
    return IDEType.CLAUDE_CODE


def format_response(ide_type, has_secrets, error_message=None, hook_event="prompt"):
    """
    Format the response based on IDE type and hook event.

    Args:
        ide_type: IDEType enum value
        has_secrets: bool indicating if secrets were found
        error_message: Optional error message for blocked responses
        hook_event: "prompt", "pretooluse", or "posttooluse" to determine response format

    Returns:
        dict with 'output' (str to print) and 'exit_code' (int)
    """
    if ide_type == IDEType.GITHUB_COPILOT:
        # GitHub Copilot uses JSON response format
        if hook_event == "pretooluse":
            # preToolUse expects {"permissionDecision": "allow"|"deny", "permissionDecisionReason": "..."}
            response = {
                "permissionDecision": "deny" if has_secrets else "allow"
            }
            if has_secrets and error_message:
                response["permissionDecisionReason"] = error_message

            return {
                "output": json.dumps(response),
                "exit_code": 0  # GitHub Copilot uses JSON response, not exit code
            }
        else:
            # userPromptSubmitted uses exit codes like Claude Code
            if has_secrets and error_message:
                # Print error to stderr
                print(error_message, file=sys.stderr)

            return {
                "output": None,
                "exit_code": 2 if has_secrets else 0
            }
    elif ide_type == IDEType.CURSOR:
        # Cursor uses JSON response to determine block/allow, not exit code
        if hook_event == "pretooluse":
            # preToolUse expects {"decision": "allow"|"deny", "reason": "..."}
            response = {
                "decision": "deny" if has_secrets else "allow",
            }
            if has_secrets and error_message:
                response["reason"] = error_message
        elif hook_event == "beforereadfile":
            # beforeReadFile expects {"permission": "allow"|"deny", "user_message": "..."}
            response = {
                "permission": "deny" if has_secrets else "allow",
            }
            if has_secrets and error_message:
                response["user_message"] = error_message
        else:
            # beforeSubmitPrompt expects {"continue": bool, "user_message": "..."}
            response = {
                "continue": not has_secrets,
            }
            if has_secrets and error_message:
                response["user_message"] = error_message

        return {
            "output": json.dumps(response),
            "exit_code": 0  # Cursor uses JSON response, not exit code
        }
    else:
        # Claude Code
        if hook_event == "posttooluse":
            # PostToolUse expects JSON response with decision/reason format
            if has_secrets:
                response = {
                    "decision": "block",
                    "reason": error_message or "Secrets detected in tool output",
                    "hookSpecificOutput": {
                        "hookEventName": "PostToolUse",
                        "additionalContext": "Tool output contained sensitive information and was blocked by ai-guardian"
                    }
                }
            else:
                # Allow - return empty JSON or omit decision field
                response = {}

            return {
                "output": json.dumps(response),
                "exit_code": 0  # PostToolUse uses JSON response, not exit code
            }
        else:
            # UserPromptSubmit and PreToolUse use exit codes
            if has_secrets and error_message:
                # Print error to stderr
                print(error_message, file=sys.stderr)

            return {
                "output": None,
                "exit_code": 2 if has_secrets else 0
            }


def detect_hook_event(hook_data):
    """
    Detect which hook event triggered this call.

    Args:
        hook_data: Parsed JSON input from the IDE

    Returns:
        str: "prompt" for prompt submission hooks, "pretooluse" for tool use hooks,
             "posttooluse" for post-tool-use hooks
    """
    # Check hook_event_name for both Claude Code and Cursor
    event_name = hook_data.get("hook_event_name", "").lower()
    if event_name in ["userpromptsubmit", "beforesubmitprompt"]:
        return "prompt"
    elif event_name in ["pretooluse"]:
        return "pretooluse"
    elif event_name in ["posttooluse"]:
        return "posttooluse"
    elif event_name in ["beforereadfile"]:
        return "beforereadfile"

    # Check hook_name for Cursor (alternative field)
    hook_name = hook_data.get("hook_name", "").lower()
    if hook_name in ["beforesubmitprompt"]:
        return "prompt"
    elif hook_name in ["pretooluse"]:
        return "pretooluse"

    # GitHub Copilot: detect by presence of toolName field
    if "toolName" in hook_data:
        return "pretooluse"

    # Check for tool_response field (indicates PostToolUse)
    if "tool_response" in hook_data:
        return "posttooluse"

    # Check for tool_use or tool fields (indicates PreToolUse)
    if "tool_use" in hook_data or "tool" in hook_data or "tool_name" in hook_data:
        return "pretooluse"

    # Default to prompt if we have a prompt/message field
    if "prompt" in hook_data or "message" in hook_data or "userMessage" in hook_data:
        return "prompt"

    # Default to prompt
    return "prompt"


def _is_path_excluded(file_path, config):
    """
    Check if a file path is within a directory exclusion.

    Directory exclusions disable .ai-read-deny blocking for specific paths.
    Note: .ai-read-deny markers ALWAYS take precedence over exclusions.

    Args:
        file_path: Absolute path to the file being accessed
        config: Configuration dict containing directory_exclusions

    Returns:
        bool: True if path is excluded (skip .ai-read-deny check), False otherwise
    """
    try:
        # Check if directory_exclusions feature is enabled
        if not config:
            return False

        dir_exclusions = config.get("directory_exclusions", {})

        # Check enabled flag (supports boolean or object format)
        if not is_feature_enabled(dir_exclusions.get("enabled", False)):
            logging.debug("Directory exclusions disabled in config")
            return False

        exclusion_paths = dir_exclusions.get("paths", [])
        if not exclusion_paths:
            logging.debug("No directory exclusion paths configured")
            return False

        # Convert file path to absolute path
        abs_file_path = os.path.abspath(os.path.expanduser(file_path))

        # Check each exclusion path
        for exclusion_path in exclusion_paths:
            if not isinstance(exclusion_path, str):
                logging.warning(f"Invalid exclusion path (not a string): {exclusion_path}")
                continue

            try:
                # Expand tilde and convert to absolute path
                expanded_path = os.path.abspath(os.path.expanduser(exclusion_path))

                # Check for wildcards
                if "**" in expanded_path:
                    # Recursive wildcard: match directory and all subdirectories
                    # Remove /** or ** from end for directory comparison
                    base_path = expanded_path.replace("/**", "").replace("**", "")
                    if abs_file_path.startswith(base_path):
                        logging.debug(f"Path {abs_file_path} matches recursive exclusion: {exclusion_path}")
                        return True
                elif "*" in expanded_path:
                    # Single-level wildcard: use fnmatch for pattern matching
                    import fnmatch
                    # Get parent directory of file for matching
                    file_parent = os.path.dirname(abs_file_path)
                    wildcard_parent = os.path.dirname(expanded_path)

                    # Check if file's parent matches the wildcard pattern
                    if fnmatch.fnmatch(file_parent, expanded_path) or file_parent.startswith(expanded_path.replace("/*", "")):
                        logging.debug(f"Path {abs_file_path} matches wildcard exclusion: {exclusion_path}")
                        return True
                else:
                    # Exact path match: check if file is within excluded directory
                    # Add trailing slash to ensure directory boundary matching
                    if abs_file_path.startswith(expanded_path + os.sep) or abs_file_path == expanded_path:
                        logging.debug(f"Path {abs_file_path} matches exact exclusion: {exclusion_path}")
                        return True

            except Exception as e:
                logging.warning(f"Error processing exclusion path '{exclusion_path}': {e}")
                # Fail-safe: skip this exclusion path, continue checking others
                continue

        return False

    except Exception as e:
        logging.error(f"Error checking directory exclusions: {e}")
        # Fail-safe: if exclusion check fails, don't exclude (let normal blocking proceed)
        return False


def check_directory_denied(file_path, config=None):
    """
    Check if a file is in a directory (or subdirectory) that contains a .ai-read-deny marker file.

    This function walks up the directory tree from the file's location to check if any
    parent directory contains a .ai-read-deny file, which indicates the directory and all
    its subdirectories should be blocked from AI access.

    PRECEDENCE: .ai-read-deny ALWAYS takes precedence over directory exclusions.
    1. First checks for .ai-read-deny marker (if found, BLOCKS regardless of exclusions)
    2. Then checks if path is excluded (if excluded, ALLOWS - skips blocking)
    3. Otherwise ALLOWS (no .ai-read-deny found, not excluded)

    Args:
        file_path: Path to the file being accessed
        config: Optional configuration dict containing directory_exclusions

    Returns:
        tuple: (is_denied: bool, denied_directory: str or None)
               - is_denied: True if access should be blocked
               - denied_directory: The directory containing .ai-read-deny, if found
    """
    try:
        # Load config if not provided
        if config is None and HAS_TOOL_POLICY:
            try:
                policy_checker = ToolPolicyChecker()
                config = policy_checker.config
            except Exception as e:
                logging.debug(f"Could not load config for directory exclusions: {e}")
                config = {}

        # Convert to absolute path
        abs_path = os.path.abspath(file_path)

        # Get the directory containing the file
        current_dir = os.path.dirname(abs_path)

        # PRIORITY 1: Check for .ai-read-deny marker (ALWAYS takes precedence)
        # Walk up the directory tree
        is_path_in_exclusion = _is_path_excluded(abs_path, config) if config else False

        while True:
            deny_marker = os.path.join(current_dir, ".ai-read-deny")

            if os.path.exists(deny_marker):
                # CRITICAL: .ai-read-deny ALWAYS blocks (no config option can override this)
                if is_path_in_exclusion:
                    logging.info(f"Found .ai-read-deny at {current_dir} (blocks even though path is in excluded directory)")
                else:
                    logging.info(f"Found .ai-read-deny marker in {current_dir}")

                # Log directory blocking violation
                _log_directory_blocking_violation(file_path, current_dir, is_excluded=is_path_in_exclusion)

                return True, current_dir

            # Move to parent directory
            parent_dir = os.path.dirname(current_dir)

            # Stop if we've reached the root
            if parent_dir == current_dir:
                break

            current_dir = parent_dir

        # PRIORITY 2: No .ai-read-deny found - check if path is excluded
        # (Exclusions only matter when there's no .ai-read-deny marker)
        if is_path_in_exclusion:
            logging.info(f"Directory exclusion active for {abs_path} (no .ai-read-deny found)")
            return False, None

        # PRIORITY 3: Not excluded, no .ai-read-deny - allow access
        return False, None

    except Exception as e:
        logging.error(f"Error checking for .ai-read-deny: {e}")
        # Fail-open: allow access if check fails
        return False, None


def extract_tool_result(hook_data):
    """
    Extract tool result/output from PostToolUse hook data.

    Only scans tools that produce content the AI reads (Bash, Read, Grep, etc.).
    Skips state-modifying tools (Write, Edit, etc.) since:
    - Their content was already scanned in tool_input (PreToolUse)
    - Their response is just metadata (success, filePath)

    Args:
        hook_data: Parsed JSON input from PostToolUse hook

    Returns:
        tuple: (output: str or None, tool_name: str)
    """
    try:
        # Get tool name from top-level field
        tool_name = hook_data.get("tool_name", "unknown")

        # Tools that modify state - don't scan their responses
        # These return metadata only, content was already scanned in PreToolUse
        STATE_MODIFY_TOOLS = {
            "Write", "Edit", "Delete", "Move", "Rename",
            "NotebookEdit",  # Notebook editing
        }

        if tool_name in STATE_MODIFY_TOOLS:
            logging.debug(f"Skipping PostToolUse scan for state-modifying tool: {tool_name}")
            return None, tool_name

        output = None

        # Claude Code format: tool_response field
        if "tool_response" in hook_data:
            tool_response = hook_data["tool_response"]
            if isinstance(tool_response, dict):
                # Try common output field names
                output = (tool_response.get("output") or
                         tool_response.get("content") or
                         tool_response.get("result"))

                # Don't convert dict to JSON if no explicit output field
                # Metadata dicts aren't meant to be scanned
            elif isinstance(tool_response, str):
                # Direct string response
                output = tool_response

        # Fallback: check for direct output field
        if not output and "output" in hook_data:
            output = hook_data["output"]

        return output, tool_name

    except Exception as e:
        logging.error(f"Error extracting tool result: {e}")
        return None, "unknown"


def extract_file_content_from_tool(hook_data):
    """
    Extract file path/content from PreToolUse/beforeReadFile hook data.

    Args:
        hook_data: Parsed JSON input from PreToolUse or beforeReadFile hook

    Returns:
        tuple: (content: str or None, filename: str, file_path: str or None, is_denied: bool, deny_reason: str or None)
    """
    try:
        # Cursor beforeReadFile format: includes content and file_path directly
        if "content" in hook_data and "file_path" in hook_data:
            content = hook_data["content"]
            file_path = hook_data["file_path"]

            # Check if directory is denied
            is_denied, denied_dir = check_directory_denied(file_path)
            if is_denied:
                error_msg = (
                    f"\n{'='*70}\n"
                    f"🚫 ACCESS DENIED - Directory Protected\n"
                    f"{'='*70}\n\n"
                    f"The file '{file_path}' is located in a directory that contains\n"
                    f"a .ai-read-deny marker file.\n\n"
                    f"Protected directory: {denied_dir}\n\n"
                    f"This directory and all its subdirectories are blocked from AI access.\n"
                    f"Please remove the .ai-read-deny file if you need AI access to this\n"
                    f"directory, or move the file to an accessible location.\n"
                    f"\n{'='*70}\n"
                )
                return None, os.path.basename(file_path), file_path, True, error_msg

            return content, os.path.basename(file_path), file_path, False, None

        # Try to extract file path from different possible locations
        file_path = None

        # Claude Code format: tool_use.parameters.file_path
        if "tool_use" in hook_data:
            tool_use = hook_data["tool_use"]
            if isinstance(tool_use, dict) and "parameters" in tool_use:
                params = tool_use["parameters"]
                file_path = params.get("file_path") or params.get("path")

        # Alternative: direct parameters field
        if not file_path and "parameters" in hook_data:
            params = hook_data["parameters"]
            if isinstance(params, dict):
                file_path = params.get("file_path") or params.get("path")

        # Cursor format: tool_input.file_path
        if not file_path and "tool_input" in hook_data:
            tool_input = hook_data["tool_input"]
            if isinstance(tool_input, dict):
                file_path = tool_input.get("file_path") or tool_input.get("path")

        # Cursor format alternative: tool field
        if not file_path and "tool" in hook_data:
            tool = hook_data["tool"]
            if isinstance(tool, dict):
                file_path = tool.get("file_path") or tool.get("path")

        # GitHub Copilot format: toolName + toolArgs (JSON string)
        if not file_path and "toolName" in hook_data and "toolArgs" in hook_data:
            try:
                # Parse toolArgs from JSON string
                tool_args = json.loads(hook_data["toolArgs"])
                file_path = tool_args.get("file_path") or tool_args.get("path")
            except json.JSONDecodeError:
                logging.warning("Could not parse GitHub Copilot toolArgs JSON")

        if not file_path:
            logging.warning("Could not extract file path from hook data")
            return None, "unknown_file", None, False, None

        # Expand ~ to home directory
        file_path = os.path.expanduser(file_path)

        # Check if directory is denied BEFORE reading the file
        is_denied, denied_dir = check_directory_denied(file_path)
        if is_denied:
            error_msg = (
                f"\n{'='*70}\n"
                f"🚫 ACCESS DENIED - Directory Protected\n"
                f"{'='*70}\n\n"
                f"The file '{file_path}' is located in a directory that contains\n"
                f"a .ai-read-deny marker file.\n\n"
                f"Protected directory: {denied_dir}\n\n"
                f"This directory and all its subdirectories are blocked from AI access.\n"
                f"Please remove the .ai-read-deny file if you need AI access to this\n"
                f"directory, or move the file to an accessible location.\n"
                f"\n{'='*70}\n"
            )
            return None, os.path.basename(file_path), file_path, True, error_msg

        # Read the file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            return content, os.path.basename(file_path), file_path, False, None
        except FileNotFoundError:
            logging.warning(f"File not found: {file_path}")
            return None, os.path.basename(file_path), file_path, False, None
        except PermissionError:
            logging.warning(f"Permission denied reading file: {file_path}")
            return None, os.path.basename(file_path), file_path, False, None
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return None, os.path.basename(file_path), file_path, False, None

    except Exception as e:
        logging.error(f"Error extracting file from tool data: {e}")
        return None, "unknown_file", None, False, None


def _load_pattern_server_config():
    """
    Load pattern server configuration from ai-guardian.json.

    Returns:
        dict: Pattern server configuration or None
    """
    try:
        # Try user global config first
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        if not config_path.exists():
            # Try project local config
            config_path = Path.cwd() / ".ai-guardian.json"

        if not config_path.exists():
            return None

        with open(config_path, 'r') as f:
            config = json.load(f)

        return config.get("pattern_server")

    except Exception as e:
        logging.debug(f"Error loading pattern server config: {e}")
        return None


def _load_prompt_injection_config():
    """
    Load prompt injection configuration from ai-guardian.json.

    Returns:
        dict: Prompt injection configuration or None
    """
    try:
        # Try user global config first
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        if not config_path.exists():
            # Try project local config
            config_path = Path.cwd() / ".ai-guardian.json"

        if not config_path.exists():
            return None

        with open(config_path, 'r') as f:
            config = json.load(f)

        return config.get("prompt_injection")

    except Exception as e:
        logging.debug(f"Error loading prompt injection config: {e}")
        return None


def _load_permissions_config():
    """
    Load permissions configuration from ai-guardian.json.

    Returns:
        dict: Permissions configuration or None
    """
    try:
        # Try user global config first
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        if not config_path.exists():
            # Try project local config
            config_path = Path.cwd() / ".ai-guardian.json"

        if not config_path.exists():
            return None

        with open(config_path, 'r') as f:
            config = json.load(f)

        return config.get("permissions_enabled")

    except Exception as e:
        logging.debug(f"Error loading permissions config: {e}")
        return None


def _load_secret_scanning_config():
    """
    Load secret scanning configuration from ai-guardian.json.

    Returns:
        dict: Secret scanning configuration or None
    """
    try:
        # Try user global config first
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        if not config_path.exists():
            # Try project local config
            config_path = Path.cwd() / ".ai-guardian.json"

        if not config_path.exists():
            return None

        with open(config_path, 'r') as f:
            config = json.load(f)

        return config.get("secret_scanning")

    except Exception as e:
        logging.debug(f"Error loading secret scanning config: {e}")
        return None


def _is_ai_guardian_test_file(file_path):
    """
    Check if a file path is an ai-guardian project test file.

    IMPORTANT: Only skips ai-guardian's own test files, NOT user project test files.
    This prevents attackers from bypassing scanning by putting secrets in test files.

    Args:
        file_path: Path to the file

    Returns:
        bool: True if this is an ai-guardian test file
    """
    if not file_path:
        return False

    import os

    # Get the absolute path
    abs_path = os.path.abspath(file_path)

    # Check if file is in ai-guardian's tests directory
    # Look for ai-guardian package directory in the path
    path_parts = abs_path.split(os.sep)

    # Check if path contains "ai-guardian" or "ai_guardian" AND "tests"
    has_ai_guardian = any('ai-guardian' in part or 'ai_guardian' in part for part in path_parts)
    has_tests = 'tests' in path_parts

    # Only skip if BOTH conditions are met (ai-guardian project + tests directory)
    return has_ai_guardian and has_tests


def _log_directory_blocking_violation(file_path: str, denied_directory: str, is_excluded: bool = False):
    """
    Log a directory blocking violation.

    Args:
        file_path: Path to the file that was blocked
        denied_directory: Directory containing .ai-read-deny marker
        is_excluded: Whether the path was in an excluded directory (but .ai-read-deny still blocked it)
    """
    if not HAS_VIOLATION_LOGGER:
        return

    try:
        violation_logger = ViolationLogger()

        # Prepare context with exclusion status
        context = {
            "project_path": os.getcwd(),
            "path_in_exclusion": is_excluded
        }

        if is_excluded:
            context["note"] = ".ai-read-deny ALWAYS takes precedence over directory exclusions"

        violation_logger.log_violation(
            violation_type="directory_blocking",
            blocked={
                "file_path": file_path,
                "denied_directory": denied_directory,
                "reason": ".ai-read-deny marker found",
                "exclusion_overridden": is_excluded
            },
            context=context,
            suggestion={
                "action": "remove_deny_marker",
                "file_path": os.path.join(denied_directory, ".ai-read-deny"),
                "warning": "This directory contains sensitive files"
            },
            severity="warning"
        )
    except Exception as e:
        logger.debug(f"Failed to log directory blocking violation: {e}")


def _log_secret_detection_violation(filename: str, context: Optional[Dict] = None, secret_details: Optional[Dict] = None):
    """
    Log a secret detection violation.

    Args:
        filename: Name of the file/prompt where secret was detected
        context: Optional context dict with ide_type, hook_event, etc.
        secret_details: Optional dict with Gitleaks finding details (rule_id, line_number, etc.)
    """
    if not HAS_VIOLATION_LOGGER:
        return

    try:
        ctx = context or {}
        details = secret_details or {}

        # Build blocked info with detailed location if available
        blocked_info = {
            "file_path": filename if filename != "user_prompt" else None,
            "source": "prompt" if filename == "user_prompt" else "file",
            "secret_type": details.get("rule_id", "Unknown"),
            "reason": "Gitleaks detected sensitive information"
        }

        # Add line number information if available
        if details.get("line_number"):
            blocked_info["line_number"] = details["line_number"]
            if details.get("end_line") and details["end_line"] != details["line_number"]:
                blocked_info["end_line"] = details["end_line"]

        # Add total findings count if available
        if details.get("total_findings"):
            blocked_info["total_findings"] = details["total_findings"]

        violation_logger = ViolationLogger()
        violation_logger.log_violation(
            violation_type="secret_detected",
            blocked=blocked_info,
            context={
                "ide_type": ctx.get("ide_type", "unknown"),
                "hook_event": ctx.get("hook_event", "unknown"),
                "project_path": os.getcwd()
            },
            suggestion={
                "action": "review_and_remove_secret",
                "warning": "Secrets should never be committed to code or shared with AI"
            },
            severity="critical"
        )
    except Exception as e:
        logger.debug(f"Failed to log secret detection violation: {e}")


def _log_prompt_injection_violation(filename: str, context: Optional[Dict] = None):
    """
    Log a prompt injection violation.

    Args:
        filename: Name of the file/prompt where injection was detected
        context: Optional context dict with ide_type, hook_event, etc.
    """
    if not HAS_VIOLATION_LOGGER:
        return

    try:
        ctx = context or {}
        violation_logger = ViolationLogger()
        violation_logger.log_violation(
            violation_type="prompt_injection",
            blocked={
                "file_path": filename if filename != "user_prompt" else None,
                "source": "prompt" if filename == "user_prompt" else "file",
                "pattern": "Heuristic pattern detected",
                "confidence": 0.95,
                "method": "heuristic",
                "reason": "Prompt injection pattern detected"
            },
            context={
                "ide_type": ctx.get("ide_type", "unknown"),
                "hook_event": ctx.get("hook_event", "unknown"),
                "project_path": os.getcwd()
            },
            suggestion={
                "action": "add_allowlist_pattern",
                "note": "If this is legitimate (e.g., documentation), add to allowlist in ai-guardian.json"
            },
            severity="high"
        )
    except Exception as e:
        logger.debug(f"Failed to log prompt injection violation: {e}")


def _handle_violations_command(args):
    """
    Handle the violations subcommand.

    Args:
        args: Parsed command-line arguments

    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    from ai_guardian.violation_logger import ViolationLogger

    violation_logger = ViolationLogger()

    # Handle --clear
    if args.clear:
        confirm = input("Are you sure you want to clear all violations? [y/N] ")
        if confirm.lower() == 'y':
            if violation_logger.clear_log():
                print("Violations log cleared successfully")
                return 0
            else:
                print("Error: Failed to clear violations log", file=sys.stderr)
                return 1
        else:
            print("Cancelled")
            return 0

    # Handle --export
    if args.export:
        export_path = Path(args.export)
        if violation_logger.export_violations(export_path, violation_type=args.type):
            print(f"Violations exported to {export_path}")
            return 0
        else:
            print(f"Error: Failed to export violations to {export_path}", file=sys.stderr)
            return 1

    # Display violations
    violations = violation_logger.get_recent_violations(
        limit=args.limit,
        violation_type=args.type,
        resolved=False  # Only show unresolved violations by default
    )

    if not violations:
        print("No recent violations found")
        return 0

    # Format and display violations
    print(f"\nRecent Violations (last {len(violations)}):\n")

    for v in violations:
        timestamp = v.get("timestamp", "Unknown")
        vtype = v.get("violation_type", "unknown").upper().replace("_", " ")
        severity = v.get("severity", "warning").upper()
        blocked = v.get("blocked", {})
        suggestion = v.get("suggestion", {})

        # Format severity with color indicators
        severity_indicator = {
            "WARNING": "⚠",
            "HIGH": "🔴",
            "CRITICAL": "🔒"
        }.get(severity, "•")

        print(f"[{timestamp}] {severity_indicator} {vtype} ({severity.lower()})")

        # Display blocked details based on violation type
        if v.get("violation_type") == "tool_permission":
            tool_name = blocked.get("tool_name", "Unknown")
            tool_value = blocked.get("tool_value", "")
            reason = blocked.get("reason", "")
            print(f"  Tool: {tool_name}/{tool_value}")
            print(f"  Reason: {reason}")

        elif v.get("violation_type") == "directory_blocking":
            file_path = blocked.get("file_path", "Unknown")
            denied_dir = blocked.get("denied_directory", "")
            print(f"  File: {file_path}")
            print(f"  Denied by: {denied_dir}/.ai-read-deny")

        elif v.get("violation_type") == "secret_detected":
            source = blocked.get("source", "unknown")
            file_path = blocked.get("file_path")
            if file_path:
                print(f"  File: {file_path}")
            else:
                print(f"  Source: {source}")
            secret_type = blocked.get("secret_type", "Unknown")
            print(f"  Secret type: {secret_type}")

        elif v.get("violation_type") == "prompt_injection":
            source = blocked.get("source", "unknown")
            pattern = blocked.get("pattern", "Unknown")
            print(f"  Source: {source}")
            print(f"  Pattern: {pattern}")

        # Display suggestion
        action = suggestion.get("action", "")
        if action:
            print(f"  → Suggestion: {action}")

        print()

    print(f"To allow blocked operations, run: ai-guardian tui (when available)")
    print(f"Or manually edit: ~/.config/ai-guardian/ai-guardian.json\n")

    return 0


def _count_gitleaks_patterns(config_path):
    """
    Count the number of rules in a Gitleaks TOML configuration file.

    Args:
        config_path: Path to the Gitleaks config file

    Returns:
        int: Number of [[rules]] sections found, or 0 if unable to count
    """
    try:
        if not config_path or not Path(config_path).exists():
            return 0

        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Count [[rules]] sections (each represents one detection rule)
        rule_count = content.count('[[rules]]')
        return rule_count

    except Exception as e:
        logging.debug(f"Error counting patterns in {config_path}: {e}")
        return 0


def _is_gitleaks_config_content(content):
    """
    Detect if content looks like a gitleaks configuration file.

    Args:
        content: Text content to check

    Returns:
        bool: True if content appears to be a gitleaks config
    """
    # Check for common gitleaks config patterns
    indicators = [
        '[[rules]]',
        '[allowlist]',
        'title = "Gitleaks',
        'regex = \'\'\'',
        'secretGroup =',
        'entropy =',
    ]

    # If content has multiple indicators, it's likely a config file
    matches = sum(1 for indicator in indicators if indicator in content)
    return matches >= 3


def check_secrets_with_gitleaks(content, filename="temp_file", context: Optional[Dict] = None):
    """
    Check content for secrets using Gitleaks binary.

    Scans content for secrets using the open-source Gitleaks tool.
    Uses in-memory temp files on Linux for better performance.

    Supports optional pattern server integration for enhanced detection patterns.

    Args:
        content: The text content to scan for secrets
        filename: Optional filename for context in error messages
        context: Optional context dict for violation logging (ide_type, hook_event, etc.)

    Returns:
        tuple: (has_secrets: bool, error_message: str or None)
            - has_secrets: True if secrets detected, False otherwise
            - error_message: Detailed error if secrets found, None otherwise
    """
    try:
        # Skip scanning if content appears to be a gitleaks config file
        # This prevents false positives when viewing pattern files
        if _is_gitleaks_config_content(content):
            logging.debug("Skipping scan - content appears to be a gitleaks config file")
            return False, None
        # Use in-memory filesystem on Linux for better performance
        tmp_base_dir = "/dev/shm" if os.path.exists("/dev/shm") else None

        # Create temporary file with content
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            suffix=f"_{filename}",
            prefix="aiguardian_",
            dir=tmp_base_dir,
            delete=False
        ) as tmp_file:
            tmp_file.write(content)
            tmp_file.flush()
            tmp_file_path = tmp_file.name

        # Create report file for JSON output
        report_file = None
        try:
            # Determine which Gitleaks configuration to use
            # Priority order:
            # 1. Pattern Server (if enabled and reachable) - Enterprise policy
            # 2. Project .gitleaks.toml (if exists) - Project customization
            # 3. Gitleaks defaults (always available) - Fallback
            gitleaks_config_path = None
            config_source = "gitleaks defaults"  # Track which config is being used

            # Priority 1: Pattern server (if enabled and available)
            if HAS_PATTERN_SERVER:
                pattern_config = _load_pattern_server_config()
                if pattern_config:
                    try:
                        pattern_client = PatternServerClient(pattern_config)
                        server_patterns = pattern_client.get_patterns_path()
                        if server_patterns:
                            gitleaks_config_path = server_patterns
                            config_source = "pattern server"
                            logging.info(f"Using pattern server config: {server_patterns}")
                        elif pattern_client.warn_on_failure:
                            # Pattern server was configured but failed to provide patterns
                            # Warnings can be disabled by setting "warn_on_failure": false in config
                            logging.warning(
                                f"Pattern server configured at {pattern_config.get('url')} but patterns unavailable. "
                                f"Falling back to project config or gitleaks defaults. "
                                f"Common causes: missing/invalid auth token, network error, server down. "
                                f"Check token at {pattern_client.token_file} or see ~/.config/ai-guardian/ai-guardian.log for details."
                            )
                    except Exception as e:
                        logging.warning(f"Pattern server error, falling back to project/default config: {e}")

            # Priority 2: Project-specific .gitleaks.toml (if pattern server not used)
            if not gitleaks_config_path:
                project_config = Path(".gitleaks.toml")
                if project_config.exists():
                    gitleaks_config_path = project_config
                    config_source = "project config"
                    logging.info(f"Using project config: {project_config}")
                else:
                    # Priority 3: Use gitleaks default config (no --config flag)
                    logging.info("Using gitleaks default config (built-in patterns)")

            # Validate pattern completeness if using pattern server
            if config_source == "pattern server" and gitleaks_config_path:
                pattern_count = _count_gitleaks_patterns(gitleaks_config_path)
                if pattern_count > 0 and pattern_count < 50:
                    logging.warning(
                        f"Pattern server returned only {pattern_count} rules. "
                        f"Standard Gitleaks has 100+ rules. "
                        f"Your pattern server may be missing common secret types (AWS keys, RSA keys, etc.). "
                        f"Ensure your pattern server includes both organization-specific AND default Gitleaks patterns."
                    )

            # Create temporary report file for JSON output
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.json',
                prefix='gitleaks_report_',
                dir=tmp_base_dir,
                delete=False
            ) as rf:
                report_file = rf.name

            # Build gitleaks command
            cmd = [
                'gitleaks',
                'detect',
                '--no-git',        # Don't use git history
                '--verbose',       # Detailed output
                '--redact',        # Hide secret values in output
                '--report-format', 'json',  # JSON output for parsing
                '--report-path', report_file,  # Write JSON to file
                '--exit-code', '42',  # Custom exit code for found secrets
                '--source', tmp_file_path,
            ]

            # Add custom config if we have one
            if gitleaks_config_path:
                cmd.extend(['--config', str(Path(gitleaks_config_path).absolute())])

            # Run Gitleaks scanner
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # Prevent hanging
            )

            # Check exit code
            if result.returncode == 42:  # Secrets found
                # Parse JSON report to extract details
                secret_details = None
                try:
                    if os.path.exists(report_file):
                        with open(report_file, 'r', encoding='utf-8') as f:
                            findings = json.load(f)
                        if findings and len(findings) > 0:
                            # Get first finding for details
                            first_finding = findings[0]
                            secret_details = {
                                "rule_id": first_finding.get("RuleID", "Unknown"),
                                "file": first_finding.get("File", filename),
                                "line_number": first_finding.get("StartLine", 0),
                                "end_line": first_finding.get("EndLine", 0),
                                "commit": first_finding.get("Commit", "N/A"),
                                "match": first_finding.get("Match", "REDACTED")[:50] + "..." if first_finding.get("Match") else "REDACTED",
                                "total_findings": len(findings)
                            }
                except Exception as e:
                    logging.debug(f"Failed to parse Gitleaks JSON report: {e}")

                # Build error message with details if available
                error_msg = (
                    f"\n{'='*70}\n"
                    f"🔒 SECRET DETECTED\n"
                    f"{'='*70}\n\n"
                    "Gitleaks has detected sensitive information in your prompt/file.\n"
                )

                # Include specific details if we have them
                if secret_details:
                    error_msg += "\n"
                    error_msg += f"Secret Type: {secret_details['rule_id']}\n"
                    if secret_details.get('line_number'):
                        error_msg += f"Location: {secret_details['file']}, line {secret_details['line_number']}\n"
                    else:
                        error_msg += f"File: {secret_details['file']}\n"
                    if secret_details.get('total_findings'):
                        error_msg += f"Total findings: {secret_details['total_findings']}\n"

                error_msg += (
                    "\nThis operation has been blocked for security.\n"
                    "Please remove the sensitive information and try again.\n\n"
                )

                # Only show generic list if we don't have specific details
                if not secret_details:
                    error_msg += (
                        "Common secrets detected:\n"
                        "  • API keys and tokens\n"
                        "  • Private keys (SSH, RSA, PGP)\n"
                        "  • Database credentials\n"
                        "  • Cloud provider keys (AWS, GCP, Azure)\n\n"
                    )

                error_msg += (
                    "If this is a false positive, add '# gitleaks:allow' to the line\n"
                    "or see: https://github.com/gitleaks/gitleaks#configuration\n"
                    f"{'='*70}\n"
                )

                # Log secret detection violation with details
                _log_secret_detection_violation(filename, context, secret_details)

                return True, error_msg

            elif result.returncode in [0, 1]:
                # No secrets found (0 or 1 are both "clean" states)
                return False, None

            else:
                # Unexpected error - analyze and decide whether to block or warn
                logging.warning(f"Gitleaks returned unexpected exit code: {result.returncode}")

                # Extract error details
                stderr_preview = ""
                if result.stderr:
                    logging.warning(f"Gitleaks stderr: {result.stderr}")
                    stderr_lines = [line.strip() for line in result.stderr.split('\n') if line.strip()]
                    if stderr_lines:
                        stderr_preview = stderr_lines[0][:200]

                # Check if this is an authentication/authorization error (user can fix)
                is_auth_error = False
                if result.stderr:
                    stderr_lower = result.stderr.lower()
                    is_auth_error = any(keyword in stderr_lower for keyword in
                                       ['401', '403', 'unauthorized', 'forbidden', 'authentication failed',
                                        'bad credentials', 'invalid token', 'access denied'])

                # Check if this is a network error (user cannot fix)
                is_network_error = False
                if result.stderr:
                    stderr_lower = result.stderr.lower()
                    is_network_error = any(keyword in stderr_lower for keyword in
                                          ['connection', 'timeout', 'network', 'unreachable',
                                           'dial tcp', 'no route to host'])

                if is_auth_error:
                    # Authentication error - BLOCK (user can fix by updating credentials)
                    error_msg = (
                        f"\n{'='*70}\n"
                        f"🔒 AUTHENTICATION ERROR\n"
                        f"{'='*70}\n\n"
                        f"Gitleaks authentication failed (exit code {result.returncode}).\n"
                    )
                    if stderr_preview:
                        error_msg += f"\nError: {stderr_preview}\n"
                    error_msg += (
                        "\nThis operation has been blocked for security.\n\n"
                        "If using pattern-servers:\n"
                        "  1. Check your authentication token is valid\n"
                        "  2. Update token: export AI_GUARDIAN_PATTERN_TOKEN='your-token'\n"
                        "  3. Or disable pattern-servers in ~/.config/ai-guardian/ai-guardian.json\n\n"
                        "If NOT using pattern-servers:\n"
                        "  1. Check ~/.gitleaks.toml configuration\n"
                        "  2. Try: gitleaks version (to verify installation)\n"
                        f"{'='*70}\n"
                    )
                    return True, error_msg  # Block operation

                else:
                    # Network error or other issue - WARN but allow (fail-open)
                    warning_msg = (
                        f"\n{'='*70}\n"
                        f"⚠️  SECRET SCANNING WARNING\n"
                        f"{'='*70}\n"
                        f"Gitleaks failed with exit code {result.returncode}.\n"
                    )
                    if stderr_preview:
                        warning_msg += f"Error: {stderr_preview}\n"

                    if is_network_error:
                        warning_msg += (
                            "\n💡 Network or server issue detected.\n"
                            "   If using pattern-servers, the server may be temporarily unavailable.\n"
                            "   You can disable pattern-servers in ~/.config/ai-guardian/ai-guardian.json\n"
                        )

                    warning_msg += (
                        "\nOperation will continue, but secret scanning may not be functioning.\n\n"
                        "Troubleshooting:\n"
                        "  • Check Gitleaks: gitleaks version\n"
                        "  • Review config: ~/.gitleaks.toml (if exists)\n"
                        "  • Reinstall: brew reinstall gitleaks (macOS)\n"
                        f"{'='*70}\n"
                    )

                    # Print to stderr for visibility
                    print(warning_msg, file=sys.stderr)

                    # Fail open - allow operation to continue
                    return False, None

        finally:
            # Secure cleanup: overwrite file before deletion
            if os.path.exists(tmp_file_path):
                try:
                    # Make file writable
                    os.chmod(tmp_file_path, 0o600)

                    # Overwrite with zeros to prevent recovery
                    file_size = os.path.getsize(tmp_file_path)
                    with open(tmp_file_path, 'wb') as f:
                        f.write(b'\x00' * file_size)
                        f.flush()
                        os.fsync(f.fileno())

                    # Delete the file
                    os.unlink(tmp_file_path)

                except Exception as cleanup_error:
                    logging.warning(f"Failed to securely cleanup temp file: {cleanup_error}")
                    # Still try basic deletion
                    try:
                        if os.path.exists(tmp_file_path):
                            os.unlink(tmp_file_path)
                    except Exception:
                        pass  # Silent fail on final cleanup

            # Clean up report file
            if report_file and os.path.exists(report_file):
                try:
                    os.unlink(report_file)
                except Exception:
                    pass  # Silent fail on cleanup

    except FileNotFoundError:
        # Gitleaks binary not found - warn but allow (user may not be able to install immediately)
        logging.warning("Gitleaks binary not found - skipping secret scanning")
        logging.warning("Install Gitleaks: https://github.com/gitleaks/gitleaks#installing")

        # Print visible warning to stderr
        warning_msg = (
            f"\n{'='*70}\n"
            f"⚠️  SECRET SCANNING DISABLED\n"
            f"{'='*70}\n\n"
            "Gitleaks binary not found - secret scanning is currently disabled.\n\n"
            "AI Guardian requires Gitleaks to scan for sensitive information like:\n"
            "  • API keys and tokens\n"
            "  • Private keys (SSH, RSA, PGP)\n"
            "  • Database credentials\n"
            "  • Cloud provider keys (AWS, GCP, Azure)\n\n"
            "Install Gitleaks:\n"
            "  macOS:   brew install gitleaks\n"
            "  Linux:   See https://github.com/gitleaks/gitleaks#installing\n"
            "  Windows: See https://github.com/gitleaks/gitleaks#installing\n\n"
            "Operation will continue, but secrets will NOT be detected.\n"
            "After installation, restart your IDE.\n"
            f"{'='*70}\n"
        )
        print(warning_msg, file=sys.stderr)

        # Fail open - allow operation to continue
        return False, None

    except subprocess.TimeoutExpired:
        logging.error("Gitleaks scan timed out after 30 seconds")
        return False, None

    except Exception as e:
        logging.error(f"Unexpected error during secret scanning: {e}")
        import traceback
        logging.error(traceback.format_exc())
        # Fail open - don't block on errors
        return False, None


def process_hook_input():
    """
    Process hook input from stdin and check for secrets.

    Supports both prompt hooks (UserPromptSubmit, beforeSubmitPrompt) and
    tool use hooks (PreToolUse, preToolUse).

    Returns:
        dict: Response with 'output' (str or None) and 'exit_code' (int)
              - For Claude Code: output=None, exit_code=0 (allow) or 2 (block)
              - For Cursor: output=JSON string, exit_code=0
    """
    try:
        # Read JSON input from stdin
        stdin_content = sys.stdin.read()
        hook_data = json.loads(stdin_content)

        # Detect which IDE is calling
        ide_type = detect_ide_type(hook_data)

        # Disable logging for Cursor (it's sensitive to stderr output)
        if ide_type == IDEType.CURSOR:
            logging.disable(logging.CRITICAL)
        else:
            logging.info(f"Detected IDE type: {ide_type.value}")

        # Detect which hook event triggered this call
        hook_event = detect_hook_event(hook_data)
        if ide_type != IDEType.CURSOR:
            logging.info(f"Detected hook event: {hook_event}")

        # Handle PostToolUse event - scan tool output before sending to AI
        if hook_event == "posttooluse":
            logging.info("Processing PostToolUse hook...")

            # Extract tool output
            tool_output, tool_name = extract_tool_result(hook_data)

            if tool_output is None:
                # No output to scan - allow
                return format_response(ide_type, has_secrets=False, hook_event=hook_event)

            logging.info(f"Scanning {tool_name} output for secrets...")

            # Check for secrets in the output
            has_secrets, error_message = check_secrets_with_gitleaks(
                tool_output, f"{tool_name}_output",
                context={"ide_type": ide_type.value, "hook_event": "posttooluse"}
            )

            if has_secrets:
                # Block output from reaching AI
                logging.warning(f"Secrets detected in {tool_name} output")
                return format_response(ide_type, has_secrets=True,
                                     error_message=error_message,
                                     hook_event=hook_event)

            logging.info(f"✓ No secrets detected in {tool_name} output")
            return format_response(ide_type, has_secrets=False, hook_event=hook_event)

        # Check tool permissions for PreToolUse events (MCP servers and Skills)
        if hook_event in ["pretooluse", "beforereadfile"] and HAS_TOOL_POLICY:
            try:
                permissions_config = _load_permissions_config()

                # Check if permissions enforcement is enabled (supports time-based disabling)
                if is_feature_enabled(
                    permissions_config.get("enabled") if permissions_config else None,
                    datetime.now(timezone.utc),
                    default=True
                ):
                    policy_checker = ToolPolicyChecker()
                    is_allowed, error_message, tool_name = policy_checker.check_tool_allowed(hook_data)

                    if not is_allowed:
                        logging.warning(f"Tool '{tool_name}' blocked by policy")
                        return format_response(ide_type, has_secrets=True, error_message=error_message, hook_event=hook_event)

                    if tool_name and ide_type != IDEType.CURSOR:
                        logging.info(f"✓ Tool '{tool_name}' allowed by policy")
                elif permissions_config and ide_type != IDEType.CURSOR:
                    # Permissions enforcement is temporarily disabled
                    logging.info("⚠️  Tool permissions enforcement temporarily disabled")
            except Exception as e:
                # Fail-open: if policy check fails, allow the operation
                logging.warning(f"Tool policy check error (fail-open): {e}")

        content_to_scan = None
        filename = "unknown"

        if hook_event in ["pretooluse", "beforereadfile"]:
            # PreToolUse or beforeReadFile hook - scan file content
            logging.info(f"Processing {hook_event} hook...")
            content_to_scan, filename, file_path, is_denied, deny_reason = extract_file_content_from_tool(hook_data)

            # Check if directory access is denied
            if is_denied:
                logging.warning(f"Directory access denied for file '{file_path}'")
                return format_response(ide_type, has_secrets=True, error_message=deny_reason, hook_event=hook_event)

            # Skip scanning ai-guardian's own test files (contain example secrets)
            # IMPORTANT: Only skips ai-guardian tests, not user project tests
            if file_path and _is_ai_guardian_test_file(file_path):
                logging.debug(f"Skipping scan for ai-guardian test file: {file_path}")
                return format_response(ide_type, has_secrets=False, hook_event=hook_event)

            if content_to_scan is None:
                # Could not extract file content - allow operation (fail-open)
                logging.warning("Could not extract file content, allowing operation")
                return format_response(ide_type, has_secrets=False, hook_event=hook_event)

            logging.info(f"Scanning file '{filename}' for secrets...")

        else:
            # Prompt hook - scan the user's prompt
            logging.info("Processing prompt submission hook...")
            content_to_scan = hook_data.get("prompt", hook_data.get("userMessage", hook_data.get("message", "")))
            filename = "user_prompt"

            if not content_to_scan:
                # No content to check - allow operation
                return format_response(ide_type, has_secrets=False, hook_event=hook_event)

            logging.info("Scanning user prompt for secrets...")

        # Check for prompt injection BEFORE scanning for secrets
        if HAS_PROMPT_INJECTION:
            try:
                injection_config = _load_prompt_injection_config()

                # Check if prompt injection detection is enabled (supports time-based disabling)
                if injection_config and is_feature_enabled(
                    injection_config.get("enabled"),
                    datetime.now(timezone.utc),
                    default=True
                ):
                    is_injection, injection_error = check_prompt_injection(
                        content_to_scan, injection_config
                    )

                    if is_injection:
                        # Prompt injection detected - block operation
                        if ide_type != IDEType.CURSOR:
                            logging.warning("Prompt injection detected, blocking operation")

                        # Log prompt injection violation
                        _log_prompt_injection_violation(
                            filename,
                            context={"ide_type": ide_type.value, "hook_event": hook_event}
                        )

                        return format_response(ide_type, has_secrets=True, error_message=injection_error, hook_event=hook_event)

                    if ide_type != IDEType.CURSOR:
                        logging.info("✓ No prompt injection detected")
                elif injection_config and ide_type != IDEType.CURSOR:
                    # Prompt injection detection is temporarily disabled
                    logging.info("⚠️  Prompt injection detection temporarily disabled")
            except Exception as e:
                # Fail-open: if prompt injection check fails, continue
                logging.warning(f"Prompt injection check error (fail-open): {e}")

        # Check for secrets in the content
        secret_config = _load_secret_scanning_config()

        # Check if secret scanning is enabled (supports time-based disabling)
        if is_feature_enabled(
            secret_config.get("enabled") if secret_config else None,
            datetime.now(timezone.utc),
            default=True
        ):
            has_secrets, error_message = check_secrets_with_gitleaks(
                content_to_scan, filename,
                context={"ide_type": ide_type.value, "hook_event": hook_event}
            )

            if has_secrets:
                # Secrets found - block operation
                return format_response(ide_type, has_secrets=True, error_message=error_message, hook_event=hook_event)

            # No secrets found, allow operation
            if hook_event == "pretooluse":
                logging.info(f"✓ No secrets detected in file '{filename}'")
            else:
                logging.info("✓ No secrets detected in prompt")
        elif secret_config and ide_type != IDEType.CURSOR:
            # Secret scanning is temporarily disabled
            logging.info("⚠️  Secret scanning temporarily disabled")

        return format_response(ide_type, has_secrets=False, hook_event=hook_event)

    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse hook input: {e}")
        # Fail-open: allow operation on errors
        # Default to Claude Code format for error responses
        return {"output": None, "exit_code": 0}
    except Exception as e:
        logging.error(f"Unexpected error in hook: {e}")
        import traceback
        logging.error(traceback.format_exc())
        # Fail-open: allow operation on errors
        return {"output": None, "exit_code": 0}


def main():
    """Main entry point for the hook."""
    # If arguments are provided, handle them
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            prog="ai-guardian",
            description="AI IDE security hook for blocking directories and scanning secrets",
        )
        parser.add_argument(
            "--version",
            "-v",
            action="version",
            version=f"ai-guardian {__version__}",
        )

        # Add subcommands
        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # Setup subcommand
        setup_parser = subparsers.add_parser(
            "setup",
            help="Setup IDE hooks with optional remote config"
        )
        setup_parser.add_argument(
            "--ide",
            choices=["claude", "cursor", "copilot"],
            help="Specify IDE type (auto-detected if not provided)"
        )
        setup_parser.add_argument(
            "--remote-config-url",
            metavar="URL",
            help="Remote configuration URL to add"
        )
        setup_parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be changed without applying"
        )
        setup_parser.add_argument(
            "--force",
            action="store_true",
            help="Overwrite existing hooks"
        )
        setup_parser.add_argument(
            "--yes",
            "-y",
            action="store_true",
            help="Skip confirmation prompts"
        )

        # Violations subcommand
        violations_parser = subparsers.add_parser(
            "violations",
            help="View and manage violation log"
        )
        violations_parser.add_argument(
            "--type",
            choices=["tool_permission", "directory_blocking", "secret_detected", "prompt_injection"],
            help="Filter by violation type"
        )
        violations_parser.add_argument(
            "--limit",
            type=int,
            default=10,
            help="Number of violations to show (default: 10)"
        )
        violations_parser.add_argument(
            "--clear",
            action="store_true",
            help="Clear all violations from log"
        )
        violations_parser.add_argument(
            "--export",
            metavar="FILE",
            help="Export violations to JSON file"
        )

        # TUI subcommand
        tui_parser = subparsers.add_parser(
            "tui",
            help="Launch interactive TUI for configuration management"
        )

        args = parser.parse_args()

        # Handle setup command
        if args.command == "setup":
            from ai_guardian.setup import setup_hooks
            success = setup_hooks(
                ide_type=args.ide,
                remote_config_url=args.remote_config_url,
                dry_run=args.dry_run,
                force=args.force,
                interactive=not args.yes
            )
            return 0 if success else 1

        # Handle violations command
        if args.command == "violations":
            if HAS_VIOLATION_LOGGER:
                return _handle_violations_command(args)
            else:
                print("Error: violation_logger module not available", file=sys.stderr)
                return 1

        # Handle tui command
        if args.command == "tui":
            try:
                from ai_guardian.tui import AIGuardianTUI
                app = AIGuardianTUI()
                app.run()
                return 0
            except ImportError as e:
                print(f"Error: TUI dependencies not available. Install with: pip install ai-guardian", file=sys.stderr)
                print(f"Details: {e}", file=sys.stderr)
                return 1
            except Exception as e:
                print(f"Error running TUI: {e}", file=sys.stderr)
                return 1

        # If no subcommand, just return (version was handled)
        return 0

    # No arguments - run as hook (read from stdin)
    response = process_hook_input()

    # Output JSON to stdout if needed (for Cursor)
    if response.get("output"):
        print(response["output"], flush=True)  # Force flush for Cursor
        sys.stdout.flush()  # Explicit flush for compatibility

    # Exit with appropriate code
    sys.exit(response["exit_code"])


if __name__ == "__main__":
    main()
