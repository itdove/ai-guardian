#!/usr/bin/env python3
"""
AI IDE Security Hook

AI Guardian provides multi-layered protection for AI IDE interactions:
- Directory blocking with .ai-read-deny markers
- Secret scanning using Gitleaks
- Multi-IDE support (Claude Code, Cursor, VS Code Claude)

Automatically detects IDE type and uses appropriate response format.
"""

__version__ = "1.4.0-dev"

import argparse
import fnmatch
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


def format_response(ide_type, has_secrets, error_message=None, hook_event="prompt", warning_message=None):
    """
    Format the response based on IDE type and hook event.

    Args:
        ide_type: IDEType enum value
        has_secrets: bool indicating if secrets were found (block vs allow)
        error_message: Optional error message for blocked responses
            - Only displayed when blocking execution (has_secrets=True)
            - Not displayed in log mode - all IDEs discard messages when allowing execution
        hook_event: "prompt", "pretooluse", or "posttooluse" to determine response format
        warning_message: Optional warning message for log mode (allows execution but shows warning)
            - Only displayed when NOT blocking (has_secrets=False)
            - Uses systemMessage field for Claude Code to display warning to user

    Returns:
        dict with 'output' (str to print) and 'exit_code' (int)

    IDE Message Display Behavior:
        All IDEs (Claude Code, Cursor, Aider, GitHub Copilot):
            - Block mode: error_message displayed to user
            - Log mode: warning_message displayed via systemMessage (Claude Code only)

        Tested and confirmed (April 2026):
            - Claude Code: systemMessage field displays warning without blocking
            - Cursor: continue:true = user_message not shown (no warning support)
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
        # Tested: Cursor does NOT display messages when allowing (continue:true, decision:allow, permission:allow)
        # Only include messages when blocking (April 2026 testing confirmed)
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
                # Allow - return empty JSON or include systemMessage for warnings
                response = {}
                if warning_message:
                    # Log mode: display warning but allow execution
                    response["systemMessage"] = warning_message

            return {
                "output": json.dumps(response),
                "exit_code": 0  # PostToolUse uses JSON response, not exit code
            }
        elif hook_event == "prompt":
            # UserPromptSubmit: Uses JSON response format (per official docs)
            # https://code.claude.com/docs/en/hooks
            if has_secrets and error_message:
                # Block with JSON response - prevents secret leakage
                response = {
                    "decision": "block",
                    "reason": error_message,
                    "hookSpecificOutput": {
                        "hookEventName": "UserPromptSubmit"
                    }
                }
            else:
                # Allow - return empty JSON or include systemMessage for warnings
                response = {}
                if warning_message:
                    # Log mode: display warning but allow execution
                    response["systemMessage"] = warning_message

            return {
                "output": json.dumps(response),
                "exit_code": 0  # UserPromptSubmit uses JSON response, not exit codes
            }
        else:
            # PreToolUse: Uses JSON response format with hookSpecificOutput
            # https://github.com/anthropics/claude-code/blob/main/plugins/plugin-dev/skills/hook-development/SKILL.md
            if has_secrets and error_message:
                # Block with proper PreToolUse format
                response = {
                    "hookSpecificOutput": {
                        "permissionDecision": "deny",
                        "hookEventName": "PreToolUse"
                    },
                    "systemMessage": error_message
                }
            elif warning_message:
                # Log mode: display warning but allow execution
                response = {
                    "hookSpecificOutput": {
                        "permissionDecision": "allow",
                        "hookEventName": "PreToolUse"
                    },
                    "systemMessage": warning_message
                }
            else:
                # Allow with no message
                response = {
                    "hookSpecificOutput": {
                        "permissionDecision": "allow",
                        "hookEventName": "PreToolUse"
                    }
                }

            return {
                "output": json.dumps(response),
                "exit_code": 0  # PreToolUse uses JSON response, not exit codes
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

    Directory exclusions can override .ai-read-deny blocking for specific paths.
    This allows creating allowlists (e.g., block ~/.claude/skills/* except approved ones).

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


def _check_directory_rules(file_path, config):
    """
    Check directory rules (allow/deny) in order.

    Rules are evaluated sequentially, with the last matching rule winning.
    This allows flexible configurations like:
    - Deny all skills, then allow specific ones
    - Allow all projects, then deny specific subdirectories

    Args:
        file_path: Absolute path to the file being accessed
        config: Configuration dict containing directory_rules

    Returns:
        tuple: (decision, action) where:
            - decision: "allow", "deny", or None (no matching rule)
            - action: "block", "log", or None
    """
    try:
        if not config:
            return None, None

        # Get directory_rules - supports both array (deprecated) and object format
        directory_rules_config = config.get("directory_rules", [])

        # Handle both formats
        if isinstance(directory_rules_config, dict):
            # New format: {"action": "block", "rules": [...]}
            global_action = directory_rules_config.get("action", "block")
            directory_rules = directory_rules_config.get("rules", [])
        else:
            # Old format: array of rules
            # Default action is "block" for backward compatibility
            global_action = "block"
            directory_rules = directory_rules_config

        # Backward compatibility: convert directory_exclusions to rules
        dir_exclusions = config.get("directory_exclusions", {})
        if dir_exclusions.get("enabled") and dir_exclusions.get("paths"):
            # Log deprecation warning once
            if not hasattr(_check_directory_rules, '_warned_deprecation'):
                logging.warning("directory_exclusions is deprecated - use directory_rules instead")
                _check_directory_rules._warned_deprecation = True

            # Prepend exclusions as allow rules (so they have lower priority than explicit rules)
            backward_compat_rule = {
                "mode": "allow",
                "paths": dir_exclusions["paths"]
            }
            directory_rules = [backward_compat_rule] + directory_rules

        if not directory_rules:
            return None, None

        # Convert file path to absolute path
        abs_file_path = os.path.abspath(os.path.expanduser(file_path))

        # Evaluate rules in order, last match wins
        final_decision = None

        for rule in directory_rules:
            if not isinstance(rule, dict):
                logging.warning(f"Invalid directory rule (not a dict): {rule}")
                continue

            mode = rule.get("mode")
            if mode not in ["allow", "deny"]:
                logging.warning(f"Invalid rule mode: {mode} (must be 'allow' or 'deny')")
                continue

            paths = rule.get("paths", [])
            if not isinstance(paths, list):
                logging.warning(f"Invalid paths in rule (not a list): {paths}")
                continue

            # Check if file matches any pattern in this rule
            for pattern in paths:
                if not isinstance(pattern, str):
                    continue

                try:
                    # Expand tilde and convert to absolute path
                    expanded_pattern = os.path.abspath(os.path.expanduser(pattern))

                    # Check for wildcards
                    if "**" in expanded_pattern:
                        # Recursive wildcard: match directory and all subdirectories
                        base_path = expanded_pattern.replace("/**", "").replace("**", "")
                        if abs_file_path.startswith(base_path):
                            final_decision = mode
                            logging.debug(f"Path {abs_file_path} matched rule: {mode} {pattern} (action={global_action})")
                            break
                    elif "*" in expanded_pattern:
                        # Single-level wildcard: use fnmatch
                        import fnmatch
                        file_parent = os.path.dirname(abs_file_path)
                        if fnmatch.fnmatch(file_parent, expanded_pattern) or file_parent.startswith(expanded_pattern.replace("/*", "")):
                            final_decision = mode
                            logging.debug(f"Path {abs_file_path} matched rule: {mode} {pattern} (action={global_action})")
                            break
                    else:
                        # Exact path match
                        if abs_file_path.startswith(expanded_pattern + os.sep) or abs_file_path == expanded_pattern:
                            final_decision = mode
                            logging.debug(f"Path {abs_file_path} matched rule: {mode} {pattern} (action={global_action})")
                            break

                except Exception as e:
                    logging.warning(f"Error processing rule pattern '{pattern}': {e}")
                    continue

        # Return decision and global action (applies to all rules)
        return final_decision, global_action if final_decision else None

    except Exception as e:
        logging.error(f"Error checking directory rules: {e}")
        return None


def check_directory_denied(file_path, config=None):
    """
    Check if a file should be blocked based on directory rules and .ai-read-deny markers.

    This function implements order-based directory access control:
    1. directory_rules are evaluated in order (last match wins)
    2. .ai-read-deny markers are checked
    3. Rules can override markers (allow rules override .ai-read-deny)

    PRECEDENCE (in order of evaluation):
    1. Check directory_rules for explicit allow/deny
    2. Check for .ai-read-deny marker files
    3. If marker found and rules say "allow" → ALLOW (rules override marker)
    4. If marker found and no "allow" rule → BLOCK (marker wins)
    5. If no marker and rules say "deny" → BLOCK
    6. Default → ALLOW

    Args:
        file_path: Path to the file being accessed
        config: Optional configuration dict containing directory_rules

    Returns:
        tuple: (is_denied: bool, denied_directory: str or None, warning_message: str or None)
               - is_denied: True if access should be blocked
               - denied_directory: The directory containing .ai-read-deny, if found
               - warning_message: Warning message for log mode (when action="log")
    """
    try:
        # Load config if not provided
        if config is None and HAS_TOOL_POLICY:
            try:
                policy_checker = ToolPolicyChecker()
                config = policy_checker.config
            except Exception as e:
                logging.debug(f"Could not load config for directory rules: {e}")
                config = {}

        # Convert to absolute path
        abs_path = os.path.abspath(file_path)

        # PRIORITY 1: Check directory_rules
        rule_decision, rule_action = _check_directory_rules(abs_path, config) if config else (None, None)

        # PRIORITY 2: Check for .ai-read-deny marker files
        current_dir = os.path.dirname(abs_path)
        deny_marker_found = False
        denied_directory = None

        while True:
            deny_marker = os.path.join(current_dir, ".ai-read-deny")

            if os.path.exists(deny_marker):
                deny_marker_found = True
                denied_directory = current_dir
                logging.info(f"Found .ai-read-deny marker in {current_dir}")
                break

            # Move to parent directory
            parent_dir = os.path.dirname(current_dir)

            # Stop if we've reached the root
            if parent_dir == current_dir:
                break

            current_dir = parent_dir

        # PRIORITY 3: Apply decision logic
        if deny_marker_found:
            # Marker found - check if rules override it
            if rule_decision == "allow":
                logging.info(f"Found .ai-read-deny at {denied_directory}, but directory rules allow access - allowing")
                return False, None, None  # ALLOW - rule overrides marker
            else:
                # No allow rule to override - block or log
                # Check if there's a deny rule with log action
                if rule_action == "log":
                    logging.warning(f"Directory access violation (log mode): {file_path} - access allowed")
                    _log_directory_blocking_violation(file_path, denied_directory, is_excluded=False)
                    warn_msg = f"⚠️  Directory access violation (log mode): File in protected directory '{denied_directory}' - access allowed"
                    return False, None, warn_msg  # ALLOW - logged for audit, with warning
                else:
                    # Block access
                    logging.error(f".ai-read-deny marker blocks access to {denied_directory}")
                    _log_directory_blocking_violation(file_path, denied_directory, is_excluded=False)
                    return True, denied_directory, None  # BLOCK

        # No .ai-read-deny marker - check rule decision
        if rule_decision == "deny":
            # Check action
            if rule_action == "log":
                logging.warning(f"Directory access violation (log mode): {file_path} - access allowed")
                _log_directory_blocking_violation(file_path, os.path.dirname(abs_path), is_excluded=False)
                warn_msg = f"⚠️  Directory access violation (log mode): Directory rules matched '{file_path}' - access allowed"
                return False, None, warn_msg  # ALLOW - logged for audit, with warning
            else:
                # Block access
                logging.error(f"Directory rules deny access to {abs_path}")
                _log_directory_blocking_violation(file_path, os.path.dirname(abs_path), is_excluded=False)
                return True, os.path.dirname(abs_path), None  # BLOCK

        # Default: allow access
        return False, None, None

    except Exception as e:
        logging.error(f"Error checking directory access: {e}")
        # Fail-open: allow access if check fails
        return False, None, None


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
        # Get tool name from multiple possible locations
        tool_name = hook_data.get("tool_name")
        logging.info(f"extract_tool_result: tool_name from hook_data.tool_name = {tool_name}")
        if not tool_name and "tool_use" in hook_data:
            # Try tool_use.name format (Claude Code format)
            if isinstance(hook_data["tool_use"], dict):
                tool_name = hook_data["tool_use"].get("name")
                logging.info(f"extract_tool_result: tool_name from tool_use.name = {tool_name}")
        if not tool_name:
            tool_name = "unknown"
            logging.info("extract_tool_result: tool_name defaulted to 'unknown'")

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

                # SECURITY FIX: Check stdout/stderr for Bash/command tools
                # This prevents the Bash bypass vulnerability where secrets in
                # stdout/stderr were not scanned (only output/content/result were checked)
                if not output:
                    stdout = tool_response.get("stdout")
                    stderr = tool_response.get("stderr")

                    # Combine stdout and stderr - both can contain sensitive data
                    if stdout and stderr:
                        output = f"{stdout}\n{stderr}"
                    elif stdout:
                        output = stdout
                    elif stderr:
                        output = stderr

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
        tuple: (content: str or None, filename: str, file_path: str or None, is_denied: bool, deny_reason: str or None, warning_message: str or None)
               - warning_message: Warning for log mode (when action="log")
    """
    try:
        # Cursor beforeReadFile format: includes content and file_path directly
        if "content" in hook_data and "file_path" in hook_data:
            content = hook_data["content"]
            file_path = hook_data["file_path"]

            # Check if directory is denied
            is_denied, denied_dir, dir_warning = check_directory_denied(file_path)
            if is_denied:
                error_msg = (
                    f"\n{'='*70}\n"
                    f"🚨 BLOCKED BY POLICY\n"
                    f"🚫 ACCESS DENIED - Directory Protected\n"
                    f"{'='*70}\n\n"
                    f"The file '{file_path}' is located in a directory that contains\n"
                    f"a .ai-read-deny marker file.\n\n"
                    f"Protected directory: {denied_dir}\n\n"
                    f"This directory and all its subdirectories are blocked from AI access.\n\n"
                    f"DO NOT attempt workarounds - the protection is intentional.\n\n"
                    f"To allow access:\n"
                    f"  1. Remove the .ai-read-deny file from {denied_dir}\n"
                    f"  2. Move this file to an accessible location\n"
                    f"  3. Add this path to directory_exclusions in ai-guardian.json\n"
                    f"\n{'='*70}\n"
                )
                return None, os.path.basename(file_path), file_path, True, error_msg, None

            return content, os.path.basename(file_path), file_path, False, None, dir_warning

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
            return None, "unknown_file", None, False, None, None

        # Expand ~ to home directory
        file_path = os.path.expanduser(file_path)

        # Check if directory is denied BEFORE reading the file
        is_denied, denied_dir, dir_warning = check_directory_denied(file_path)
        if is_denied:
            error_msg = (
                f"\n{'='*70}\n"
                f"🚨 BLOCKED BY POLICY\n"
                f"🚫 ACCESS DENIED - Directory Protected\n"
                f"{'='*70}\n\n"
                f"The file '{file_path}' is located in a directory that contains\n"
                f"a .ai-read-deny marker file.\n\n"
                f"Protected directory: {denied_dir}\n\n"
                f"This directory and all its subdirectories are blocked from AI access.\n\n"
                f"DO NOT attempt workarounds - the protection is intentional.\n\n"
                f"To allow access:\n"
                f"  1. Remove the .ai-read-deny file from {denied_dir}\n"
                f"  2. Move this file to an accessible location\n"
                f"  3. Add this path to directory_exclusions in ai-guardian.json\n"
                f"\n{'='*70}\n"
            )
            return None, os.path.basename(file_path), file_path, True, error_msg, None

        # Read the file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            return content, os.path.basename(file_path), file_path, False, None, dir_warning
        except FileNotFoundError:
            logging.warning(f"File not found: {file_path}")
            return None, os.path.basename(file_path), file_path, False, None, dir_warning
        except PermissionError:
            logging.warning(f"Permission denied reading file: {file_path}")
            return None, os.path.basename(file_path), file_path, False, None, dir_warning
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return None, os.path.basename(file_path), file_path, False, None, dir_warning

    except Exception as e:
        logging.error(f"Error extracting file from tool data: {e}")
        return None, "unknown_file", None, False, None, None


def _load_config_file():
    """
    Load ai-guardian.json configuration file with detailed error reporting.

    Returns:
        tuple: (config_dict or None, error_message or None)
            - config_dict: Parsed configuration if successful
            - error_message: User-friendly error message if failed, suitable for systemMessage
    """
    try:
        # Try user global config first
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        if not config_path.exists():
            # Try project local config
            config_path = Path.cwd() / ".ai-guardian.json"

        if not config_path.exists():
            # No config file found - not an error, just use defaults
            return None, None

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config, None

        except json.JSONDecodeError as e:
            error_msg = (
                f"⚠️  Configuration Error: Failed to parse {config_path}\n"
                f"JSON Error: {e.msg} (line {e.lineno}, column {e.colno})\n"
                f"Using default configuration. Please fix the config file."
            )
            logging.error(f"JSON parse error in {config_path}: {e}")
            return None, error_msg

        except Exception as e:
            error_msg = (
                f"⚠️  Configuration Error: Failed to read {config_path}\n"
                f"Error: {str(e)}\n"
                f"Using default configuration."
            )
            logging.error(f"Error reading config {config_path}: {e}")
            return None, error_msg

    except Exception as e:
        # Unexpected error in config path resolution
        error_msg = f"⚠️  Configuration Error: {str(e)}"
        logging.error(f"Unexpected error loading config: {e}")
        return None, error_msg


def _load_pattern_server_config():
    """
    Load pattern server configuration from ai-guardian.json.

    NEW in v1.7.0: Checks secret_scanning.pattern_server first (new location),
    then falls back to root-level pattern_server (deprecated, backward compatibility).

    Returns:
        dict: Pattern server configuration or None
            - None if pattern_server not configured (use defaults)
            - None if pattern_server explicitly set to null (disabled)
            - dict if configured (presence = enabled)
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

        # Priority 1: NEW location (v1.7.0+) - secret_scanning.pattern_server
        secret_scanning = config.get("secret_scanning", {})
        if "pattern_server" in secret_scanning:
            pattern_config = secret_scanning["pattern_server"]

            # Handle explicit null (disabled)
            if pattern_config is None:
                logging.debug("Pattern server explicitly disabled (secret_scanning.pattern_server = null)")
                return None

            # Handle dict config (enabled if has url)
            if isinstance(pattern_config, dict):
                # Warn if using deprecated 'enabled' field
                if "enabled" in pattern_config:
                    logging.warning(
                        "DEPRECATED: pattern_server.enabled field is no longer needed. "
                        "Use presence/absence of pattern_server section to enable/disable. "
                        "To disable: set pattern_server to null or remove the section. "
                        "This field will be removed in v2.0.0."
                    )
                    # Respect enabled=false for backward compatibility
                    if not pattern_config.get("enabled", True):
                        logging.debug("Pattern server disabled via deprecated 'enabled: false'")
                        return None

                # Enabled if configured (has URL)
                if pattern_config.get("url"):
                    logging.debug("Using pattern server from secret_scanning.pattern_server")
                    return pattern_config
                else:
                    logging.debug("Pattern server section present but no URL configured")
                    return None

        # Priority 2: OLD location (backward compatibility) - root pattern_server
        if "pattern_server" in config:
            pattern_config = config["pattern_server"]

            logging.warning(
                "DEPRECATED: Root-level 'pattern_server' configuration. "
                "Move to 'secret_scanning.pattern_server' instead. "
                "Example:\n"
                "  \"secret_scanning\": {\n"
                "    \"enabled\": true,\n"
                "    \"pattern_server\": {...}\n"
                "  }\n"
                "Root-level support will be removed in v2.0.0."
            )

            if isinstance(pattern_config, dict):
                # Warn if using deprecated 'enabled' field
                if "enabled" in pattern_config:
                    logging.warning(
                        "DEPRECATED: pattern_server.enabled field is no longer needed. "
                        "Use presence/absence of pattern_server section to enable/disable."
                    )
                    # Respect enabled=false for backward compatibility
                    if not pattern_config.get("enabled", True):
                        logging.debug("Pattern server disabled via deprecated 'enabled: false'")
                        return None

                # Enabled if configured
                if pattern_config.get("url"):
                    return pattern_config

        # Not configured
        return None

    except Exception as e:
        logging.debug(f"Error loading pattern server config: {e}")
        return None


def _load_prompt_injection_config():
    """
    Load prompt injection configuration from ai-guardian.json.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    config, error_msg = _load_config_file()
    if error_msg:
        return None, error_msg
    if config is None:
        return None, None
    return config.get("prompt_injection"), None


def _load_permissions_config():
    """
    Load permissions configuration from ai-guardian.json.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    config, error_msg = _load_config_file()
    if error_msg:
        return None, error_msg
    if config is None:
        return None, None
    return config.get("permissions_enabled"), None


def _load_secret_scanning_config():
    """
    Load secret scanning configuration from ai-guardian.json.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    config, error_msg = _load_config_file()
    if error_msg:
        return None, error_msg
    if config is None:
        return None, None
    return config.get("secret_scanning"), None


def _extract_block_reason(error_message: str) -> str:
    """
    Extract a concise reason from error message for logging.

    Args:
        error_message: The full error message from policy checker

    Returns:
        str: Concise reason suitable for log messages

    Examples:
        - "Critical file protected: ai-guardian config"
        - "Matched deny pattern: *.env"
        - "No permission rule"
    """
    import re

    if "CRITICAL FILE PROTECTED" in error_message:
        if "ai-guardian configuration" in error_message:
            return "Critical file protected: ai-guardian config"
        elif "Repository source file" in error_message:
            return "Critical file protected: source code"
        elif "Directory protection marker" in error_message:
            return "Critical file protected: .ai-read-deny marker"
        else:
            return "Critical file protected"

    elif "matched deny pattern:" in error_message:
        # Extract the pattern
        match = re.search(r'matched deny pattern: ([^\n]+)', error_message)
        if match:
            pattern = match.group(1).strip()
            return f"Matched deny pattern: {pattern}"
        return "Matched deny pattern"

    elif "no permission rule" in error_message:
        return "No permission rule configured"

    elif "not in allow list" in error_message:
        return "Not in allow list"

    else:
        return "Policy violation"


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
            context["note"] = "Directory exclusions can override .ai-read-deny markers (path was excluded but deny marker existed)"

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


def check_secrets_with_gitleaks(content, filename="temp_file", context: Optional[Dict] = None,
                                file_path: Optional[str] = None, tool_name: Optional[str] = None,
                                ignore_files: Optional[list] = None, ignore_tools: Optional[list] = None):
    """
    Check content for secrets using Gitleaks binary.

    Scans content for secrets using the open-source Gitleaks tool.
    Uses in-memory temp files on Linux for better performance.

    Supports optional pattern server integration for enhanced detection patterns.

    TODO: Multi-engine support (#91) - Currently hardcoded to Gitleaks only.
          Future: Support multiple engines via secret_scanning.engines config:
          - gitleaks (current default)
          - trufflehog
          - detect-secrets
          - secretlint
          See https://github.com/itdove/ai-guardian/issues/91 for implementation plan.

    Args:
        content: The text content to scan for secrets
        filename: Optional filename for context in error messages
        context: Optional context dict for violation logging (ide_type, hook_event, etc.)
        file_path: Optional file path being scanned (for ignore_files matching)
        tool_name: Optional tool name being used (for ignore_tools matching)
        ignore_files: Optional list of glob patterns for files to skip
        ignore_tools: Optional list of tool name patterns to skip

    Returns:
        tuple: (has_secrets: bool, error_message: str or None)
            - has_secrets: True if secrets detected, False otherwise
            - error_message: Detailed error if secrets found, None otherwise

    Note:
        Secret scanning ALWAYS blocks when secrets are detected (no "log" mode).
        This prevents secrets from reaching Claude's API or being exposed in sessions.
    """
    try:
        # Check if tool should be ignored
        if ignore_tools and tool_name:
            for pattern in ignore_tools:
                if fnmatch.fnmatch(tool_name, pattern):
                    logging.info(f"Skipping secret scanning for ignored tool: {tool_name}")
                    return False, None

        # Check if file should be ignored
        if ignore_files and file_path:
            file_path_obj = Path(file_path).expanduser()
            for pattern in ignore_files:
                # Use Path.match() which supports ** glob patterns
                # fnmatch doesn't support ** so we need pathlib
                expanded_pattern = str(Path(pattern).expanduser())
                if file_path_obj.match(expanded_pattern):
                    logging.info(f"Skipping secret scanning for ignored file: {file_path}")
                    return False, None

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
            # TODO: Multi-engine support (#91) - make scanner selection configurable
            #       Currently hardcoded to 'gitleaks', future: support engines config
            cmd = [
                'gitleaks',
                'detect',
                '--no-git',        # Don't use git history
                '--verbose',       # Detailed output
                '--redact',        # Defense-in-depth: redact Match/Secret fields in JSON
                                   # (we don't extract these fields, but safeguard against future changes)
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
                # NOTE: We only extract metadata (RuleID, File, Line), never Match/Secret fields
                #       The --redact flag is defense-in-depth in case code is modified later
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
                                # NOTE: "match" field removed - never displayed, redacted anyway
                                "total_findings": len(findings)
                            }
                except Exception as e:
                    logging.debug(f"Failed to parse Gitleaks JSON report: {e}")

                # Build error message with details if available
                error_msg = (
                    f"\n{'='*70}\n"
                    f"🚨 BLOCKED BY POLICY\n"
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
                    "DO NOT attempt to bypass this protection - it prevents credential leaks.\n\n"
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

                # Always block - secret scanning does not support "log" mode
                # Rationale: Allowing secrets through (even in audit mode) creates security risk:
                #   - UserPromptSubmit: secrets reach Claude's API
                #   - PostToolUse: secrets in tool outputs go to Claude's session
                logging.error(f"Secret detected: {secret_details.get('rule_id') if secret_details else 'unknown'}")
                return True, error_msg

            elif result.returncode in [0, 1]:
                # No secrets found (0 or 1 are both "clean" states)
                return False, None

            else:
                # Unexpected error - analyze and decide whether to block or warn
                logging.warning(f"Gitleaks returned unexpected exit code: {result.returncode}")

                # Extract error details (sanitized - don't log full stderr to avoid leaking secrets)
                stderr_preview = ""
                if result.stderr:
                    # Only log sanitized error info, not full stderr
                    logging.debug(f"Gitleaks stderr present (length: {len(result.stderr)} chars)")
                    stderr_lines = [line.strip() for line in result.stderr.split('\n') if line.strip()]
                    if stderr_lines:
                        # Only show first line (error summary), truncated
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
                        f"🚨 BLOCKED BY POLICY\n"
                        f"🔒 AUTHENTICATION ERROR\n"
                        f"{'='*70}\n\n"
                        f"Gitleaks authentication failed (exit code {result.returncode}).\n"
                    )
                    if stderr_preview:
                        error_msg += f"\nError: {stderr_preview}\n"
                    error_msg += (
                        "\nThis operation has been blocked for security.\n\n"
                        "DO NOT attempt to bypass this protection - fix the authentication issue.\n\n"
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

            # Securely clean up report file (contains Gitleaks findings)
            # Even though --redact is used, we securely overwrite as defense in depth
            if report_file and os.path.exists(report_file):
                try:
                    # Make file writable
                    os.chmod(report_file, 0o600)

                    # Overwrite with zeros to prevent recovery
                    file_size = os.path.getsize(report_file)
                    with open(report_file, 'wb') as f:
                        f.write(b'\x00' * file_size)
                        f.flush()
                        os.fsync(f.fileno())

                    # Delete the file
                    os.unlink(report_file)

                except Exception as cleanup_error:
                    logging.debug(f"Failed to securely cleanup report file: {cleanup_error}")
                    # Still try basic deletion
                    try:
                        if os.path.exists(report_file):
                            os.unlink(report_file)
                    except Exception:
                        pass  # Silent fail on final cleanup

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
            logging.info(f"PostToolUse: tool_name={tool_name}, has_output={tool_output is not None}")

            if tool_output is None:
                # No output to scan - allow
                return format_response(ide_type, has_secrets=False, hook_event=hook_event)

            # Create composite tool identifier for more granular ignore patterns
            # This allows ignore_tools to match both PreToolUse (input) and PostToolUse (output)
            # For Skill tool: "Skill:code-review"
            # For MCP tools: already have composite name like "mcp__notebooklm__chat"
            tool_identifier = tool_name

            # Get tool_input from either tool_use.input or tool_input field
            tool_input = {}
            if "tool_use" in hook_data and isinstance(hook_data["tool_use"], dict):
                tool_input = hook_data["tool_use"].get("input", {})
            elif "tool_input" in hook_data and isinstance(hook_data["tool_input"], dict):
                tool_input = hook_data["tool_input"]

            if tool_name == "Skill" and tool_input.get("skill"):
                tool_identifier = f"Skill:{tool_input['skill']}"
                logging.info(f"PostToolUse (with output): Created composite identifier {tool_identifier}")

            logging.info(f"PostToolUse tool_identifier: {tool_identifier}")

            logging.info(f"Scanning {tool_identifier} output for secrets...")

            # Load secret scanning config for ignore lists
            secret_config, config_error = _load_secret_scanning_config()

            # If config has errors, display warning but continue with defaults
            if config_error:
                logging.warning("Config error in PostToolUse, displaying warning")
                return format_response(ide_type, has_secrets=False, hook_event=hook_event, warning_message=config_error)

            ignore_files = secret_config.get("ignore_files", []) if secret_config else []
            ignore_tools = secret_config.get("ignore_tools", []) if secret_config else []

            # Check for secrets in the output (use composite identifier for ignore matching)
            has_secrets, error_message = check_secrets_with_gitleaks(
                tool_output, f"{tool_identifier}_output",
                context={"ide_type": ide_type.value, "hook_event": "posttooluse"},
                tool_name=tool_identifier,
                ignore_files=ignore_files,
                ignore_tools=ignore_tools
            )

            if has_secrets:
                # Block output from reaching AI
                logging.warning(f"Secrets detected in {tool_identifier} output")
                return format_response(ide_type, has_secrets=True,
                                     error_message=error_message,
                                     hook_event=hook_event)

            logging.info(f"✓ No secrets detected in {tool_identifier} output")

            return format_response(ide_type, has_secrets=False, hook_event=hook_event)

        # Accumulate warning messages from log mode checks (tool policy, prompt injection, etc.)
        warning_messages = []

        # Extract tool name for PreToolUse events (needed for permissions and prompt injection)
        tool_name = None
        tool_identifier = None  # Composite identifier like "Skill:code-review" or "mcp__server__tool"
        if hook_event in ["pretooluse", "beforereadfile"]:
            # Extract tool name and input from hook_data
            tool_input = {}
            if "tool_use" in hook_data and isinstance(hook_data["tool_use"], dict):
                tool_name = hook_data["tool_use"].get("name")
                tool_input = hook_data["tool_use"].get("input", {})
            elif "tool" in hook_data and isinstance(hook_data["tool"], dict):
                tool_name = hook_data["tool"].get("name")
                tool_input = hook_data.get("tool_input", {})
            elif "tool_name" in hook_data:
                tool_name = hook_data["tool_name"]
                tool_input = hook_data.get("tool_input", {})

            # Create composite tool identifier for more granular ignore patterns
            # For Skill tool: "Skill:code-review"
            # For MCP tools: already have composite name like "mcp__notebooklm__chat"
            # For other tools: just use tool_name
            if tool_name == "Skill" and tool_input.get("skill"):
                tool_identifier = f"Skill:{tool_input['skill']}"
            else:
                tool_identifier = tool_name

        # Check tool permissions for PreToolUse events (MCP servers and Skills)
        if hook_event in ["pretooluse", "beforereadfile"] and HAS_TOOL_POLICY:
            try:
                permissions_config, config_error = _load_permissions_config()
                if config_error:
                    warning_messages.append(config_error)

                # Check if permissions enforcement is enabled (supports time-based disabling)
                if is_feature_enabled(
                    permissions_config.get("enabled") if permissions_config else None,
                    datetime.now(timezone.utc),
                    default=True
                ):
                    policy_checker = ToolPolicyChecker()
                    is_allowed, error_message, checked_tool_name = policy_checker.check_tool_allowed(hook_data)

                    if not is_allowed:
                        # Extract reason summary for logging
                        reason_summary = _extract_block_reason(error_message) if error_message else "policy violation"
                        logging.warning(f"🚨 BLOCKED BY POLICY: Tool '{checked_tool_name}' - {reason_summary}")
                        return format_response(ide_type, has_secrets=True, error_message=error_message, hook_event=hook_event)
                    elif is_allowed and error_message:
                        # Log mode: allowed but violation logged - display warning to user
                        logging.warning(f"⚠️  Policy violation (log mode): Tool '{checked_tool_name}' - execution allowed")
                        # Accumulate warning message to display at the end
                        warning_messages.append(error_message)

                    if checked_tool_name and ide_type != IDEType.CURSOR:
                        logging.info(f"✓ Tool '{checked_tool_name}' allowed by policy")
                elif permissions_config and ide_type != IDEType.CURSOR:
                    # Permissions enforcement is temporarily disabled
                    logging.info("⚠️  Tool permissions enforcement temporarily disabled")
            except Exception as e:
                # Fail-open: if policy check fails, allow the operation
                logging.warning(f"Tool policy check error (fail-open): {e}")

        content_to_scan = None
        filename = "unknown"
        file_path = None

        if hook_event in ["pretooluse", "beforereadfile"]:
            # PreToolUse or beforeReadFile hook - scan file content
            logging.info(f"Processing {hook_event} hook...")
            content_to_scan, filename, file_path, is_denied, deny_reason, dir_warning = extract_file_content_from_tool(hook_data)

            # Check if directory access is denied
            if is_denied:
                logging.warning(f"Directory access denied for file '{file_path}'")
                return format_response(ide_type, has_secrets=True, error_message=deny_reason, hook_event=hook_event)
            elif dir_warning:
                # Log mode: directory violation detected but execution allowed
                # Accumulate warning message to display at the end
                warning_messages.append(dir_warning)

            # Skip scanning ai-guardian's own test files (contain example secrets)
            # IMPORTANT: Only skips ai-guardian tests, not user project tests
            if file_path and _is_ai_guardian_test_file(file_path):
                logging.debug(f"Skipping scan for ai-guardian test file: {file_path}")

                combined_warning = "\n\n".join(warning_messages) if warning_messages else None
                return format_response(ide_type, has_secrets=False, hook_event=hook_event, warning_message=combined_warning)

            if content_to_scan is None:
                # Could not extract file content - allow operation (fail-open)
                logging.warning("Could not extract file content, allowing operation")

                combined_warning = "\n\n".join(warning_messages) if warning_messages else None
                return format_response(ide_type, has_secrets=False, hook_event=hook_event, warning_message=combined_warning)

            # Log with full path for debugging false positives
            if file_path:
                logging.info(f"Scanning file '{filename}' ({file_path}) for secrets...")
            else:
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
                injection_config, config_error = _load_prompt_injection_config()
                if config_error:
                    warning_messages.append(config_error)

                # Check if prompt injection detection is enabled (supports time-based disabling)
                if injection_config and is_feature_enabled(
                    injection_config.get("enabled"),
                    datetime.now(timezone.utc),
                    default=True
                ):
                    should_block, injection_error, injection_detected = check_prompt_injection(
                        content_to_scan, injection_config, file_path=file_path, tool_name=tool_identifier
                    )

                    # Log violation if injection was detected (in both log and block modes)
                    if injection_detected:
                        _log_prompt_injection_violation(
                            filename,
                            context={"ide_type": ide_type.value, "hook_event": hook_event, "file_path": file_path}
                        )

                    if should_block:
                        # Prompt injection detected - block operation
                        if ide_type != IDEType.CURSOR:
                            if file_path:
                                logging.warning(f"Prompt injection detected in {file_path}, blocking operation")
                            else:
                                logging.warning("Prompt injection detected, blocking operation")

                        return format_response(ide_type, has_secrets=True, error_message=injection_error, hook_event=hook_event)
                    elif injection_detected and injection_error:
                        # Log mode: injection detected but execution allowed - display warning
                        # Accumulate warning message to display at the end
                        warning_messages.append(injection_error)

                    if ide_type != IDEType.CURSOR:
                        if not injection_detected:
                            logging.info("✓ No prompt injection detected")
                elif injection_config and ide_type != IDEType.CURSOR:
                    # Prompt injection detection is temporarily disabled
                    logging.info("⚠️  Prompt injection detection temporarily disabled")
            except Exception as e:
                # Fail-open: if prompt injection check fails, continue
                logging.warning(f"Prompt injection check error (fail-open): {e}")

        # Check for secrets in the content
        secret_config, config_error = _load_secret_scanning_config()
        if config_error:
            warning_messages.append(config_error)

        # Check if secret scanning is enabled (supports time-based disabling)
        if is_feature_enabled(
            secret_config.get("enabled") if secret_config else None,
            datetime.now(timezone.utc),
            default=True
        ):
            # Extract ignore lists from config
            ignore_files = secret_config.get("ignore_files", []) if secret_config else []
            ignore_tools = secret_config.get("ignore_tools", []) if secret_config else []

            has_secrets, error_message = check_secrets_with_gitleaks(
                content_to_scan, filename,
                context={"ide_type": ide_type.value, "hook_event": hook_event},
                file_path=file_path,
                tool_name=tool_identifier,
                ignore_files=ignore_files,
                ignore_tools=ignore_tools
            )

            if has_secrets:
                # Secrets found - block operation
                return format_response(ide_type, has_secrets=True, error_message=error_message, hook_event=hook_event)

            # No secrets found, allow operation
            if hook_event == "pretooluse":
                if file_path:
                    logging.info(f"✓ No secrets detected in file '{filename}' ({file_path})")
                else:
                    logging.info(f"✓ No secrets detected in file '{filename}'")
            else:
                logging.info("✓ No secrets detected in prompt")
        elif secret_config and ide_type != IDEType.CURSOR:
            # Secret scanning is temporarily disabled
            logging.info("⚠️  Secret scanning temporarily disabled")

        # Combine all warning messages if any exist
        combined_warning = "\n\n".join(warning_messages) if warning_messages else None

        return format_response(ide_type, has_secrets=False, hook_event=hook_event, warning_message=combined_warning)

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
            "--migrate-pattern-server",
            action="store_true",
            help="Migrate old root-level pattern_server config to new nested structure (v1.7.0+)"
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
                interactive=not args.yes,
                migrate_pattern_server=args.migrate_pattern_server
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
