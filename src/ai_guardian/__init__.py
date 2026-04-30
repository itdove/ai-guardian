#!/usr/bin/env python3
"""
AI IDE Security Hook

AI Guardian provides multi-layered protection for AI IDE interactions:
- Directory blocking with .ai-read-deny markers
- Secret scanning using Gitleaks
- Multi-IDE support (Claude Code, Cursor, VS Code Claude)

Automatically detects IDE type and uses appropriate response format.
"""

__version__ = "1.6.0-dev"

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
from ai_guardian.utils.path_matching import match_leading_doublestar_pattern

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

# Import config file scanner
try:
    from ai_guardian.config_scanner import check_config_file_threats
    HAS_CONFIG_SCANNER = True
except ImportError:
    HAS_CONFIG_SCANNER = False
    logging.debug("config_scanner module not available")

# Import violation logger
try:
    from ai_guardian.violation_logger import ViolationLogger
    HAS_VIOLATION_LOGGER = True
except ImportError:
    HAS_VIOLATION_LOGGER = False
    logging.debug("violation_logger module not available")

# Import scanner engine modules for flexible scanner support
try:
    from ai_guardian.scanners.engine_builder import select_engine, build_scanner_command
    from ai_guardian.scanners.output_parsers import get_parser
    HAS_SCANNER_ENGINE = True
except ImportError:
    HAS_SCANNER_ENGINE = False
    logging.debug("scanner engine modules not available - using legacy gitleaks only")

# Configure logging - will be disabled for Cursor hooks
# Custom log record factory to add version to all log records
_old_factory = logging.getLogRecordFactory()

def _record_factory(*args, **kwargs):
    """Custom log record factory that injects version into all log records."""
    record = _old_factory(*args, **kwargs)
    record.version = __version__
    return record

logging.setLogRecordFactory(_record_factory)

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
    '%(asctime)s - v%(version)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

# Suppress stderr banner when --json is requested (keep file logging)
_stderr_handler = logging.StreamHandler(sys.stderr)
if "--json" in sys.argv:
    _stderr_handler.setLevel(logging.WARNING)

# Configure root logger with both stderr and file handlers
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",  # Simple format for stderr
    handlers=[
        _stderr_handler,  # Keep stderr output for IDE compatibility
        _file_handler  # Add file output
    ]
)

# Global logger instance
logger = logging.getLogger(__name__)

# Log version at startup
logger.info(f"AI Guardian v{__version__} initialized")
logger.info(f"Python {sys.version.split()[0]}")
import platform
logger.info(f"Platform: {platform.platform()}")


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


def format_response(ide_type, has_secrets, error_message=None, hook_event="prompt", warning_message=None, modified_output=None):
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
        modified_output: Optional modified tool output (for PostToolUse redaction)
            - Only used for PostToolUse hook when has_secrets=False
            - Contains redacted version of tool output to replace original

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
            # preToolUse: Only return permissionDecision when denying
            # If no secrets: omit permissionDecision to allow Claude Code's normal permission system
            response = {}
            if has_secrets:
                response["permissionDecision"] = "deny"
                if error_message:
                    # Prepend warning messages if present (e.g., JSON config errors)
                    final_error = error_message
                    if warning_message:
                        final_error = f"{warning_message}\n\n{error_message}"
                    response["permissionDecisionReason"] = final_error

            return {
                "output": json.dumps(response),
                "exit_code": 0  # GitHub Copilot uses JSON response, not exit code
            }
        else:
            # userPromptSubmitted uses exit codes like Claude Code
            if has_secrets and error_message:
                # Prepend warning messages if present (e.g., JSON config errors)
                final_error = error_message
                if warning_message:
                    final_error = f"{warning_message}\n\n{error_message}"
                # Print error to stderr
                print(final_error, file=sys.stderr)

            return {
                "output": None,
                "exit_code": 2 if has_secrets else 0
            }
    elif ide_type == IDEType.CURSOR:
        # Cursor uses JSON response to determine block/allow, not exit code
        # Tested: Cursor does NOT display messages when allowing (continue:true, decision:allow, permission:allow)
        # Only include messages when blocking (April 2026 testing confirmed)
        # Prepend warning messages if present (e.g., JSON config errors)
        final_error = error_message
        if has_secrets and error_message and warning_message:
            final_error = f"{warning_message}\n\n{error_message}"

        if hook_event == "pretooluse":
            # preToolUse expects {"decision": "allow"|"deny", "reason": "..."}
            response = {
                "decision": "deny" if has_secrets else "allow",
            }
            if has_secrets and final_error:
                response["reason"] = final_error
        elif hook_event == "beforereadfile":
            # beforeReadFile expects {"permission": "allow"|"deny", "user_message": "..."}
            response = {
                "permission": "deny" if has_secrets else "allow",
            }
            if has_secrets and final_error:
                response["user_message"] = final_error
        else:
            # beforeSubmitPrompt expects {"continue": bool, "user_message": "..."}
            response = {
                "continue": not has_secrets,
            }
            if has_secrets and final_error:
                response["user_message"] = final_error

        return {
            "output": json.dumps(response),
            "exit_code": 0  # Cursor uses JSON response, not exit code
        }
    else:
        # Claude Code
        if hook_event == "posttooluse":
            # PostToolUse expects JSON response with decision/reason format
            if has_secrets:
                # Prepend warning messages if present (e.g., JSON config errors)
                final_error = error_message or "Secrets detected in tool output"
                if warning_message:
                    final_error = f"{warning_message}\n\n{final_error}"
                response = {
                    "decision": "block",
                    "reason": final_error,
                    "hookSpecificOutput": {
                        "hookEventName": "PostToolUse",
                        "additionalContext": "Tool output contained sensitive information and was blocked by ai-guardian"
                    }
                }
            else:
                # Allow - return empty JSON or include systemMessage for warnings and/or modified output
                response = {}
                if warning_message:
                    # Log mode: display warning but allow execution
                    response["systemMessage"] = warning_message
                if modified_output is not None:
                    # Secret redaction: replace tool output with redacted version
                    response["output"] = modified_output

            return {
                "output": json.dumps(response),
                "exit_code": 0  # PostToolUse uses JSON response, not exit code
            }
        elif hook_event == "prompt":
            # UserPromptSubmit: Uses JSON response format (per official docs)
            # https://code.claude.com/docs/en/hooks
            if has_secrets and error_message:
                # Block with JSON response - prevents secret leakage
                # Prepend warning messages if present (e.g., JSON config errors)
                final_error = error_message
                if warning_message:
                    final_error = f"{warning_message}\n\n{error_message}"
                response = {
                    "decision": "block",
                    "reason": final_error,
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
            # PreToolUse: Only return permissionDecision when denying
            # If no secrets: omit permissionDecision to allow Claude Code's normal permission system
            # https://github.com/anthropics/claude-code/blob/main/plugins/plugin-dev/skills/hook-development/SKILL.md
            if has_secrets and error_message:
                # Block with proper PreToolUse format
                # Prepend warning messages if present (e.g., JSON config errors)
                final_error = error_message
                if warning_message:
                    final_error = f"{warning_message}\n\n{error_message}"
                response = {
                    "hookSpecificOutput": {
                        "permissionDecision": "deny",
                        "hookEventName": "PreToolUse"
                    },
                    "systemMessage": final_error
                }
            elif warning_message:
                # Log mode: display warning but don't override permission decision
                response = {
                    "systemMessage": warning_message
                }
            else:
                # No secrets, no warnings: return empty response
                # Claude Code will use its normal permission system
                response = {}

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

        # Convert file path to absolute path and resolve symlinks
        abs_file_path = os.path.realpath(os.path.expanduser(file_path))

        # Check each exclusion path
        for exclusion_path in exclusion_paths:
            if not isinstance(exclusion_path, str):
                logging.warning(f"Invalid exclusion path (not a string): {exclusion_path}")
                continue

            try:
                # Expand tilde and convert to absolute path, resolving symlinks
                expanded_path = os.path.realpath(os.path.expanduser(exclusion_path))

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
        tuple: (decision, action, matched_pattern) where:
            - decision: "allow", "deny", or None (no matching rule)
            - action: "block", "log", or None
            - matched_pattern: The pattern that triggered the match, or None
    """
    try:
        if not config:
            return None, None, None

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
            # No rules, but global_action still applies to .ai-read-deny markers
            return None, global_action, None

        # Convert file path to absolute path and resolve symlinks
        abs_file_path = os.path.realpath(os.path.expanduser(file_path))

        # Evaluate rules in order, last match wins
        final_decision = None
        matched_pattern = None

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
                    # Handle leading ** patterns (e.g., **/.claude/skills/**)
                    # These should match anywhere in the filesystem
                    if pattern.startswith("**/"):
                        # Use custom matching function for leading ** patterns
                        # This provides consistent glob support with ignore_files
                        if match_leading_doublestar_pattern(abs_file_path, pattern):
                            final_decision = mode
                            matched_pattern = pattern
                            logging.debug(f"Path {abs_file_path} matched rule: {mode} {pattern} (action={global_action})")
                            break
                    else:
                        # For non-leading-** patterns, use the original implementation
                        # This handles absolute paths, tilde expansion, and wildcards correctly
                        expanded_pattern = os.path.realpath(os.path.expanduser(pattern))

                        # Check for wildcards
                        if "**" in expanded_pattern:
                            # Recursive wildcard: match directory and all subdirectories
                            base_path = expanded_pattern.replace("/**", "").replace("**", "")

                            # Check if base_path still contains wildcards (e.g., daf-*/**, ~/projects/*/src/**)
                            if "*" in base_path:
                                # Use fnmatch to match the directory structure
                                # For pattern like /home/user/.claude/skills/daf-*/**
                                # base_path is /home/user/.claude/skills/daf-*
                                # We need to check if abs_file_path is under a directory matching base_path

                                # Check all parent directories from abs_file_path upwards
                                current_path = abs_file_path
                                matched = False

                                while current_path and current_path != os.path.dirname(current_path):
                                    # Check if this directory matches the base pattern
                                    if fnmatch.fnmatch(current_path, base_path):
                                        # Found a matching directory - the file is under it
                                        matched = True
                                        break
                                    # Move to parent directory
                                    current_path = os.path.dirname(current_path)

                                if matched:
                                    final_decision = mode
                                    matched_pattern = pattern
                                    logging.debug(f"Path {abs_file_path} matched rule: {mode} {pattern} (action={global_action})")
                                    break
                            else:
                                # No wildcards in base_path, use simple startswith
                                if abs_file_path.startswith(base_path):
                                    final_decision = mode
                                    matched_pattern = pattern
                                    logging.debug(f"Path {abs_file_path} matched rule: {mode} {pattern} (action={global_action})")
                                    break
                        elif "*" in expanded_pattern:
                            # Single-level wildcard: use fnmatch
                            file_parent = os.path.dirname(abs_file_path)
                            if fnmatch.fnmatch(file_parent, expanded_pattern) or file_parent.startswith(expanded_pattern.replace("/*", "")):
                                final_decision = mode
                                matched_pattern = pattern
                                logging.debug(f"Path {abs_file_path} matched rule: {mode} {pattern} (action={global_action})")
                                break
                        else:
                            # Exact path match
                            if abs_file_path.startswith(expanded_pattern + os.sep) or abs_file_path == expanded_pattern:
                                final_decision = mode
                                matched_pattern = pattern
                                logging.debug(f"Path {abs_file_path} matched rule: {mode} {pattern} (action={global_action})")
                                break

                except Exception as e:
                    logging.warning(f"Error processing rule pattern '{pattern}': {e}")
                    continue

        # Return decision, global action, and matched pattern
        # Note: global_action is returned even when no rule matches because
        # it applies to ALL violations, including .ai-read-deny markers (issue #93)
        return final_decision, global_action, matched_pattern

    except Exception as e:
        logging.error(f"Error checking directory rules: {e}")
        return None, None, None


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
        tuple: (is_denied: bool, denied_directory: str or None, warning_message: str or None, matched_pattern: str or None)
               - is_denied: True if access should be blocked
               - denied_directory: The directory containing .ai-read-deny, if found
               - warning_message: Warning message for log mode (when action="log")
               - matched_pattern: The directory rule pattern that triggered the match, if any
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

        # Convert to absolute path and resolve symlinks
        abs_path = os.path.realpath(file_path)

        # PRIORITY 1: Check directory_rules
        rule_decision, rule_action, matched_pattern = _check_directory_rules(abs_path, config) if config else (None, None, None)

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
                return False, None, None, matched_pattern  # ALLOW - rule overrides marker
            else:
                # No allow rule to override - block, warn, or log-only
                # Check action
                if rule_action == "warn":
                    logging.warning(f"Policy violation (warn mode): {file_path} - .ai-read-deny marker in {denied_directory} but allowed for audit")
                    _log_directory_blocking_violation(file_path, denied_directory, is_excluded=False)
                    warn_msg = f"⚠️  Policy violation (warn mode): Directory '{denied_directory}' denied by marker but allowed for audit"
                    return False, None, warn_msg, matched_pattern  # ALLOW - logged for audit, with warning
                elif rule_action == "log-only":
                    logging.warning(f"Policy violation (log-only mode): {file_path} - .ai-read-deny marker in {denied_directory} but allowed for audit (silent)")
                    _log_directory_blocking_violation(file_path, denied_directory, is_excluded=False)
                    return False, None, None, matched_pattern  # ALLOW - logged for audit, NO warning
                else:
                    # Block access
                    logging.error(f".ai-read-deny marker blocks access to {denied_directory}")
                    _log_directory_blocking_violation(file_path, denied_directory, is_excluded=False)
                    return True, denied_directory, None, matched_pattern  # BLOCK

        # No .ai-read-deny marker - check rule decision
        if rule_decision == "deny":
            # Check action
            if rule_action == "warn":
                logging.warning(f"Policy violation (warn mode): {file_path} - denied by rules but allowed for audit")
                _log_directory_blocking_violation(file_path, os.path.dirname(abs_path), is_excluded=False)
                warn_msg = f"⚠️  Policy violation (warn mode): Directory rules deny '{file_path}' but allowed for audit"
                return False, None, warn_msg, matched_pattern  # ALLOW - logged for audit, with warning
            elif rule_action == "log-only":
                logging.warning(f"Policy violation (log-only mode): {file_path} - denied by rules but allowed for audit (silent)")
                _log_directory_blocking_violation(file_path, os.path.dirname(abs_path), is_excluded=False)
                return False, None, None, matched_pattern  # ALLOW - logged for audit, NO warning
            else:
                # Block access
                logging.error(f"Directory rules deny access to {abs_path}")
                _log_directory_blocking_violation(file_path, os.path.dirname(abs_path), is_excluded=False)
                return True, os.path.dirname(abs_path), None, matched_pattern  # BLOCK

        # Default: allow access
        return False, None, None, None

    except Exception as e:
        logging.error(f"Error checking directory access: {e}")
        import traceback
        logging.debug(traceback.format_exc())
        # Fail-closed: block access if check fails (security-critical path)
        return True, None, f"Directory access check error: {e}", None


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
            is_denied, denied_dir, dir_warning, matched_pattern = check_directory_denied(file_path)
            if is_denied:
                # Format error message with new structure
                error_msg = "🛡️ Directory Access Denied\n\n"

                if matched_pattern:
                    error_msg += "Protection: Directory Rule\n"
                else:
                    error_msg += "Protection: .ai-read-deny Marker\n"

                # Truncate very long paths
                display_path = file_path if len(file_path) <= 100 else "..." + file_path[-97:]
                error_msg += f"File: {display_path}\n"

                if denied_dir:
                    display_dir = denied_dir if len(denied_dir) <= 100 else "..." + denied_dir[-97:]
                    error_msg += f"Protected Directory: {display_dir}\n"

                if matched_pattern:
                    display_pattern = matched_pattern if len(matched_pattern) <= 100 else matched_pattern[:97] + "..."
                    error_msg += f"Pattern: {display_pattern}\n"

                # Why blocked section
                error_msg += "\nWhy blocked: "
                if matched_pattern:
                    error_msg += "This file is blocked by a directory access rule.\n"
                    error_msg += "Directory rules prevent AI access to specific paths.\n"
                else:
                    error_msg += "This directory contains a .ai-read-deny marker file.\n"
                    error_msg += "All subdirectories are blocked from AI access.\n"

                # Security warnings
                error_msg += "\nThis operation has been blocked for security.\n"
                error_msg += "DO NOT attempt to bypass this protection - it prevents unauthorized directory access.\n"

                # Recommendations
                error_msg += "\nRecommendation:\n"
                if matched_pattern:
                    error_msg += "- Update directory_rules in ai-guardian.json to allow this path\n"
                    error_msg += "- Move this file to an accessible location\n"
                    error_msg += "- Verify this file should be accessible to AI agents\n"
                else:
                    error_msg += f"- Remove the .ai-read-deny file from {denied_dir} (manually)\n"
                    error_msg += "- Move this file to an accessible location\n"
                    error_msg += "- Add an allow rule in directory_rules config to override marker\n"

                # Config path
                error_msg += "\nConfig: ~/.config/ai-guardian/ai-guardian.json\n"
                error_msg += "Section: directory_rules\n"

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

        # Claude Code format alternative: tool_use.input.file_path
        if not file_path and "tool_use" in hook_data:
            tool_use = hook_data["tool_use"]
            if isinstance(tool_use, dict) and "input" in tool_use:
                input_params = tool_use["input"]
                file_path = input_params.get("file_path") or input_params.get("path")

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
        is_denied, denied_dir, dir_warning, matched_pattern = check_directory_denied(file_path)
        if is_denied:
            # Format error message with new structure
            error_msg = "🛡️ Directory Access Denied\n\n"

            if matched_pattern:
                error_msg += "Protection: Directory Rule\n"
            else:
                error_msg += "Protection: .ai-read-deny Marker\n"

            # Truncate very long paths
            display_path = file_path if len(file_path) <= 100 else "..." + file_path[-97:]
            error_msg += f"File: {display_path}\n"

            if denied_dir:
                display_dir = denied_dir if len(denied_dir) <= 100 else "..." + denied_dir[-97:]
                error_msg += f"Protected Directory: {display_dir}\n"

            if matched_pattern:
                display_pattern = matched_pattern if len(matched_pattern) <= 100 else matched_pattern[:97] + "..."
                error_msg += f"Pattern: {display_pattern}\n"

            # Why blocked section
            error_msg += "\nWhy blocked: "
            if matched_pattern:
                error_msg += "This file is blocked by a directory access rule.\n"
                error_msg += "Directory rules prevent AI access to specific paths.\n"
            else:
                error_msg += "This directory contains a .ai-read-deny marker file.\n"
                error_msg += "All subdirectories are blocked from AI access.\n"

            # Security warnings
            error_msg += "\nThis operation has been blocked for security.\n"
            error_msg += "DO NOT attempt to bypass this protection - it prevents unauthorized directory access.\n"

            # Recommendations
            error_msg += "\nRecommendation:\n"
            if matched_pattern:
                error_msg += "- Update directory_rules in ai-guardian.json to allow this path\n"
                error_msg += "- Move this file to an accessible location\n"
                error_msg += "- Verify this file should be accessible to AI agents\n"
            else:
                error_msg += f"- Remove the .ai-read-deny file from {denied_dir} (manually)\n"
                error_msg += "- Move this file to an accessible location\n"
                error_msg += "- Add an allow rule in directory_rules config to override marker\n"

            # Config path
            error_msg += "\nConfig: ~/.config/ai-guardian/ai-guardian.json\n"
            error_msg += "Section: directory_rules\n"

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
            print(error_msg, file=sys.stderr)
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


def _load_config_scanner_config():
    """
    Load config file scanning configuration from ai-guardian.json.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    config, error_msg = _load_config_file()
    if error_msg:
        return None, error_msg
    if config is None:
        return None, None
    return config.get("config_file_scanning"), None


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

    # NEW unified structure in v1.4.0: permissions.enabled
    permissions = config.get("permissions")
    if isinstance(permissions, dict):
        # Return the enabled field from the permissions object
        return {"enabled": permissions.get("enabled", True)}, None

    # Fallback: default to enabled
    return {"enabled": True}, None


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


def _load_secret_redaction_config():
    """
    Load secret redaction configuration from ai-guardian.json.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    config, error_msg = _load_config_file()
    if error_msg:
        return None, error_msg
    if config is None:
        return None, None
    return config.get("secret_redaction"), None


def _load_pii_config():
    """
    Load PII scanning configuration from ai-guardian.json.

    Returns defaults (enabled=True) when the scan_pii section is absent,
    so PII protection is on by default.

    Returns:
        tuple: (config_dict, error_message or None)
    """
    _PII_DEFAULTS = {
        'enabled': True,
        'pii_types': ['ssn', 'credit_card', 'phone', 'email', 'us_passport', 'iban', 'intl_phone'],
        'action': 'redact',
        'ignore_files': []
    }
    config, error_msg = _load_config_file()
    if error_msg:
        return _PII_DEFAULTS, error_msg
    if config is None:
        return _PII_DEFAULTS, None
    return config.get("scan_pii", _PII_DEFAULTS), None


def _scan_for_pii(text, pii_config):
    """
    Scan text for PII using SecretRedactor with PII patterns.

    Args:
        text: Text to scan
        pii_config: PII config dict with enabled, pii_types, action

    Returns:
        tuple: (has_pii, redacted_text, redactions, warning_message)
    """
    try:
        from ai_guardian.secret_redactor import SecretRedactor
        # pii_only=True skips loading secret patterns, only loads PII patterns
        redactor = SecretRedactor(config={'enabled': True}, pii_config=pii_config, pii_only=True)
        result = redactor.redact(text)
        redactions = result.get('redactions', [])
        if redactions:
            pii_types = list(set(r['type'] for r in redactions))
            warning = (
                f"\n{'='*70}\n"
                f"🔒 PII DETECTED\n"
                f"{'='*70}\n"
                f"Found {len(redactions)} PII item(s):\n"
                + "\n".join([f"  - {r['type']}" for r in redactions[:10]])
                + ("\n  - ..." if len(redactions) > 10 else "")
                + f"\n\nAction: {pii_config.get('action', 'redact')}\n"
                f"{'='*70}\n"
            )
            return True, result['redacted_text'], redactions, warning
        return False, text, [], None
    except Exception as e:
        logging.error(f"PII scan error: {e}")
        return False, text, [], None


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

    # Phase 3 format - Immutable Protection
    if "🛡️ Immutable Protection" in error_message:
        if "Protection: Configuration File" in error_message:
            return "Critical file protected: ai-guardian config"
        elif "Protection: Package Source Code" in error_message:
            return "Critical file protected: source code"
        elif "Protection: Directory Protection Marker" in error_message:
            return "Critical file protected: .ai-read-deny marker"
        else:
            return "Critical file protected"

    # Phase 3 format - Tool Access Denied
    elif "🛡️ Tool Access Denied" in error_message:
        # Check for special patterns first
        if "Pattern: no permission rule" in error_message or "no permission rule" in error_message.lower():
            return "No permission rule configured"
        elif "Pattern: not in allow list" in error_message or "not in allow list" in error_message.lower():
            return "Not in allow list"

        # Try to extract pattern from "Pattern: <value>" line
        match = re.search(r'Pattern:\s*([^\n]+)', error_message)
        if match:
            pattern = match.group(1).strip()
            return f"Matched deny pattern: {pattern}"
        return "Matched deny pattern"

    # Old format fallbacks for backward compatibility
    elif "CRITICAL FILE PROTECTED" in error_message:
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

    # Get the absolute path and resolve symlinks
    abs_path = os.path.realpath(file_path)

    # Check if file is in ai-guardian's tests directory
    # More strict check: must be in ai-guardian project root followed by tests/
    # Prevents false positives in unrelated projects containing "ai-guardian" + "tests"
    path_parts = abs_path.split(os.sep)

    # Find ai-guardian or ai_guardian directory in path
    ai_guardian_index = -1
    for i, part in enumerate(path_parts):
        if part in ('ai-guardian', 'ai_guardian'):
            ai_guardian_index = i
            break

    if ai_guardian_index == -1:
        return False

    # Check if 'tests' appears IMMEDIATELY after ai-guardian directory
    # This ensures it's the ai-guardian project's tests/, not some other tests/
    if ai_guardian_index + 1 < len(path_parts) and path_parts[ai_guardian_index + 1] == 'tests':
        return True

    return False


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
            # Expand file path (handle ~)
            abs_file_path = str(Path(file_path).expanduser().absolute())

            for pattern in ignore_files:
                matched = False

                # Handle leading ** patterns (e.g., **/.claude/skills/**)
                if pattern.startswith("**/"):
                    matched = match_leading_doublestar_pattern(abs_file_path, pattern)
                else:
                    # For non-leading-** patterns, use Path.match()
                    file_path_obj = Path(abs_file_path)
                    expanded_pattern = str(Path(pattern).expanduser())
                    matched = file_path_obj.match(expanded_pattern)

                if matched:
                    logging.info(f"Skipping secret scanning for ignored file: {file_path}")
                    return False, None

        # Convert content to string if it's not already
        # Agent tool outputs can be lists, dicts, or other types
        if isinstance(content, list):
            content = '\n'.join(str(item) for item in content)
        elif not isinstance(content, str):
            content = str(content)

        # Skip scanning if file is a gitleaks config file (path-based check)
        # This prevents false positives when viewing pattern files
        # Use path-based detection instead of content-based to prevent bypass
        if file_path and file_path.endswith('.gitleaks.toml'):
            logging.debug(f"Skipping scan - file is a gitleaks config: {file_path}")
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
            # 1. Pattern Server (if enabled and available) - Enterprise policy
            # 2. Scanner Engines (first available from config) - Falls back automatically
            #    - Engines auto-detect .gitleaks.toml if they support it
            # 3. BLOCK if no scanner available
            gitleaks_config_path = None
            config_source = None
            pattern_server_attempted = False

            # Priority 1: Pattern server (if enabled and available)
            if HAS_PATTERN_SERVER:
                pattern_config = _load_pattern_server_config()
                if pattern_config:
                    pattern_server_attempted = True
                    try:
                        pattern_client = PatternServerClient(pattern_config)
                        server_patterns = pattern_client.get_patterns_path()
                        if server_patterns:
                            # SUCCESS: Use pattern server
                            gitleaks_config_path = server_patterns
                            config_source = "pattern server"
                            logging.info(f"Using pattern server config: {server_patterns}")
                        else:
                            # Pattern server failed - will try scanner engines below
                            logging.warning(
                                f"Pattern server unavailable ({pattern_config.get('url')}), "
                                f"falling back to scanner engines"
                            )
                    except Exception as e:
                        logging.warning(f"Pattern server error, trying scanner engines: {e}")

            # Priority 2: Scanner Engines (if pattern server not used)
            engine_config = None
            if not gitleaks_config_path and HAS_SCANNER_ENGINE:
                try:
                    scanner_config, _ = _load_secret_scanning_config()
                    engines_list = scanner_config.get("engines", ["gitleaks"]) if scanner_config else ["gitleaks"]

                    # Select first available engine (logs warnings for unavailable ones)
                    engine_config = select_engine(engines_list)

                    # Log context about why we're using scanner engines
                    if pattern_server_attempted:
                        logging.warning(
                            f"Using {engine_config.type} scanner (pattern server unavailable)"
                        )
                    else:
                        logging.info(f"Using {engine_config.type} scanner")

                    config_source = f"{engine_config.type} defaults"

                except RuntimeError as e:
                    # NO SCANNER AVAILABLE - BLOCK
                    error_msg = (
                        f"\n{'='*70}\n"
                        f"🚨 BLOCKED BY POLICY\n"
                        f"🔒 NO SCANNER AVAILABLE\n"
                        f"{'='*70}\n\n"
                        f"Secret scanning is enabled but no scanner is available.\n\n"
                    )

                    if pattern_server_attempted:
                        error_msg += (
                            f"Attempted fallback:\n"
                            f"  1. Pattern server: {pattern_config.get('url')} - unavailable\n"
                            f"  2. Scanner engines: {engines_list} - none installed\n\n"
                        )
                    else:
                        error_msg += (
                            f"Tried scanner engines: {engines_list} - none installed\n\n"
                        )

                    error_msg += (
                        f"This operation has been blocked for security.\n\n"
                        f"To fix:\n"
                        f"  1. Install a scanner: brew install gitleaks\n"
                        f"  2. OR disable secret_scanning in config\n"
                        f"{'='*70}\n"
                    )
                    logging.error(f"No scanner available")
                    return True, error_msg

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
                prefix='scanner_report_',
                dir=tmp_base_dir,
                delete=False
            ) as rf:
                report_file = rf.name

            # If we have pattern server config, select engine for using it
            # (engine_config already set above if using scanner defaults)
            if gitleaks_config_path and not engine_config and HAS_SCANNER_ENGINE:
                try:
                    scanner_config, _ = _load_secret_scanning_config()
                    engines_list = scanner_config.get("engines", ["gitleaks"]) if scanner_config else ["gitleaks"]
                    engine_config = select_engine(engines_list)
                except RuntimeError as e:
                    # No scanner found - error already logged
                    error_msg = (
                        f"\n{'='*70}\n"
                        f"🚨 BLOCKED BY POLICY\n"
                        f"🔒 NO SCANNER AVAILABLE\n"
                        f"{'='*70}\n\n"
                        f"{str(e)}\n\n"
                        f"Secret scanning is enabled but no scanner is available.\n\n"
                        f"This operation has been blocked for security.\n"
                        f"Install a scanner or update your configuration.\n"
                        f"{'='*70}\n"
                    )
                    logging.error(f"Scanner engine selection failed: {e}")
                    return True, error_msg
                except Exception as e:
                    logging.error(f"Unexpected error selecting scanner engine: {e}")
                    return False, None

            # Build scanner command
            if engine_config and HAS_SCANNER_ENGINE:
                # Use flexible engine builder (Issue #154)
                cmd = build_scanner_command(
                    engine_config=engine_config,
                    source_file=tmp_file_path,
                    report_file=report_file,
                    config_path=str(Path(gitleaks_config_path).absolute()) if gitleaks_config_path else None
                )
            else:
                # Legacy fallback: hardcoded gitleaks command
                logging.debug("Using legacy gitleaks command (scanner engine not available)")
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

            # Run scanner
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # Prevent hanging
            )

            # Determine expected exit codes for secrets found/success
            # Use engine-specific codes if available, otherwise use gitleaks defaults
            expected_secrets_code = engine_config.secrets_found_exit_code if engine_config else 42
            expected_success_codes = [engine_config.success_exit_code] if engine_config else [0, 1]
            # Also accept exit code 1 for gitleaks compatibility
            if engine_config and engine_config.type == "gitleaks" and 1 not in expected_success_codes:
                expected_success_codes.append(1)

            # Check exit code
            if result.returncode == expected_secrets_code:  # Secrets found
                # Parse scanner output using appropriate parser (Issue #154)
                secret_details = None
                scan_result = None

                if engine_config and HAS_SCANNER_ENGINE:
                    # Use flexible parser based on engine type
                    try:
                        parser = get_parser(engine_config.output_parser)
                        scan_result = parser.parse(report_file)
                        if scan_result and scan_result.get("has_secrets"):
                            # Convert to legacy format for compatibility
                            first_finding = scan_result["findings"][0] if scan_result["findings"] else {}
                            secret_details = {
                                "rule_id": first_finding.get("rule_id", "Unknown"),
                                "file": first_finding.get("file", filename),
                                "line_number": first_finding.get("line_number", 0),
                                "end_line": first_finding.get("end_line", 0),
                                "commit": first_finding.get("commit", "N/A"),
                                "total_findings": scan_result.get("total_findings", 0)
                            }
                    except Exception as e:
                        logging.error(f"Failed to parse scanner output with {engine_config.output_parser} parser: {e}")
                else:
                    # Legacy parser for gitleaks
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
                                    "total_findings": len(findings)
                                }
                    except Exception as e:
                        logging.debug(f"Failed to parse scanner JSON report: {e}")

                # Build error message with details if available
                scanner_name = engine_config.type if engine_config else "Gitleaks"
                error_msg = (
                    f"\n{'='*70}\n"
                    f"🛡️ Secret Detected\n"
                    f"{'='*70}\n\n"
                    f"Protection: Secret Scanning\n"
                )

                # Include specific details if we have them
                if secret_details:
                    error_msg += f"Secret Type: {secret_details['rule_id']}\n"
                    if secret_details.get('line_number'):
                        error_msg += f"Location: {secret_details['file']}:{secret_details['line_number']}\n"
                    else:
                        error_msg += f"Location: {secret_details['file']}\n"
                else:
                    error_msg += "Secret Type: (multiple or unknown)\n"

                # Add scanner information
                error_msg += f"Scanner: {scanner_name}\n"

                if config_source == "pattern server" and pattern_config:
                    error_msg += f"Patterns: LeakTK Pattern Server ({pattern_config.get('url', 'N/A')})\n"
                elif config_source == "project config" and gitleaks_config_path:
                    error_msg += f"Patterns: {gitleaks_config_path}\n"
                elif config_source == "gitleaks defaults":
                    error_msg += "Patterns: Built-in Defaults (100+ rules)\n"

                error_msg += (
                    f"\nWhy blocked: Hard-coded secrets in source code can leak to version control\n"
                    f"and be accessed by unauthorized users.\n\n"
                    f"This operation has been blocked for security.\n"
                    f"Please remove the sensitive information and try again.\n\n"
                    f"DO NOT attempt to bypass this protection - it prevents credential leaks.\n\n"
                    f"Recommendation:\n"
                    f"  • Move secrets to environment variables\n"
                    f"  • Use secret management (AWS Secrets Manager, HashiCorp Vault)\n"
                    f"  • Add to .gitignore if in config file\n"
                    f"  • Never commit secrets to git\n"
                    f"  • If false positive: add '# gitleaks:allow' comment to the line\n\n"
                    f"⚠️  Secret value NOT shown in this message for security\n\n"
                )

                # Only show generic list if we don't have specific details
                if not secret_details:
                    error_msg += (
                        "Common secret types:\n"
                        "  • API keys and tokens\n"
                        "  • Private keys (SSH, RSA, PGP)\n"
                        "  • Database credentials\n"
                        "  • Cloud provider keys (AWS, GCP, Azure)\n\n"
                    )

                error_msg += (
                    f"Config: ~/.config/ai-guardian/ai-guardian.json\n"
                    f"Section: secret_scanning.enabled\n"
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

            elif result.returncode in expected_success_codes:
                # No secrets found
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
        # Scanner binary not found - warn but allow (user may not be able to install immediately)
        scanner_name = engine_config.type if engine_config else "scanner"
        logging.warning(f"{scanner_name} binary not found - skipping secret scanning")

        # Print visible warning to stderr
        warning_msg = (
            f"\n{'='*70}\n"
            f"⚠️  SECRET SCANNING DISABLED\n"
            f"{'='*70}\n\n"
            f"{scanner_name.capitalize()} binary not found - secret scanning is currently disabled.\n\n"
            "AI Guardian requires a secret scanner to detect sensitive information like:\n"
            "  • API keys and tokens\n"
            "  • Private keys (SSH, RSA, PGP)\n"
            "  • Database credentials\n"
            "  • Cloud provider keys (AWS, GCP, Azure)\n\n"
            "Install a supported scanner:\n"
            "  Gitleaks:     brew install gitleaks\n"
            "  BetterLeaks:  brew install betterleaks (20-40% faster)\n"
            "  LeakTK:       brew install leaktk/tap/leaktk\n\n"
            "See https://github.com/itdove/ai-guardian for more information.\n\n"
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

            # If config has errors, log warning and continue with defaults
            # (ignore lists default to [] when secret_config is None)
            if config_error:
                logging.warning(f"Config error in PostToolUse: {config_error}")

            # Check if secret scanning is enabled (respect disabled_until)
            if secret_config and not is_feature_enabled(
                secret_config.get("enabled", True),
                secret_config.get("disabled_until")
            ):
                logging.info("Secret scanning is disabled - skipping PostToolUse scan")
                return format_response(ide_type, has_secrets=False, hook_event=hook_event)

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
                # Check if redaction is enabled
                redaction_config, redaction_error = _load_secret_redaction_config()

                if redaction_error:
                    logging.warning(f"Config error loading secret_redaction: {redaction_error}")
                    # Fall back to blocking
                    logging.warning(f"Secrets detected in {tool_identifier} output - blocking")
                    return format_response(ide_type, has_secrets=True,
                                         error_message=error_message,
                                         hook_event=hook_event)

                # Determine action mode (always redact when secrets detected)
                if redaction_config is None:
                    redaction_config = {}

                action = redaction_config.get("action", "warn")
                enabled = redaction_config.get("enabled", True)

                if enabled:
                    # REDACT instead of block
                    logging.info(f"Secret redaction enabled with action={action}")

                    try:
                        from ai_guardian.secret_redactor import SecretRedactor

                        # Also load PII config so secrets+PII are handled in one pass
                        pii_config_for_redactor, _ = _load_pii_config()
                        pii_cfg = pii_config_for_redactor if pii_config_for_redactor and pii_config_for_redactor.get('enabled', True) else None
                        redactor = SecretRedactor(redaction_config, pii_config=pii_cfg)
                        result = redactor.redact(tool_output)

                        redacted_text = result['redacted_text']
                        redactions = result['redactions']

                        # Log redaction event
                        logging.warning(f"Redacted {len(redactions)} secret(s) from {tool_identifier} output")
                        for r in redactions:
                            logging.info(f"  - {r['type']} at position {r['position']} using {r['strategy']}")

                        # Log to violation logger
                        from ai_guardian.violation_logger import ViolationLogger
                        violation_logger = ViolationLogger()
                        violation_logger.log_violation(
                            violation_type='secret_redaction',
                            blocked={
                                'tool': tool_identifier,
                                'redaction_count': len(redactions),
                                'redacted_types': [r['type'] for r in redactions]
                            },
                            context={
                                'action': 'redacted',
                                'mode': action
                            }
                        )

                        # Return redacted output (allow, with modifications)
                        # For warn mode, include a warning message
                        warning_msg = None
                        if action == "warn":
                            warning_msg = (
                                f"⚠️  Redacted {len(redactions)} secret(s) from output:\n"
                                + "\n".join([f"  - {r['type']}" for r in redactions[:5]])
                                + ("\n  - ..." if len(redactions) > 5 else "")
                            )
                            logging.warning(f"WARN mode: {warning_msg}")

                        logging.info(f"✓ Secrets redacted, allowing output to continue")
                        return format_response(ide_type, has_secrets=False, hook_event=hook_event,
                                             warning_message=warning_msg, modified_output=redacted_text)

                    except Exception as redact_error:
                        logging.error(f"Error during secret redaction: {redact_error}")
                        import traceback
                        logging.error(traceback.format_exc())
                        # Fall back to blocking on redaction errors
                        logging.warning(f"Redaction failed, falling back to blocking")
                        return format_response(ide_type, has_secrets=True,
                                             error_message=error_message,
                                             hook_event=hook_event)
                else:
                    # Emergency bypass - allow secrets through when redaction disabled
                    logging.warning(
                        f"Secrets detected but redaction disabled (emergency bypass) - allowing through"
                    )
                    return format_response(ide_type, has_secrets=False, hook_event=hook_event)

            logging.info(f"✓ No secrets detected in {tool_identifier} output")

            # PII scanning in PostToolUse (Issue #262)
            pii_config, pii_error = _load_pii_config()
            if pii_error:
                logging.warning(f"PII config error: {pii_error}")
            if pii_config and pii_config.get('enabled', True):
                logging.info("Scanning tool output for PII...")
                has_pii, redacted_text, pii_redactions, pii_warning = _scan_for_pii(tool_output, pii_config)
                if has_pii:
                    pii_action = pii_config.get('action', 'redact')
                    pii_types = list(set(r['type'] for r in pii_redactions))
                    logging.warning(f"PII detected in {tool_identifier} output: {pii_types}")

                    # Log violation
                    from ai_guardian.violation_logger import ViolationLogger
                    violation_logger = ViolationLogger()
                    violation_logger.log_violation(
                        violation_type='pii_detected',
                        blocked={
                            'tool': tool_identifier,
                            'hook': 'PostToolUse',
                            'pii_count': len(pii_redactions),
                            'pii_types': pii_types
                        },
                        context={'action': pii_action, 'hook_event': 'posttooluse'}
                    )

                    if pii_action == 'redact':
                        return format_response(ide_type, has_secrets=False, hook_event=hook_event,
                                             warning_message=pii_warning, modified_output=redacted_text)
                    elif pii_action == 'block':
                        return format_response(ide_type, has_secrets=True,
                                             error_message=pii_warning, hook_event=hook_event)
                    # log-only: fall through to allow
                    elif pii_action == 'log-only':
                        return format_response(ide_type, has_secrets=False, hook_event=hook_event,
                                             warning_message=pii_warning)

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
                # Try both "parameters" (PreToolUse) and "input" (PostToolUse)
                tool_input = hook_data["tool_use"].get("parameters") or hook_data["tool_use"].get("input", {})
            elif "tool" in hook_data and isinstance(hook_data["tool"], dict):
                tool_name = hook_data["tool"].get("name")
                tool_input = hook_data.get("tool_input", {})
            elif "toolName" in hook_data:
                # GitHub Copilot format
                tool_name = hook_data["toolName"]
                # toolArgs is a JSON string in Copilot format
                if "toolArgs" in hook_data:
                    try:
                        tool_input = json.loads(hook_data["toolArgs"])
                    except (json.JSONDecodeError, TypeError):
                        tool_input = {}
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

                        # Extract tool-specific parameters for better logging
                        tool_details = ""
                        if tool_input:
                            if checked_tool_name == "Skill" or (tool_name == "Skill" and checked_tool_name.startswith("Skill:")):
                                # For Skill tool: show skill name and args
                                skill_name = tool_input.get("skill", "unknown")
                                skill_args = tool_input.get("args", "")
                                args_preview = skill_args[:50] + "..." if len(skill_args) > 50 else skill_args
                                tool_details = f" (skill='{skill_name}', args='{args_preview}')"
                            elif tool_name == "Bash":
                                # For Bash tool: show command preview
                                command = tool_input.get("command", "")
                                cmd_preview = command[:100] + "..." if len(command) > 100 else command
                                tool_details = f" (command='{cmd_preview}')"
                            elif tool_name in ["Read", "Write", "Edit"]:
                                # For file tools: show full file path
                                file_path = tool_input.get("file_path") or tool_input.get("path", "")
                                if file_path:
                                    tool_details = f" (file_path='{file_path}')"

                        logging.warning(f"🚨 BLOCKED BY POLICY: Tool '{checked_tool_name}'{tool_details} - {reason_summary}")
                        # Include any config errors with the blocking message
                        combined_warning = "\n\n".join(warning_messages) if warning_messages else None
                        return format_response(ide_type, has_secrets=True, error_message=error_message, hook_event=hook_event, warning_message=combined_warning)
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
            # PreToolUse or beforeReadFile hook
            logging.info(f"Processing {hook_event} hook...")

            # Only extract file content for file-reading tools
            # Bash, Write, Edit, etc. don't read files in PreToolUse - they have command/content parameters
            # Bug #94: Bash commands were incorrectly treated as file paths
            # Bug #174: Glob removed - uses 'pattern' parameter, not 'file_path', doesn't read content in PreToolUse
            FILE_READING_TOOLS = [
                # Claude Code tool names
                "Read", "Grep",
                # GitHub Copilot tool names
                "read_file", "read", "grep", "search",
                # Cursor tool names (if different)
                "ReadFile"
            ]

            if tool_name in FILE_READING_TOOLS or hook_event == "beforereadfile":
                # Extract file content for tools that read files
                content_to_scan, filename, file_path, is_denied, deny_reason, dir_warning = extract_file_content_from_tool(hook_data)

                # Check if directory access is denied
                if is_denied:
                    logging.warning(f"Directory access denied for file '{file_path}'")
                    # Include any config errors with the blocking message
                    combined_warning = "\n\n".join(warning_messages) if warning_messages else None
                    return format_response(ide_type, has_secrets=True, error_message=deny_reason, hook_event=hook_event, warning_message=combined_warning)
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
                # Non-file-reading tool (Bash, Write, Edit, etc.)
                # These tools don't read files in PreToolUse, so no content to scan here
                # They are checked by tool_policy.py for command patterns
                logging.info(f"Tool '{tool_name}' does not read files - skipping file content scan")

                # No content to scan for these tools in PreToolUse
                # Allow operation (secret scanning happens for Bash in PostToolUse if enabled)
                combined_warning = "\n\n".join(warning_messages) if warning_messages else None
                return format_response(ide_type, has_secrets=False, hook_event=hook_event, warning_message=combined_warning)

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
                    # Determine source type based on hook event
                    # UserPromptSubmit = user input (check all patterns, threshold 0.75)
                    # PreToolUse = file content (check critical patterns only, threshold 0.90)
                    source_type = "user_prompt" if hook_event == "prompt" else "file_content"

                    should_block, injection_error, injection_detected = check_prompt_injection(
                        content_to_scan, injection_config, file_path=file_path, tool_name=tool_identifier, source_type=source_type
                    )

                    # Log violation if injection was detected (in both log and block modes)
                    if injection_detected:
                        _log_prompt_injection_violation(
                            filename,
                            context={"ide_type": ide_type.value, "hook_event": hook_event, "file_path": file_path}
                        )

                    if should_block:
                        # Prompt injection detected - block operation
                        # Note: detailed logging (confidence, pattern, text) already done in prompt_injection.py
                        if ide_type != IDEType.CURSOR:
                            if file_path:
                                logging.info(f"Blocking operation for {file_path} due to prompt injection detection")
                            else:
                                logging.info("Blocking operation due to prompt injection detection")

                        # Include any config errors with the blocking message
                        combined_warning = "\n\n".join(warning_messages) if warning_messages else None
                        return format_response(ide_type, has_secrets=True, error_message=injection_error, hook_event=hook_event, warning_message=combined_warning)
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

        # Check for config file threats (credential exfiltration patterns in AI config files)
        # Only scan for PreToolUse/Read operations on actual files
        logger.debug(f"Config scanner check: HAS_CONFIG_SCANNER={HAS_CONFIG_SCANNER}, hook_event={hook_event}, file_path={file_path}, has_content={content_to_scan is not None}")
        if HAS_CONFIG_SCANNER and hook_event in ["pretooluse", "beforereadfile"] and file_path and content_to_scan:
            logger.debug("Config scanner conditions met, running scan...")
            try:
                scanner_config, config_error = _load_config_scanner_config()
                if config_error:
                    warning_messages.append(config_error)

                # Check if config file scanning is enabled (supports time-based disabling)
                # Default to enabled even if config section doesn't exist
                is_enabled = is_feature_enabled(
                    scanner_config.get("enabled") if scanner_config else None,
                    datetime.now(timezone.utc),
                    default=True
                )

                if is_enabled:
                    should_block, config_error, config_details = check_config_file_threats(
                        file_path, content_to_scan, scanner_config
                    )

                    if should_block:
                        # Config file threat detected - block operation
                        if ide_type != IDEType.CURSOR:
                            logging.info(f"Blocking operation for {file_path} due to config file threat")

                        # Log config file exfiltration violation
                        if HAS_VIOLATION_LOGGER:
                            try:
                                violation_logger = ViolationLogger()
                                violation_logger.log_violation(
                                    violation_type="config_file_exfil",
                                    blocked={
                                        "file_path": file_path,
                                        "reason": config_error,
                                        "details": config_details
                                    },
                                    context={
                                        "ide_type": ide_type.value if hasattr(ide_type, 'value') else str(ide_type),
                                        "hook_event": hook_event,
                                        "project_path": os.getcwd()
                                    },
                                    severity="critical"
                                )
                            except Exception as e:
                                logging.debug(f"Failed to log config file exfil violation: {e}")

                        # Include any config errors with the blocking message
                        combined_warning = "\n\n".join(warning_messages) if warning_messages else None
                        return format_response(ide_type, has_secrets=True, error_message=config_error, hook_event=hook_event, warning_message=combined_warning)
                    elif config_details and config_error:
                        # Log/warn mode: threat detected but execution allowed - display warning
                        warning_messages.append(config_error)

                    if ide_type != IDEType.CURSOR:
                        if not config_details:
                            logging.debug("✓ No config file threats detected")
                elif ide_type != IDEType.CURSOR:
                    # Config file scanning is temporarily disabled
                    logging.info("⚠️  Config file scanning temporarily disabled")
            except Exception as e:
                # Fail-open: if config scanning fails, continue
                logging.warning(f"Config file scanning error (fail-open): {e}")

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
                # Include any warning messages (e.g., JSON config errors) with the blocking message
                combined_warning = "\n\n".join(warning_messages) if warning_messages else None
                return format_response(ide_type, has_secrets=True, error_message=error_message, hook_event=hook_event, warning_message=combined_warning)

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

        # PII scanning for UserPromptSubmit and PreToolUse (Issue #262)
        if content_to_scan:
            pii_config, pii_error = _load_pii_config()
            if pii_error:
                logging.warning(f"PII config error: {pii_error}")
            if pii_config and pii_config.get('enabled', True):
                # Check ignore_files for PreToolUse
                pii_ignore_files = pii_config.get('ignore_files', [])
                should_scan_pii = True
                if file_path and pii_ignore_files:
                    import fnmatch
                    for pattern in pii_ignore_files:
                        if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(filename, pattern):
                            logging.info(f"Skipping PII scan for {filename} (matched ignore pattern: {pattern})")
                            should_scan_pii = False
                            break

                if should_scan_pii:
                    logging.info(f"Scanning {'prompt' if hook_event == 'prompt' else filename} for PII...")
                    has_pii, _, pii_redactions, pii_warning = _scan_for_pii(content_to_scan, pii_config)
                    if has_pii:
                        pii_action = pii_config.get('action', 'redact')
                        pii_types = list(set(r['type'] for r in pii_redactions))
                        logging.warning(f"PII detected: {pii_types}")

                        # Log violation
                        from ai_guardian.violation_logger import ViolationLogger
                        violation_logger = ViolationLogger()
                        hook_name = 'UserPromptSubmit' if hook_event == 'prompt' else 'PreToolUse'
                        violation_logger.log_violation(
                            violation_type='pii_detected',
                            blocked={
                                'tool': tool_identifier or filename,
                                'hook': hook_name,
                                'pii_count': len(pii_redactions),
                                'pii_types': pii_types
                            },
                            context={'action': pii_action, 'hook_event': hook_event}
                        )

                        if pii_action == 'block':
                            combined_warning = "\n\n".join(warning_messages) if warning_messages else None
                            final_error = pii_warning
                            if combined_warning:
                                final_error = f"{combined_warning}\n\n{pii_warning}"
                            return format_response(ide_type, has_secrets=True,
                                                 error_message=final_error, hook_event=hook_event)
                        elif pii_action == 'redact':
                            # UserPromptSubmit and PreToolUse cannot modify content,
                            # so redact mode falls back to blocking with an explanation.
                            combined_warning = "\n\n".join(warning_messages) if warning_messages else None
                            final_error = pii_warning
                            if combined_warning:
                                final_error = f"{combined_warning}\n\n{pii_warning}"
                            return format_response(ide_type, has_secrets=True,
                                                 error_message=final_error, hook_event=hook_event)
                        elif pii_action == 'log-only':
                            warning_messages.append(pii_warning)

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
        setup_parser.add_argument(
            "--create-config",
            action="store_true",
            help="Create default ai-guardian.json config file"
        )
        setup_parser.add_argument(
            "--permissive",
            action="store_true",
            help="Use permissive config (permissions disabled, all tools allowed)"
        )
        setup_parser.add_argument(
            "--pre-commit",
            action="store_true",
            help="Install pre-commit hooks for git workflow"
        )
        setup_parser.add_argument(
            "--auto-install-hooks",
            action="store_true",
            help="Allow automatic hook installation (default: show instructions only)"
        )
        setup_parser.add_argument(
            "--uninstall-hooks",
            action="store_true",
            help="Remove AI Guardian pre-commit hooks"
        )
        setup_parser.add_argument(
            "--install-scanner",
            nargs="?",
            const="gitleaks",
            choices=["gitleaks", "betterleaks", "leaktk"],
            help="Install scanner engine (default: gitleaks)"
        )
        setup_parser.add_argument(
            "--json",
            action="store_true",
            dest="json_output",
            help="Output only raw JSON config (use with --create-config)"
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

        # Scan subcommand
        scan_parser = subparsers.add_parser(
            "scan",
            help="Scan repository files for security issues"
        )
        scan_parser.add_argument(
            "path",
            nargs="?",
            default=".",
            help="Path to scan (file or directory, default: current directory)"
        )
        scan_parser.add_argument(
            "--config",
            metavar="FILE",
            help="Path to ai-guardian.json config file"
        )
        scan_parser.add_argument(
            "--include",
            action="append",
            metavar="PATTERN",
            help="File patterns to include (glob style, can be specified multiple times)"
        )
        scan_parser.add_argument(
            "--exclude",
            action="append",
            metavar="PATTERN",
            help="File patterns to exclude (glob style, can be specified multiple times)"
        )
        scan_parser.add_argument(
            "--config-only",
            action="store_true",
            help="Only scan AI config files (CLAUDE.md, AGENTS.md, etc.)"
        )
        scan_parser.add_argument(
            "--sarif-output",
            metavar="FILE",
            help="Write SARIF format output to file (for CI/CD integration)"
        )
        scan_parser.add_argument(
            "--json-output",
            metavar="FILE",
            help="Write JSON format output to file"
        )
        scan_parser.add_argument(
            "--exit-code",
            action="store_true",
            help="Exit with code 1 if security issues found (for CI/CD)"
        )
        scan_parser.add_argument(
            "--verbose",
            "-v",
            action="store_true",
            help="Enable verbose output"
        )

        # Show-config subcommand (NEW in v1.5.0)
        show_config_parser = subparsers.add_parser(
            "show-config",
            help="Display effective configuration with source attribution"
        )
        show_config_parser.add_argument(
            "--feature",
            choices=["ssrf", "secrets", "unicode", "config-scanner", "all"],
            default="all",
            help="Which feature to show (default: all)"
        )
        show_config_parser.add_argument(
            "--show-sources",
            action="store_true",
            help="Show source attribution (IMMUTABLE, SERVER, DEFAULT, LOCAL_CONFIG)"
        )
        show_config_parser.add_argument(
            "--json",
            action="store_true",
            help="Output as JSON"
        )
        show_config_parser.add_argument(
            "--config",
            metavar="FILE",
            help="Path to ai-guardian.json config file (default: auto-detect)"
        )

        # Config subcommand (NEW in v1.8.0, Issue #144)
        config_parser = subparsers.add_parser(
            "config",
            help="Configuration management (show merged config, preview auto-rules)"
        )
        config_sub = config_parser.add_subparsers(dest="config_command", help="Config commands")

        # config show
        config_show_parser = config_sub.add_parser("show", help="Display merged configuration")
        config_show_parser.add_argument(
            "--all",
            action="store_true",
            help="Include auto-generated rules marked [GENERATED]"
        )
        config_show_parser.add_argument(
            "--section",
            metavar="NAME",
            help="Show specific section only (e.g., permissions, directory_rules)"
        )
        config_show_parser.add_argument(
            "--preview-auto-rules",
            action="store_true",
            help="Preview what auto-generation would create (without enabling)"
        )
        config_show_parser.add_argument(
            "--json",
            action="store_true",
            help="Output configuration as JSON"
        )

        # Scanner subcommand (NEW in v1.6.0)
        scanner_parser = subparsers.add_parser(
            "scanner",
            help="Manage scanner engines (install, list, info)"
        )
        scanner_sub = scanner_parser.add_subparsers(dest="scanner_command", help="Scanner commands")

        # scanner list
        scanner_list_parser = scanner_sub.add_parser("list", help="List installed scanners")
        scanner_list_parser.add_argument(
            "--verbose",
            "-v",
            action="store_true",
            help="Show installation paths"
        )
        scanner_list_parser.add_argument(
            "--json",
            action="store_true",
            help="Output as JSON"
        )

        # scanner install
        scanner_install_parser = scanner_sub.add_parser("install", help="Install a scanner")
        scanner_install_parser.add_argument(
            "name",
            choices=["gitleaks", "betterleaks", "leaktk", "trufflehog", "detect-secrets"],
            help="Scanner to install"
        )
        scanner_install_parser.add_argument(
            "--version",
            help="Install specific version (e.g., 8.30.1)"
        )
        scanner_install_parser.add_argument(
            "--use-pinned",
            action="store_true",
            help="Use version from pyproject.toml (tested with this ai-guardian release)"
        )
        scanner_install_parser.add_argument(
            "--path",
            type=Path,
            help="Custom installation directory (default: /usr/local/bin, fallback: ~/.local/bin)"
        )

        # scanner info
        scanner_info_parser = scanner_sub.add_parser("info", help="Show scanner details")
        scanner_info_parser.add_argument(
            "name",
            choices=["gitleaks", "betterleaks", "leaktk", "trufflehog", "detect-secrets"],
            help="Scanner to show info for"
        )
        scanner_info_parser.add_argument(
            "--json",
            action="store_true",
            help="Output as JSON"
        )

        # scanner supported
        scanner_supported_parser = scanner_sub.add_parser(
            "supported",
            help="List all supported scanners with versions and repos"
        )
        scanner_supported_parser.add_argument(
            "--json",
            action="store_true",
            help="Output as JSON"
        )

        # Pattern-servers subcommand
        pattern_servers_parser = subparsers.add_parser(
            "pattern-servers",
            help="Pattern server management"
        )
        pattern_servers_sub = pattern_servers_parser.add_subparsers(
            dest="pattern_servers_command",
            help="Pattern server commands"
        )

        # pattern-servers supported
        ps_supported_parser = pattern_servers_sub.add_parser(
            "supported",
            help="List all supported pattern servers"
        )
        ps_supported_parser.add_argument(
            "--json",
            action="store_true",
            help="Output as JSON"
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
                migrate_pattern_server=args.migrate_pattern_server,
                create_config=args.create_config,
                permissive=args.permissive,
                pre_commit=args.pre_commit,
                auto_install_hooks=args.auto_install_hooks,
                uninstall_hooks=args.uninstall_hooks,
                install_scanner=args.install_scanner,
                json_output=args.json_output
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

        # Handle scan command
        if args.command == "scan":
            try:
                from ai_guardian.scanner import scan_command
                return scan_command(args)
            except ImportError as e:
                print(f"Error: Scanner module not available: {e}", file=sys.stderr)
                return 1
            except Exception as e:
                print(f"Error running scan: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc()
                return 1

        # Handle show-config command (NEW in v1.5.0)
        if args.command == "show-config":
            try:
                from ai_guardian.config_inspector import ConfigInspector

                # Load config
                if args.config:
                    config_path = Path(args.config)
                    if config_path.exists():
                        import json
                        config = json.loads(config_path.read_text())
                    else:
                        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
                        return 1
                else:
                    # Try to find config in default locations
                    config_candidates = [
                        Path.cwd() / "ai-guardian.json",
                        Path.cwd() / ".ai-guardian.json",
                        Path.home() / ".config" / "ai-guardian" / "ai-guardian.json",
                    ]
                    config_path = None
                    for candidate in config_candidates:
                        if candidate.exists():
                            config_path = candidate
                            break

                    if config_path:
                        import json
                        config = json.loads(config_path.read_text())
                    else:
                        # No config found, use empty config (show defaults)
                        config = {}

                inspector = ConfigInspector(config)

                # Output format
                if args.json:
                    print(inspector.export_json())
                else:
                    # Display specific feature or all
                    if args.feature == "ssrf":
                        print(inspector.show_ssrf_config(show_sources=args.show_sources))
                    elif args.feature == "secrets":
                        print(inspector.show_secret_config(show_sources=args.show_sources))
                    elif args.feature == "unicode":
                        print(inspector.show_unicode_config(show_sources=args.show_sources))
                    elif args.feature == "config-scanner":
                        print(inspector.show_config_scanner_config(show_sources=args.show_sources))
                    else:  # all
                        print(inspector.show_all(show_sources=args.show_sources))

                return 0
            except ImportError as e:
                print(f"Error: Config inspector module not available: {e}", file=sys.stderr)
                return 1
            except Exception as e:
                print(f"Error displaying configuration: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc()
                return 1

        # Handle config command (NEW in v1.8.0, Issue #144)
        if args.command == "config":
            try:
                from ai_guardian.config_display import ConfigDisplay

                if args.config_command is None:
                    config_parser.print_help()
                    return 1

                if args.config_command == "show":
                    display = ConfigDisplay()
                    output = display.show(
                        show_all=args.all,
                        section=args.section,
                        preview_auto_rules=args.preview_auto_rules,
                        output_json=args.json
                    )
                    print(output)
                    return 0
                else:
                    print(f"Unknown config command: {args.config_command}", file=sys.stderr)
                    return 1

            except ImportError as e:
                print(f"Error: Config display module not available: {e}", file=sys.stderr)
                return 1
            except Exception as e:
                print(f"Error displaying configuration: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc()
                return 1

        # Handle scanner command (NEW in v1.6.0)
        if args.command == "scanner":
            try:
                from ai_guardian.scanner_installer import ScannerInstaller
                from ai_guardian.scanner_manager import ScannerManager

                if args.scanner_command == "list":
                    manager = ScannerManager()
                    if args.json:
                        print(manager.get_scanner_list_json())
                    else:
                        manager.print_scanner_list(verbose=args.verbose)
                    return 0

                elif args.scanner_command == "install":
                    # Create installer with custom path if provided
                    install_dir = args.path if hasattr(args, 'path') and args.path else None
                    installer = ScannerInstaller(install_dir=install_dir)

                    print(f"Installing {args.name}...")
                    success = installer.install(
                        args.name,
                        version=args.version,
                        use_pinned=args.use_pinned
                    )

                    if success:
                        # Verify installation
                        if installer.verify_installation(args.name):
                            print(f"\n✓ {args.name} is ready to use")

                            # Show suggestion to update config
                            print(f"\nRecommended: Update your configuration to use {args.name}")
                            print(f"\nAdd to ~/.config/ai-guardian/ai-guardian.json:")
                            print('{')
                            print('  "secret_scanning": {')
                            print('    "enabled": true,')
                            print(f'    "engines": ["{args.name}"]')
                            print('  }')
                            print('}')
                        else:
                            print(f"\n⚠ Installation completed but {args.name} verification failed")
                            print(f"Make sure ~/.local/bin is in your PATH")
                            return 1
                        return 0
                    else:
                        print(f"\n✗ Failed to install {args.name}")
                        return 1

                elif args.scanner_command == "info":
                    manager = ScannerManager()
                    if args.json:
                        print(manager.get_scanner_info_json(args.name))
                    else:
                        manager.print_scanner_info(args.name)
                    return 0

                elif args.scanner_command == "supported":
                    manager = ScannerManager()
                    if args.json:
                        print(manager.get_supported_scanners_json())
                    else:
                        manager.print_supported_scanners()
                    return 0

                else:
                    # No scanner subcommand provided
                    scanner_parser.print_help()
                    return 1

            except Exception as e:
                print(f"Error managing scanner: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc()
                return 1

        # Handle pattern-servers command
        if args.command == "pattern-servers":
            try:
                from ai_guardian.scanner_manager import ScannerManager

                if args.pattern_servers_command is None:
                    pattern_servers_parser.print_help()
                    return 1

                if args.pattern_servers_command == "supported":
                    manager = ScannerManager()
                    if args.json:
                        print(manager.get_pattern_servers_json())
                    else:
                        manager.print_pattern_servers()
                    return 0

                else:
                    pattern_servers_parser.print_help()
                    return 1

            except Exception as e:
                print(f"Error managing pattern servers: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc()
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
