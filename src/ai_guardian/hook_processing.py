"""
Hook processing logic for AI Guardian.

Contains the core hook processing pipeline: directory checking, tool extraction,
secret scanning, PII detection, violation logging, transcript scanning,
and the main process_hook_data() entry point.
"""

try:
    import fcntl

    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False
import fnmatch
import glob


def _fnmatch_path(path, pattern):
    """fnmatch with normalized separators for cross-platform path matching."""
    return fnmatch.fnmatch(path.replace("\\", "/"), pattern.replace("\\", "/"))


def _startswith_path(path, prefix):
    """startswith with normalized separators for cross-platform path matching."""
    return path.replace("\\", "/").startswith(prefix.replace("\\", "/"))


def _resolve_pattern_path(pattern):
    """Resolve a glob pattern path: realpath for the concrete prefix, normpath for wildcard suffix."""
    expanded = os.path.expanduser(pattern)
    star_idx = expanded.find("*")
    if star_idx == -1:
        return os.path.realpath(expanded)
    prefix = expanded[:star_idx]
    suffix = expanded[star_idx:]
    last_sep = max(prefix.rfind("/"), prefix.rfind("\\"))
    if last_sep >= 0:
        dir_prefix = prefix[:last_sep]
        remainder = prefix[last_sep:] + suffix
    else:
        dir_prefix = ""
        remainder = expanded
    resolved_prefix = os.path.realpath(dir_prefix) if dir_prefix else ""
    return os.path.normpath(resolved_prefix + remainder)


import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from ai_guardian.config_utils import (
    get_config_dir,
    get_project_dir,
    get_state_dir,
    is_feature_enabled,
)
from ai_guardian.constants import ActionMode, ViolationType, HookEvent, AUGMENT_TOOL_MAP
from ai_guardian.scan_result import ScanResult
from ai_guardian.utils.path_matching import match_leading_doublestar_pattern

from ai_guardian.config_loaders import (
    _load_pattern_server_config,
    _load_prompt_injection_config,
    _load_config_scanner_config,
    _load_permissions_config,
    _load_secret_scanning_config,
    _load_secret_redaction_config,
    _load_pii_config,
    _load_transcript_scanning_config,
    _load_annotations_config,
    _load_image_scanning_config,
    _load_security_instructions_config,
    _load_context_poisoning_config,
    _load_supply_chain_config,
    _load_code_scanning_config,
    _load_offensive_language_config,
    _load_canary_detection_config,
    _load_exfil_detection_config,
    _get_on_scan_error_action,
    _load_config_file,  # noqa: F401 — patched by tests via this namespace
)
from ai_guardian.constants import parse_ask_action

from ai_guardian.response_format import (
    _SECURITY_SYSTEM_MESSAGE,
    IDEType,
)
from ai_guardian.hook_adapters import detect_adapter
from ai_guardian.latency_logger import _CheckTimer


def _format_response(adapter, **kwargs):
    """Call adapter.format_response() with [ai-guardian] prefix on warning_message.

    Replaces the backward-compat wrapper in response_format.py for internal
    use, ensuring the correct adapter instance (from detect_adapter) is used
    instead of re-resolving via IDEType enum.
    """
    wm = kwargs.get("warning_message")
    if wm and not wm.lstrip().startswith("[ai-guardian]"):
        kwargs["warning_message"] = f"[ai-guardian] {wm}"
    return adapter.format_response(**kwargs)


# Conditional imports for optional features
try:
    from ai_guardian import gitleaks_config as _gitleaks_cfg

    HAS_GITLEAKS_CONFIG = True
except ImportError:
    HAS_GITLEAKS_CONFIG = False

try:
    from ai_guardian.tool_policy import ToolPolicyChecker

    HAS_TOOL_POLICY = True
except ImportError:
    HAS_TOOL_POLICY = False

try:
    from ai_guardian.pattern_server import PatternServerClient

    HAS_PATTERN_SERVER = True
except ImportError:
    HAS_PATTERN_SERVER = False

try:
    from ai_guardian.prompt_injection import (
        check_prompt_injection,
        PromptInjectionDetector,
    )

    HAS_PROMPT_INJECTION = True
except ImportError:
    HAS_PROMPT_INJECTION = False

try:
    from ai_guardian.context_poisoning import ContextPoisoningDetector

    HAS_CONTEXT_POISONING = True
except ImportError:
    HAS_CONTEXT_POISONING = False

try:
    from ai_guardian.config_scanner import (
        check_config_file_threats,
        check_bash_command_threats,
    )

    HAS_CONFIG_SCANNER = True
except ImportError:
    HAS_CONFIG_SCANNER = False

try:
    from ai_guardian.supply_chain import SupplyChainScanner

    HAS_SUPPLY_CHAIN = True
except ImportError:
    HAS_SUPPLY_CHAIN = False

try:
    from ai_guardian.offensive_language import OffensiveLanguageScanner

    HAS_OFFENSIVE_LANGUAGE = True
except ImportError:
    HAS_OFFENSIVE_LANGUAGE = False

try:
    from ai_guardian.canary_detection import CanaryTokenScanner

    HAS_CANARY_DETECTION = True
except ImportError:
    HAS_CANARY_DETECTION = False

try:
    from ai_guardian.exfil_detection import ExfilDetectionScanner

    HAS_EXFIL_DETECTION = True
except ImportError:
    HAS_EXFIL_DETECTION = False

try:
    from ai_guardian.violation_logger import ViolationLogger

    HAS_VIOLATION_LOGGER = True
except ImportError:
    HAS_VIOLATION_LOGGER = False

try:
    from ai_guardian.scanners.engine_builder import (
        select_engine,
        select_all_engines,
        build_scanner_command,
        resolve_engine_config_path,
        PATTERN_SERVER_UNSET,
    )
    from ai_guardian.scanners.output_parsers import get_parser
    from ai_guardian.scanners.strategies import (
        get_strategy,
        ScanResult as StrategyScanResult,
        SecretMatch,
    )
    from ai_guardian.scanners.executor import run_single_engine, run_engine

    HAS_SCANNER_ENGINE = True
except ImportError:
    HAS_SCANNER_ENGINE = False

try:
    from ai_guardian.annotations import process_annotations

    HAS_ANNOTATIONS = True
except ImportError:
    HAS_ANNOTATIONS = False

try:
    from ai_guardian.image_scanner import ImageDetector, scan_image, ImageRedactor

    HAS_IMAGE_SCANNER = True
except ImportError:
    HAS_IMAGE_SCANNER = False

try:
    from ai_guardian.ast_scanner import extract_scannable_content

    HAS_AST_SCANNER = True
except ImportError:
    HAS_AST_SCANNER = False

logger = logging.getLogger(__name__)


def _is_latency_enabled():
    try:
        from ai_guardian.latency_logger import LatencyLogger

        return LatencyLogger()._is_enabled()
    except Exception:
        return False


def _finalize_latency(timer, hook_event, tool_name):
    if timer is None or not timer._enabled:
        return
    try:
        from ai_guardian.latency_logger import LatencyLogger

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "hook_event": (
                hook_event.value
                if hasattr(hook_event, "value")
                else str(hook_event or "")
            ),
            "tool": tool_name or "",
            "total_ms": round(timer.total_ms(), 2),
            "processing_ms": round(timer.processing_ms(), 2),
            "checks": {k: round(v, 2) for k, v in timer.to_dict().items()},
        }
        if timer.ask_wait_total_ms > 0:
            entry["ask_dialog_ms"] = round(timer.ask_wait_total_ms, 2)
        LatencyLogger().log_timing(entry)
    except Exception:
        pass  # intentionally silent — optional dependency


DEFAULT_ENGINES = ["toml-patterns", "gitleaks"]

# Keywords used to classify scanner error messages
_AUTH_ERROR_KEYWORDS = frozenset(
    {
        "401",
        "403",
        "unauthorized",
        "authentication",
        "forbidden",
        "authentication failed",
        "bad credentials",
        "invalid token",
        "access denied",
    }
)
_NETWORK_ERROR_KEYWORDS = frozenset(
    {
        "connection",
        "timeout",
        "network",
        "unreachable",
        "refused",
        "dial tcp",
        "no route",
        "no route to host",
    }
)

# Tools that modify state - don't scan their responses.
# These return metadata only; content was already scanned in PreToolUse.
STATE_MODIFY_TOOLS = frozenset(
    {
        "Write",
        "Edit",
        "Delete",
        "Move",
        "Rename",
        "NotebookEdit",
    }
)

# Tools that read files - need content scanning in PreToolUse.
FILE_READING_TOOLS = frozenset(
    {
        # Claude Code tool names
        "Read",
        "Grep",
        # GitHub Copilot tool names
        "read_file",
        "read",
        "grep",
        "search",
        # Cursor tool names (if different)
        "ReadFile",
    }
)

# Augment Code tool name mapping imported from constants (single source of truth).
_AUGMENT_TOOL_MAP = AUGMENT_TOOL_MAP


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
        if not is_feature_enabled(
            dir_exclusions.get("enabled", False),
            datetime.now(timezone.utc),
            default=False,
        ):
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
                logging.warning(
                    f"Invalid exclusion path (not a string): {exclusion_path}"
                )
                continue

            try:
                # Expand tilde and convert to absolute path, resolving symlinks
                expanded_path = _resolve_pattern_path(exclusion_path)

                # Check for wildcards
                if "**" in expanded_path:
                    # Recursive wildcard: match directory and all subdirectories
                    # Remove /** or ** from end for directory comparison
                    base_path = (
                        expanded_path.replace("\\**", "")
                        .replace("/**", "")
                        .replace("**", "")
                    )
                    if _startswith_path(abs_file_path, base_path):
                        logging.debug(
                            f"Path {abs_file_path} matches recursive exclusion: {exclusion_path}"
                        )
                        return True
                elif "*" in expanded_path:
                    # Get parent directory of file for matching
                    file_parent = os.path.dirname(abs_file_path)
                    wildcard_parent = os.path.dirname(expanded_path)

                    # Check if file's parent matches the wildcard pattern
                    if _fnmatch_path(file_parent, expanded_path) or _startswith_path(
                        file_parent, expanded_path.replace("\\*", "").replace("/*", "")
                    ):
                        logging.debug(
                            f"Path {abs_file_path} matches wildcard exclusion: {exclusion_path}"
                        )
                        return True
                else:
                    # Exact path match: check if file is within excluded directory
                    # Add trailing slash to ensure directory boundary matching
                    if (
                        _startswith_path(abs_file_path, expanded_path + "/")
                        or abs_file_path == expanded_path
                    ):
                        logging.debug(
                            f"Path {abs_file_path} matches exact exclusion: {exclusion_path}"
                        )
                        return True

            except Exception as e:
                logging.warning(
                    f"Error processing exclusion path '{exclusion_path}': {e}"
                )
                # Fail-safe: skip this exclusion path, continue checking others
                continue

        return False

    except Exception as e:
        logging.error(f"Error checking directory exclusions: {e}")
        # Fail-safe: if exclusion check fails, don't exclude (let normal blocking proceed)
        return False


def _matches_directory_pattern(abs_file_path, pattern):
    """Check if an absolute file path matches a single directory glob pattern.

    Returns True if the path matches.
    """
    if not isinstance(pattern, str):
        return False

    if pattern.startswith("**/"):
        return match_leading_doublestar_pattern(abs_file_path, pattern)

    expanded_pattern = _resolve_pattern_path(pattern)

    if "**" in expanded_pattern:
        base_path = (
            expanded_pattern.replace("\\**", "").replace("/**", "").replace("**", "")
        )
        if "*" in base_path:
            current_path = abs_file_path
            while current_path and current_path != os.path.dirname(current_path):
                if _fnmatch_path(current_path, base_path):
                    return True
                current_path = os.path.dirname(current_path)
            return False
        else:
            return _startswith_path(abs_file_path, base_path)
    elif "*" in expanded_pattern:
        file_parent = os.path.dirname(abs_file_path)
        return _fnmatch_path(file_parent, expanded_pattern) or _startswith_path(
            file_parent, expanded_pattern.replace("\\*", "").replace("/*", "")
        )
    else:
        return (
            abs_file_path.startswith(expanded_pattern + os.sep)
            or abs_file_path == expanded_pattern
        )


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
            global_action = directory_rules_config.get("action", ActionMode.BLOCK)
            directory_rules = directory_rules_config.get("rules", [])
        else:
            # Old format: array of rules
            # Default action is "block" for backward compatibility
            global_action = ActionMode.BLOCK
            directory_rules = directory_rules_config

        # Backward compatibility: convert directory_exclusions to rules
        dir_exclusions = config.get("directory_exclusions", {})
        if is_feature_enabled(
            dir_exclusions.get("enabled"), datetime.now(timezone.utc), default=False
        ) and dir_exclusions.get("paths"):
            # Log deprecation warning once
            if not hasattr(_check_directory_rules, "_warned_deprecation"):
                logging.warning(
                    "directory_exclusions is deprecated - use directory_rules instead"
                )
                _check_directory_rules._warned_deprecation = True

            # Prepend exclusions as allow rules (so they have lower priority than explicit rules)
            backward_compat_rule = {"mode": "allow", "paths": dir_exclusions["paths"]}
            directory_rules = [backward_compat_rule] + directory_rules

        # Load exclusions (glob patterns that are always allowed)
        exclusions = []
        if isinstance(directory_rules_config, dict):
            exclusions = directory_rules_config.get("exclusions", [])
            if not isinstance(exclusions, list):
                exclusions = []

        if not directory_rules and not exclusions:
            # No rules or exclusions, but global_action still applies to .ai-read-deny markers
            return None, global_action, None

        # Convert file path to absolute path and resolve symlinks
        abs_file_path = os.path.realpath(os.path.expanduser(file_path))

        # Check exclusions first — these always allow access
        for excl_pattern in exclusions:
            try:
                if _matches_directory_pattern(abs_file_path, excl_pattern):
                    logging.debug(
                        f"Path {abs_file_path} matched exclusion: {excl_pattern}"
                    )
                    return "allow", global_action, excl_pattern
            except Exception as e:
                logging.warning(
                    f"Error processing exclusion pattern '{excl_pattern}': {e}"
                )
                continue

        # Evaluate rules in order, last match wins
        final_decision = None
        matched_pattern = None

        for rule in directory_rules:
            if not isinstance(rule, dict):
                logging.warning(f"Invalid directory rule (not a dict): {rule}")
                continue

            mode = rule.get("mode")
            if mode not in ["allow", "deny"]:
                logging.warning(
                    f"Invalid rule mode: {mode} (must be 'allow' or 'deny')"
                )
                continue

            paths = rule.get("paths", [])
            if not isinstance(paths, list):
                logging.warning(f"Invalid paths in rule (not a list): {paths}")
                continue

            # Check if file matches any pattern in this rule
            for pattern in paths:
                try:
                    if _matches_directory_pattern(abs_file_path, pattern):
                        final_decision = mode
                        matched_pattern = pattern
                        logging.debug(
                            f"Path {abs_file_path} matched rule: {mode} {pattern} (action={global_action})"
                        )
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
        rule_decision, rule_action, matched_pattern = (
            _check_directory_rules(abs_path, config) if config else (None, None, None)
        )

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
                logging.info(
                    f"Found .ai-read-deny at {denied_directory}, but directory rules allow access - allowing"
                )
                return (
                    False,
                    None,
                    None,
                    matched_pattern,
                )  # ALLOW - rule overrides marker
            else:
                # No allow rule to override - block, warn, or log-only
                # Check action
                if rule_action == ActionMode.WARN:
                    logging.warning(
                        f"Policy violation (warn mode): {file_path} - .ai-read-deny marker in {denied_directory} but allowed for audit"
                    )
                    _log_directory_blocking_violation(
                        file_path, denied_directory, is_excluded=False
                    )
                    warn_msg = "⚠️  Directory access policy violation (warn mode) - execution allowed"
                    return (
                        False,
                        None,
                        warn_msg,
                        matched_pattern,
                    )  # ALLOW - logged for audit, with warning
                elif rule_action == ActionMode.LOG_ONLY:
                    logging.warning(
                        f"Policy violation (log-only mode): {file_path} - .ai-read-deny marker in {denied_directory} but allowed for audit (silent)"
                    )
                    _log_directory_blocking_violation(
                        file_path, denied_directory, is_excluded=False
                    )
                    return (
                        False,
                        None,
                        None,
                        matched_pattern,
                    )  # ALLOW - logged for audit, NO warning
                else:
                    # Block access
                    logging.error(
                        f".ai-read-deny marker blocks access to {denied_directory}"
                    )
                    _log_directory_blocking_violation(
                        file_path, denied_directory, is_excluded=False
                    )
                    return True, denied_directory, None, matched_pattern  # BLOCK

        # No .ai-read-deny marker - check rule decision
        if rule_decision == "deny":
            # Check action
            rule_reason = f"denied by directory rule: {matched_pattern}"
            rule_suggestion = {
                "action": "update_directory_rules",
                "config_file": "ai-guardian.json",
                "warning": f"Directory rules deny access (matched pattern: {matched_pattern})",
            }
            if rule_action == ActionMode.WARN:
                logging.warning(
                    f"Policy violation (warn mode): {file_path} - denied by rules but allowed for audit"
                )
                _log_directory_blocking_violation(
                    file_path,
                    os.path.dirname(abs_path),
                    is_excluded=False,
                    reason=rule_reason,
                    suggestion=rule_suggestion,
                )
                warn_msg = "⚠️  Directory access policy violation (warn mode) - execution allowed"
                return (
                    False,
                    None,
                    warn_msg,
                    matched_pattern,
                )  # ALLOW - logged for audit, with warning
            elif rule_action == ActionMode.LOG_ONLY:
                logging.warning(
                    f"Policy violation (log-only mode): {file_path} - denied by rules but allowed for audit (silent)"
                )
                _log_directory_blocking_violation(
                    file_path,
                    os.path.dirname(abs_path),
                    is_excluded=False,
                    reason=rule_reason,
                    suggestion=rule_suggestion,
                )
                return (
                    False,
                    None,
                    None,
                    matched_pattern,
                )  # ALLOW - logged for audit, NO warning
            else:
                # Block access
                logging.error(f"Directory rules deny access to {abs_path}")
                _log_directory_blocking_violation(
                    file_path,
                    os.path.dirname(abs_path),
                    is_excluded=False,
                    reason=rule_reason,
                    suggestion=rule_suggestion,
                )
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
        logging.info(
            f"extract_tool_result: tool_name from hook_data.tool_name = {tool_name}"
        )
        if not tool_name and "tool_use" in hook_data:
            # Try tool_use.name format (Claude Code format)
            if isinstance(hook_data["tool_use"], dict):
                tool_name = hook_data["tool_use"].get("name")
                logging.info(
                    f"extract_tool_result: tool_name from tool_use.name = {tool_name}"
                )
        if not tool_name:
            tool_name = "unknown"
            logging.info("extract_tool_result: tool_name defaulted to 'unknown'")

        # Augment Code: normalize tool names
        if tool_name in _AUGMENT_TOOL_MAP:
            tool_name = _AUGMENT_TOOL_MAP[tool_name]

        if tool_name in STATE_MODIFY_TOOLS:
            logging.debug(
                f"Skipping PostToolUse scan for state-modifying tool: {tool_name}"
            )
            return None, tool_name

        output = None

        # Claude Code format: tool_response field
        if "tool_response" in hook_data:
            tool_response = hook_data["tool_response"]
            if isinstance(tool_response, dict):
                # Try common output field names
                output = (
                    tool_response.get("output")
                    or tool_response.get("content")
                    or tool_response.get("result")
                )

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


def _matches_ignore_files(file_path, ignore_files):
    """Check if file_path matches any pattern in ignore_files list."""
    if not ignore_files or not file_path:
        return False
    for pattern in ignore_files:
        if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(
            os.path.basename(file_path), pattern
        ):
            return True
    return False


def _should_skip_pii_scan(pii_config, tool_identifier=None, file_path=None):
    """Check if PII scan should be skipped based on ignore_tools and ignore_files config."""
    ignore_tools = pii_config.get("ignore_tools", [])
    if ignore_tools and tool_identifier:
        for pattern in ignore_tools:
            if fnmatch.fnmatch(tool_identifier, pattern):
                logging.info(
                    f"Skipping PII scan for ignored tool: {tool_identifier} (pattern: {pattern})"
                )
                return True

    if _matches_ignore_files(file_path, pii_config.get("ignore_files", [])):
        logging.info(f"Skipping PII scan for ignored file: {file_path}")
        return True


def _should_skip_context_poisoning(cp_config, tool_identifier=None, file_path=None):
    """Check if context poisoning scan should be skipped based on ignore_tools and ignore_files config."""
    ignore_tools = cp_config.get("ignore_tools", [])
    if ignore_tools and tool_identifier:
        for pattern in ignore_tools:
            if fnmatch.fnmatch(tool_identifier, pattern):
                logging.info(
                    f"Skipping context poisoning scan for ignored tool: {tool_identifier} (pattern: {pattern})"
                )
                return True

    if _matches_ignore_files(file_path, cp_config.get("ignore_files", [])):
        logging.info(f"Skipping context poisoning scan for ignored file: {file_path}")
        return True

    return False

    return False


def _build_directory_denied_message(file_path, denied_dir, matched_pattern):
    """Build a standardized directory access denied error message."""
    error_msg = "🛡️ Directory Access Denied\n\n"

    if matched_pattern:
        error_msg += "Protection: Directory Rule\n"
    else:
        error_msg += "Protection: .ai-read-deny Marker\n"

    display_path = file_path if len(file_path) <= 100 else "..." + file_path[-97:]
    error_msg += f"File: {display_path}\n"

    if denied_dir:
        display_dir = denied_dir if len(denied_dir) <= 100 else "..." + denied_dir[-97:]
        error_msg += f"Protected Directory: {display_dir}\n"

    if matched_pattern:
        display_pattern = (
            matched_pattern
            if len(matched_pattern) <= 100
            else matched_pattern[:97] + "..."
        )
        error_msg += f"Pattern: {display_pattern}\n"

    error_msg += "\nWhy blocked: "
    if matched_pattern:
        error_msg += "This file is blocked by a directory access rule.\n"
        error_msg += "Directory rules prevent AI access to specific paths.\n"
    else:
        error_msg += "This directory contains a .ai-read-deny marker file.\n"
        error_msg += "All subdirectories are blocked from AI access.\n"

    error_msg += "\nThis operation has been blocked for security.\n"
    error_msg += "DO NOT attempt to bypass this protection - it prevents unauthorized directory access.\n"

    error_msg += "\nRecommendation:\n"
    if matched_pattern:
        error_msg += "- Update directory_rules in ai-guardian.json to allow this path\n"
        error_msg += "- Move this file to an accessible location\n"
        error_msg += "- Verify this file should be accessible to AI agents\n"
    else:
        error_msg += f"- Remove the .ai-read-deny file from {denied_dir} (manually)\n"
        error_msg += "- Move this file to an accessible location\n"
        error_msg += (
            "- Add an allow rule in directory_rules config to override marker\n"
        )

    error_msg += f"\nConfig: {get_config_dir() / 'ai-guardian.json'}\n"
    error_msg += "Section: directory_rules\n"

    return error_msg


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
            is_denied, denied_dir, dir_warning, matched_pattern = (
                check_directory_denied(file_path)
            )
            if is_denied:
                error_msg = _build_directory_denied_message(
                    file_path, denied_dir, matched_pattern
                )
                return (
                    None,
                    os.path.basename(file_path),
                    file_path,
                    True,
                    error_msg,
                    None,
                )

            return (
                content,
                os.path.basename(file_path),
                file_path,
                False,
                None,
                dir_warning,
            )

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
        is_denied, denied_dir, dir_warning, matched_pattern = check_directory_denied(
            file_path
        )
        if is_denied:
            error_msg = _build_directory_denied_message(
                file_path, denied_dir, matched_pattern
            )
            return None, os.path.basename(file_path), file_path, True, error_msg, None

        # Read the file content
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return (
                content,
                os.path.basename(file_path),
                file_path,
                False,
                None,
                dir_warning,
            )
        except FileNotFoundError:
            logging.warning(f"File not found: {file_path}")
            return (
                None,
                os.path.basename(file_path),
                file_path,
                False,
                None,
                dir_warning,
            )
        except PermissionError:
            logging.warning(f"Permission denied reading file: {file_path}")
            return (
                None,
                os.path.basename(file_path),
                file_path,
                False,
                None,
                dir_warning,
            )
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return (
                None,
                os.path.basename(file_path),
                file_path,
                False,
                None,
                dir_warning,
            )

    except Exception as e:
        logging.error(f"Error extracting file from tool data: {e}")
        return None, "unknown_file", None, False, None, None


def _get_transcript_path(hook_data: dict) -> Optional[str]:
    """
    Extract transcript path from hook data across IDE types.

    Tries multiple field names for IDE-agnostic support:
    - Claude Code: transcript_path
    - Other IDEs may use transcriptPath, transcript, or conversation_path

    Args:
        hook_data: Parsed hook input JSON

    Returns:
        Absolute path to transcript file, or None if not available
    """
    for field in (
        "transcript_path",
        "transcriptPath",
        "transcript",
        "conversation_path",
    ):
        path = hook_data.get(field)
        if path and isinstance(path, str):
            return path
    return None


def _load_transcript_positions() -> Dict[str, int]:
    """Load transcript scanning byte-offset positions from state dir."""
    state_dir = get_state_dir()
    pos_file = state_dir / "transcript_positions.json"
    try:
        with open(pos_file, "r", encoding="utf-8") as f:
            positions = json.load(f)
        if isinstance(positions, dict):
            return positions
    except FileNotFoundError:
        pass  # intentionally silent — file may not exist yet
    except Exception as e:
        logging.debug(f"Failed to load transcript positions: {e}")
    return {}


def _save_transcript_positions(positions: Dict[str, int]) -> None:
    """Save transcript scanning byte-offset positions to state dir.

    Prunes entries for transcript files that no longer exist.
    """
    state_dir = get_state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    pos_file = state_dir / "transcript_positions.json"
    try:
        pruned = {
            k: v
            for k, v in positions.items()
            if k.startswith("opencode:") or os.path.exists(k)
        }
        with open(pos_file, "w", encoding="utf-8") as f:
            json.dump(pruned, f)
    except Exception as e:
        logging.debug(f"Failed to save transcript positions: {e}")


def _handle_session_end(hook_data, daemon_state, session_id, adapter):
    """Handle true session end (SessionEnd event) with cleanup.

    Performs best-effort cleanup actions:
    1. Advance transcript position to EOF
    2. Clean up hook contexts for this session
    3. Remove session from security injection tracking
    4. Log session summary

    All steps are fail-open: errors are logged but never raised.

    Returns:
        dict: Empty allow response (exit_code 0)
    """
    session_label = (
        (session_id[:16] + "...")
        if session_id and len(session_id) > 16
        else (session_id or "unknown")
    )
    adapter_name = adapter.name if adapter else "unknown"
    logging.info(f"Session ended for {session_label} (adapter: {adapter_name})")

    contexts_cleaned = 0

    try:
        _advance_transcript_position(hook_data)
    except Exception as e:
        logging.debug(
            f"Session end: transcript position advance failed (non-fatal): {e}"
        )

    try:
        from ai_guardian.hook_context import HookContextManager

        context_mgr = HookContextManager(
            session_id=session_id, daemon_state=daemon_state
        )
        contexts_cleaned = context_mgr.cleanup_session()
    except Exception as e:
        logging.debug(f"Session end: hook context cleanup failed (non-fatal): {e}")

    try:
        from ai_guardian.session_state import SessionStateManager, derive_session_key

        session_key = derive_session_key(hook_data)
        state_mgr = SessionStateManager(daemon_state=daemon_state)
        state_mgr.cleanup_session(session_key)
    except Exception as e:
        logging.debug(f"Session end: session state cleanup failed (non-fatal): {e}")

    logging.info(f"Session cleanup complete: {contexts_cleaned} contexts removed")

    return {"output": None, "exit_code": 0}


def _advance_transcript_position(hook_data: dict) -> None:
    """Advance transcript position to current file size after PostToolUse.

    Prevents stale warnings when the next session rescans unscanned tail bytes.
    Only advances entries that scan_transcript_incremental has already
    initialized — never creates new entries, so the first-scan skip logic
    in scan_transcript_incremental is preserved.

    Uses file locking (where available) for atomic read-modify-write to
    prevent concurrent sessions from clobbering each other's updates.

    Skips file-existence pruning to avoid discarding valid entries when
    the transcript is transiently unavailable (e.g. NFS).
    """
    transcript_path = _get_transcript_path(hook_data)
    if not transcript_path:
        return
    try:
        file_size = os.path.getsize(transcript_path)
    except OSError:
        return

    state_dir = get_state_dir()
    pos_file = state_dir / "transcript_positions.json"
    lock_file = state_dir / "transcript_positions.lock"

    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_file, "w") as lf:
            if _HAS_FCNTL:
                fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                positions = {}
                try:
                    with open(pos_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, dict):
                        positions = data
                except (FileNotFoundError, json.JSONDecodeError):
                    pass  # intentionally silent — file may not exist yet

                if transcript_path not in positions:
                    return

                old_pos = positions[transcript_path]
                if file_size > old_pos:
                    positions[transcript_path] = file_size
                    import tempfile as _tf

                    fd, tmp_path = _tf.mkstemp(
                        dir=str(state_dir), prefix=".transcript-pos-", suffix=".tmp"
                    )
                    closed = False
                    try:
                        os.write(fd, json.dumps(positions).encode("utf-8"))
                        os.close(fd)
                        closed = True
                        os.replace(tmp_path, str(pos_file))
                    except BaseException:
                        if not closed:
                            os.close(fd)
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                        raise
            finally:
                if _HAS_FCNTL:
                    fcntl.flock(lf, fcntl.LOCK_UN)
    except OSError as e:
        logging.debug(f"Failed to advance transcript position: {e}")


def _load_seen_findings() -> Dict[str, Dict[str, str]]:
    """Load seen transcript findings from state dir.

    Returns:
        Dict mapping transcript paths to dicts of {fingerprint: iso_timestamp}.
    """
    state_dir = get_state_dir()
    sf_file = state_dir / "transcript_seen_findings.json"
    try:
        with open(sf_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except FileNotFoundError:
        pass  # intentionally silent — file may not exist yet
    except Exception as e:
        logging.debug(f"Failed to load seen findings: {e}")
    return {}


def _save_seen_findings(seen: Dict[str, Dict[str, str]]) -> None:
    """Save seen transcript findings to state dir.

    Prunes entries for transcript files that no longer exist.
    """
    state_dir = get_state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    sf_file = state_dir / "transcript_seen_findings.json"
    try:
        pruned = {
            k: v
            for k, v in seen.items()
            if k.startswith("opencode:") or os.path.exists(k)
        }
        with open(sf_file, "w", encoding="utf-8") as f:
            json.dump(pruned, f)
    except Exception as e:
        logging.debug(f"Failed to save seen findings: {e}")


def _finding_fingerprint(finding_type: str, detail: str) -> str:
    # ai-guardian:begin-allow
    """Compute a short hash fingerprint for a transcript finding.

    Args:
        finding_type: Category such as "pii" or "secret"
        detail: Type-specific detail (e.g. "SSN:078-05-1120" or rule_id)

    Returns:
        First 16 hex chars of SHA-256 digest.
    """
    # ai-guardian:end-allow
    return hashlib.sha256(f"{finding_type}:{detail}".encode()).hexdigest()[:16]


def _extract_secret_type_from_error(error_msg: str) -> str:
    """Extract the secret type (rule_id) from a scanner error message.

    The error message contains a line like "Secret Type: aws-access-token".
    We extract just the rule_id for stable fingerprinting, since the full
    error message includes temp file paths that change every invocation.
    """
    match = re.search(r"Secret Type:\s*(.+)", error_msg)
    if match:
        return match.group(1).strip()
    return "unknown"


def _extract_text_from_transcript_line(line_data: dict) -> str:
    """Extract scannable text content from a transcript JSONL line.

    Defensively handles various JSONL formats from different IDEs.

    Args:
        line_data: Parsed JSON object from one line of the transcript

    Returns:
        Concatenated text content found in the line
    """
    texts = []

    # message.content (string or list of content blocks)
    message = line_data.get("message")
    if isinstance(message, dict):
        content = message.get("content", "")
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(block.get("text", ""))

    # Direct content field (string or list)
    content = line_data.get("content")
    if isinstance(content, str):
        texts.append(content)
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                text = block.get("text") or block.get("content", "")
                if text:
                    texts.append(text)

    # Direct text field
    text = line_data.get("text")
    if isinstance(text, str):
        texts.append(text)

    # Tool result / output fields
    for field in ("result", "output", "stdout"):
        val = line_data.get(field)
        if isinstance(val, str):
            texts.append(val)

    return "\n".join(t for t in texts if t)


def scan_transcript_incremental(
    transcript_path: str,
    secret_config: Optional[Dict] = None,
    pii_config: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    allowed_findings: Optional[set] = None,
) -> list:
    """
    Incrementally scan transcript file for secrets and PII.

    Reads only new bytes since the last recorded position. Extracts text
    content from JSONL lines and runs through available scanners.

    Prompt injection scanning is intentionally excluded — conversation
    history naturally contains patterns that trigger false positives.

    Args:
        transcript_path: Absolute path to the JSONL transcript file
        secret_config: Secret scanning config (for allowlist, ignore patterns)
        pii_config: PII scanning config
        hook_context: Optional dict with session_id for correlation
        allowed_findings: Optional set of fingerprints to skip (from ask dialog allows)

    Returns:
        List of warning message strings (empty if nothing found)
    """
    warnings = []

    if not os.path.exists(transcript_path):
        logging.debug(f"Transcript file does not exist: {transcript_path}")
        return warnings

    positions = _load_transcript_positions()

    try:
        file_size = os.path.getsize(transcript_path)
    except OSError as e:
        logging.debug(f"Cannot stat transcript file: {e}")
        return warnings

    if transcript_path not in positions:
        # First scan for this transcript: skip to current end.
        # Content up to this point was already scanned by PreToolUse/PostToolUse hooks.
        # Transcript scanning only needs to catch content from ! shell commands,
        # which will appear in bytes added AFTER this initial position.
        positions[transcript_path] = file_size
        _save_transcript_positions(positions)
        logging.debug(f"Transcript first seen, initialized position to {file_size}")
        return warnings

    last_pos = positions[transcript_path]

    # File truncated or rotated — skip to current end rather than rescanning.
    # The old content was already scanned; rescanning from 0 causes duplicate warnings.
    if file_size < last_pos:
        logging.debug("Transcript file truncated, advancing position to current size")
        positions[transcript_path] = file_size
        _save_transcript_positions(positions)
        return warnings

    # Nothing new to scan
    if file_size <= last_pos:
        return warnings

    try:
        with open(transcript_path, "rb") as f:
            f.seek(last_pos)
            new_bytes = f.read()
            new_pos = f.tell()
    except OSError as e:
        logging.debug(f"Cannot read transcript file: {e}")
        return warnings

    new_content = new_bytes.decode("utf-8", errors="replace")

    # Parse JSONL lines and extract text
    texts = []
    for line in new_content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            line_data = json.loads(line)
            if isinstance(line_data, dict):
                extracted = _extract_text_from_transcript_line(line_data)
                if extracted:
                    texts.append(extracted)
        except json.JSONDecodeError:
            continue

    combined_text = "\n".join(texts)

    if not combined_text:
        # Update position even if no text found (skip binary/empty lines)
        positions[transcript_path] = new_pos
        _save_transcript_positions(positions)
        return warnings

    warnings = _scan_transcript_text(
        combined_text,
        transcript_path,
        secret_config,
        pii_config,
        hook_context,
        allowed_findings=allowed_findings,
    )

    # Update position to actual bytes read
    positions[transcript_path] = new_pos
    _save_transcript_positions(positions)

    return warnings


def _scan_transcript_text(
    combined_text: str,
    transcript_key: str,
    secret_config: Optional[Dict] = None,
    pii_config: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    allowed_findings: Optional[set] = None,
) -> list:
    """Scan combined text for secrets and PII with deduplication.

    Shared by both JSONL and SQLite transcript scanning paths.

    Args:
        combined_text: Concatenated transcript text to scan.
        transcript_key: Key for dedup tracking (file path or ``opencode:<session_id>``).
        secret_config: Secret scanning config.
        pii_config: PII scanning config.
        hook_context: Optional context with session_id for correlation.
        allowed_findings: Optional set of fingerprints to skip (from ask dialog allows).

    Returns:
        List of warning message strings.
    """
    warnings = []

    seen_all = _load_seen_findings()
    seen = seen_all.get(transcript_key, {})
    now_iso = datetime.now(timezone.utc).isoformat()

    # --- Secret scanning ---
    if secret_config is None or is_feature_enabled(
        secret_config.get("enabled") if secret_config else None,
        datetime.now(timezone.utc),
        default=True,
    ):
        try:
            secret_allowlist = (
                secret_config.get("allowlist_patterns", []) if secret_config else []
            )
            has_secrets, secret_error = check_secrets_with_gitleaks(
                combined_text,
                "transcript",
                context={"ide_type": "transcript_scan", "hook_event": HookEvent.PROMPT},
                allowlist_patterns=secret_allowlist,
            )
            if has_secrets and secret_error:
                fp = _finding_fingerprint(
                    "secret", _extract_secret_type_from_error(secret_error)
                )
                if fp not in seen and fp not in (allowed_findings or ()):
                    warning_msg = (
                        f"\n{'='*70}\n"
                        f"🔍 SECRET DETECTED IN CONVERSATION TRANSCRIPT\n"
                        f"{'='*70}\n"
                        f"A secret was found in your conversation history\n"
                        f"(possibly from a ! shell command).\n"
                        f"The secret has already been sent to the AI model.\n"
                        f"Recommended actions:\n"
                        f"  1. Rotate the exposed credential immediately\n"
                        f"  2. Start a new session to limit further exposure\n"
                        f"  3. Review your shell history for other leaked secrets\n"
                        f"{'='*70}\n"
                    )
                    warnings.append(warning_msg)
                    _log_transcript_violation(
                        ViolationType.SECRET_IN_TRANSCRIPT,
                        transcript_key,
                        details={"reason": secret_error},
                        hook_context=hook_context,
                    )
                    seen[fp] = now_iso
        except Exception as e:
            logging.debug(f"Transcript secret scan error (fail-open): {e}")

    # --- PII scanning ---
    if pii_config and is_feature_enabled(
        pii_config.get("enabled"), datetime.now(timezone.utc), default=True
    ):
        try:
            has_pii, _, pii_redactions, _ = _scan_for_pii(combined_text, pii_config)
            if has_pii:
                new_redactions = []
                for r in pii_redactions:
                    pos = r.get("position", 0)
                    length = r.get("original_length", 0)
                    original_value = (
                        combined_text[pos : pos + length]
                        if length
                        else r.get("type", "")
                    )
                    fp = _finding_fingerprint("pii", f"{r['type']}:{original_value}")
                    if fp not in seen and fp not in (allowed_findings or ()):
                        new_redactions.append(r)
                        seen[fp] = now_iso

                if new_redactions:
                    pii_types = list(set(r["type"] for r in new_redactions))
                    warning_msg = (
                        f"\n{'='*70}\n"
                        f"🔍 PII DETECTED IN CONVERSATION TRANSCRIPT\n"
                        f"{'='*70}\n"
                        f"Found {len(new_redactions)} PII item(s): {', '.join(pii_types)}\n"
                        f"(possibly from a ! shell command).\n"
                        f"The PII has already been sent to the AI model.\n"
                        f"Recommended actions:\n"
                        f"  1. Assess the data exposure per your compliance policies\n"
                        f"  2. Start a new session to limit further exposure\n"
                        f"  3. Review your shell history for other leaked PII\n"
                        f"{'='*70}\n"
                    )
                    warnings.append(warning_msg)
                    _log_transcript_violation(
                        ViolationType.PII_IN_TRANSCRIPT,
                        transcript_key,
                        details={
                            "pii_types": pii_types,
                            "pii_count": len(new_redactions),
                        },
                        hook_context=hook_context,
                    )
        except Exception as e:
            logging.debug(f"Transcript PII scan error (fail-open): {e}")

    # Persist seen findings
    seen_all[transcript_key] = seen
    _save_seen_findings(seen_all)

    return warnings


def scan_opencode_transcript_incremental(
    db_path: str,
    session_id: str,
    secret_config: Optional[Dict] = None,
    pii_config: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    allowed_findings: Optional[set] = None,
) -> list:
    """Incrementally scan OpenCode session transcript via SQLite.

    Reads new message parts since the last recorded timestamp from
    OpenCode's SQLite database. Uses the same scanning logic as the
    JSONL transcript scanner.

    Args:
        db_path: Absolute path to opencode.db.
        session_id: OpenCode session ID.
        secret_config: Secret scanning config.
        pii_config: PII scanning config.
        hook_context: Optional context with session_id for correlation.
        allowed_findings: Optional set of fingerprints to skip (from ask dialog allows).

    Returns:
        List of warning message strings (empty if nothing found).
    """
    from ai_guardian.opencode_transcript import (
        get_opencode_latest_timestamp,
        read_opencode_transcript,
    )

    warnings = []
    pos_key = f"opencode:{session_id}"

    positions = _load_transcript_positions()

    if pos_key not in positions:
        # First scan: skip to current end (same as JSONL behaviour).
        latest_ts = get_opencode_latest_timestamp(db_path, session_id)
        positions[pos_key] = latest_ts
        _save_transcript_positions(positions)
        logging.debug(
            f"OpenCode transcript first seen, initialized position to {latest_ts}"
        )
        return warnings

    last_ts = positions[pos_key]
    combined_text, new_ts = read_opencode_transcript(db_path, session_id, last_ts)

    if not combined_text:
        return warnings

    warnings = _scan_transcript_text(
        combined_text,
        pos_key,
        secret_config,
        pii_config,
        hook_context,
        allowed_findings=allowed_findings,
    )

    # Advance cursor
    positions[pos_key] = new_ts
    _save_transcript_positions(positions)

    return warnings


def _log_transcript_violation(
    violation_type: str,
    transcript_path: str,
    details: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
):
    """Log a violation detected in the conversation transcript."""
    if not HAS_VIOLATION_LOGGER:
        return
    try:
        hctx = hook_context or {}
        blocked_info = {
            "transcript_path": transcript_path,
            "source": "transcript",
        }
        if details:
            blocked_info.update(details)

        violation_ctx = {
            "ide_type": "unknown",
            "hook_event": HookEvent.PROMPT,
            "project_path": get_project_dir(),
        }
        if hctx.get("session_id"):
            violation_ctx["session_id"] = hctx["session_id"]

        violation_logger = ViolationLogger()
        violation_logger.log_violation(
            violation_type=violation_type,
            blocked=blocked_info,
            context=violation_ctx,
            suggestion={
                "action": "review_and_remediate",
                "warning": "Sensitive content was detected in the conversation transcript. "
                "It may have been entered via a ! shell command. "
                "The content has already been sent to the AI model. "
                "Rotate any exposed credentials and start a new session.",
            },
            severity="high",
        )
    except Exception as e:
        logging.error(f"Failed to log transcript violation: {e}")


def _scan_for_pii(text, pii_config, file_path=None):
    """
    Scan text for PII using SecretRedactor with PII patterns.

    Args:
        text: Text to scan
        pii_config: PII config dict with enabled, pii_types, action
        file_path: Optional file path for inclusion in warning message

    Returns:
        tuple: (has_pii, redacted_text, redactions, warning_message)
    """
    try:
        from ai_guardian.secret_redactor import SecretRedactor

        # pii_only=True skips loading secret patterns, only loads PII patterns
        redactor = SecretRedactor(
            config={"enabled": True}, pii_config=pii_config, pii_only=True
        )
        result = redactor.redact(text)
        redactions = result.get("redactions", [])
        if redactions:
            # Group redactions by type, collecting line numbers
            type_lines = {}
            for r in redactions:
                rtype = r["type"]
                line_num = r.get("line_number")
                if rtype not in type_lines:
                    type_lines[rtype] = []
                if line_num is not None:
                    type_lines[rtype].append(line_num)

            # Build per-type display with line numbers
            display_items = []
            for rtype in sorted(type_lines.keys()):
                lines = sorted(set(type_lines[rtype]))
                if lines:
                    if len(lines) <= 3:
                        line_info = ", ".join(str(ln) for ln in lines)
                    else:
                        line_info = ", ".join(str(ln) for ln in lines[:3]) + ", ..."
                    display_items.append(f"  - {rtype} (line {line_info})")
                else:
                    display_items.append(f"  - {rtype}")

            file_info = ""
            if file_path:
                display_path = (
                    file_path if len(file_path) <= 100 else "..." + file_path[-97:]
                )
                file_info = f"File: {display_path}\n"

            warning = (
                f"\n{'='*70}\n"
                f"🔒 PII DETECTED\n"
                f"{'='*70}\n"
                + file_info
                + f"Found {len(redactions)} PII item(s):\n"
                + "\n".join(display_items[:10])
                + ("\n  - ..." if len(display_items) > 10 else "")
                + f"\n\nAction: {pii_config.get('action', 'block')}\n"
                + f"{'='*70}\n"
            )
            return True, result["redacted_text"], redactions, warning
        return False, text, [], None
    except Exception as e:
        logging.warning(f"PII scan error: {e}")
        on_error = _get_on_scan_error_action()
        if on_error == ActionMode.BLOCK:
            logging.error(f"PII scan failed (fail-closed, on_scan_error=block): {e}")
            return (
                True,
                text,
                [],
                f"PII scan failed (blocked by on_scan_error=block): {e}",
            )
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
        if (
            "Pattern: no permission rule" in error_message
            or "no permission rule" in error_message.lower()
        ):
            return "No permission rule configured"
        elif (
            "Pattern: not in allow list" in error_message
            or "not in allow list" in error_message.lower()
        ):
            return "Not in allow list"

        # Try to extract pattern from "Pattern: <value>" line
        match = re.search(r"Pattern:\s*([^\n]+)", error_message)
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
        match = re.search(r"matched deny pattern: ([^\n]+)", error_message)
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

    # Get the absolute path and resolve symlinks
    abs_path = os.path.realpath(file_path)

    # Check if file is in ai-guardian's tests directory
    # More strict check: must be in ai-guardian project root followed by tests/
    # Prevents false positives in unrelated projects containing "ai-guardian" + "tests"
    path_parts = abs_path.split(os.sep)

    # Find ai-guardian or ai_guardian directory in path
    ai_guardian_index = -1
    for i, part in enumerate(path_parts):
        if part in ("ai-guardian", "ai_guardian"):
            ai_guardian_index = i
            break

    if ai_guardian_index == -1:
        return False

    # Check if 'tests' appears IMMEDIATELY after ai-guardian directory
    # This ensures it's the ai-guardian project's tests/, not some other tests/
    if (
        ai_guardian_index + 1 < len(path_parts)
        and path_parts[ai_guardian_index + 1] == "tests"
    ):
        return True

    return False


def _annotation_hint(
    error_message: str,
    file_path: Optional[str] = None,
    annotations_config: Optional[Dict] = None,
) -> str:
    """Append annotation suppression hint to error messages for file content scans."""
    if not error_message or not file_path:
        return error_message

    from ai_guardian.annotations import (
        INLINE_MARKER,
        BLOCK_BEGIN_MARKER,
        BLOCK_END_MARKER,
        _build_alias_lists,
    )

    inline_allow_aliases, secret_aliases, block_begin_aliases, block_end_aliases = (
        _build_alias_lists(annotations_config)
    )

    # Build inline all-violation examples
    all_markers = [INLINE_MARKER] + inline_allow_aliases
    all_examples = "  or  ".join(f"# {m}" for m in all_markers)

    # Build inline secrets-only examples
    secret_examples = "  or  ".join(f"# {m}" for m in secret_aliases)

    # Build block examples
    begin_markers = [BLOCK_BEGIN_MARKER] + block_begin_aliases
    end_markers = [BLOCK_END_MARKER] + block_end_aliases
    block_example = f"# {begin_markers[0]} ... # {end_markers[0]}"

    lines = [
        "\n\n\U0001f4a1 To suppress this finding, add an inline annotation:",
        f"  Secrets + PII:    {all_examples}",
    ]
    if secret_aliases:
        lines.append(f"  Secrets only:     {secret_examples}")
    lines.append(f"  Multi-line block: {block_example}")

    return error_message + "\n".join(lines)


def _extract_context_snippet(
    text: str, line_number: int, max_chars: int = 200
) -> Optional[str]:
    """
    Extract a few lines of context around a detection position.

    The text should already be redacted (no raw PII/secrets).

    Args:
        text: Already-redacted text to extract snippet from
        line_number: 1-based line number of the detection
        max_chars: Maximum characters in the snippet

    Returns:
        Snippet string or None if inputs are invalid
    """
    if not text or not line_number or line_number < 1:
        return None

    lines = text.split("\n")
    idx = line_number - 1

    if idx >= len(lines):
        return None

    start = max(0, idx - 1)
    end = min(len(lines), idx + 2)
    snippet_lines = lines[start:end]

    snippet = "...".join(line.strip() for line in snippet_lines if line.strip())
    if not snippet:
        return None

    if len(snippet) > max_chars:
        snippet = snippet[: max_chars - 3] + "..."

    return snippet


def _log_directory_blocking_violation(
    file_path: str,
    denied_directory: str,
    is_excluded: bool = False,
    reason: str = None,
    suggestion: dict = None,
    hook_context: Optional[Dict] = None,
    violation_logger=None,
):
    """
    Log a directory blocking violation.

    Args:
        file_path: Path to the file that was blocked
        denied_directory: Directory containing .ai-read-deny marker or matched by rules
        is_excluded: Whether the path was in an excluded directory (but .ai-read-deny still blocked it)
        reason: Why the path was blocked (defaults to ".ai-read-deny marker found")
        suggestion: Remediation suggestion dict (defaults to marker removal suggestion)
        hook_context: Optional dict with tool_use_id, session_id for correlation
    """
    if not HAS_VIOLATION_LOGGER:
        return

    try:
        hctx = hook_context or {}
        violation_logger = violation_logger or ViolationLogger()

        context = {"project_path": get_project_dir(), "path_in_exclusion": is_excluded}

        if is_excluded:
            context["note"] = (
                "Directory exclusions can override .ai-read-deny markers (path was excluded but deny marker existed)"
            )

        if hctx.get("tool_use_id"):
            context["tool_use_id"] = hctx["tool_use_id"]
        if hctx.get("session_id"):
            context["session_id"] = hctx["session_id"]

        if reason is None:
            reason = ".ai-read-deny marker found"

        if suggestion is None:
            suggestion = {
                "action": "remove_deny_marker",
                "file_path": os.path.join(denied_directory, ".ai-read-deny"),
                "warning": "This directory contains sensitive files",
            }

        violation_logger.log_violation(
            violation_type=ViolationType.DIRECTORY_BLOCKING,
            blocked={
                "file_path": file_path,
                "denied_directory": denied_directory,
                "reason": reason,
                "exclusion_overridden": is_excluded,
            },
            context=context,
            suggestion=suggestion,
            severity="warning",
        )
    except Exception as e:
        logger.error(f"Failed to log directory blocking violation: {e}")


def _build_violation_context(context, hook_context):
    """Build standard violation context dict from context and hook_context."""
    ctx = context or {}
    hctx = hook_context or {}
    violation_ctx = {
        "ide_type": ctx.get("ide_type", "unknown"),
        "hook_event": ctx.get("hook_event", "unknown"),
        "project_path": get_project_dir(),
    }
    if hctx.get("tool_use_id"):
        violation_ctx["tool_use_id"] = hctx["tool_use_id"]
    if hctx.get("session_id"):
        violation_ctx["session_id"] = hctx["session_id"]
    return violation_ctx


def _enrich_blocked_from_details(blocked_info, details):
    """Add line_number, end_line, column, total_findings, validation from scan details."""
    if details.get("line_number"):
        blocked_info["line_number"] = details["line_number"]
        if details.get("end_line") and details["end_line"] != details["line_number"]:
            blocked_info["end_line"] = details["end_line"]
    if details.get("start_column") is not None:
        blocked_info["start_column"] = details["start_column"]
    if details.get("end_column") is not None:
        blocked_info["end_column"] = details["end_column"]
    if details.get("total_findings"):
        blocked_info["total_findings"] = details["total_findings"]
    if details.get("findings"):
        blocked_info["findings"] = details["findings"]
    if details.get("validation"):
        blocked_info["validation"] = details["validation"]


def _log_secret_detection_violation(
    filename: str,
    context: Optional[Dict] = None,
    secret_details: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    violation_logger=None,
):
    """
    Log a secret detection violation.

    Args:
        filename: Name of the file/prompt where secret was detected
        context: Optional context dict with ide_type, hook_event, etc.
        secret_details: Optional dict with Gitleaks finding details (rule_id, line_number, etc.)
        hook_context: Optional dict with tool_use_id, session_id for correlation
    """
    if not HAS_VIOLATION_LOGGER:
        return

    try:
        details = secret_details or {}
        engine_name = details.get("engine", "Gitleaks")
        blocked_info = {
            "file_path": filename if filename != "user_prompt" else None,
            "source": "prompt" if filename == "user_prompt" else "file",
            "secret_type": details.get("rule_id", "Unknown"),
            "reason": f"{engine_name} detected sensitive information",
        }
        _enrich_blocked_from_details(blocked_info, details)

        violation_logger = violation_logger or ViolationLogger()
        if details.get("end_line") and details["end_line"] != details.get(
            "line_number"
        ):
            line_num = details.get("line_number")
            end_line = details["end_line"]
            false_positive_msg = (
                f"Add '# ai-guardian:allow' at the end of line {line_num}, "
                f"or wrap lines {line_num}-{end_line} with "
                f"ai-guardian:begin-allow / ai-guardian:end-allow"
            )
        else:
            false_positive_msg = (
                "Add '# gitleaks:allow' or '# ai-guardian:allow' at the end of the line"
            )

        violation_logger.log_violation(
            violation_type=ViolationType.SECRET_DETECTED,
            blocked=blocked_info,
            context=_build_violation_context(context, hook_context),
            suggestion={
                "action": "review_and_remove_secret",
                "warning": "Secrets should never be committed to code or shared with AI",
                "false_positive": false_positive_msg,
            },
            severity="critical",
        )
    except Exception as e:
        logger.critical(f"Failed to log secret detection violation: {e}")


# Category → (ViolationType, reason template, severity)
_CATEGORY_VIOLATION_MAP = {
    "pii": (ViolationType.PII_DETECTED, "PII detected", "high"),
    "prompt_injection": (
        ViolationType.PROMPT_INJECTION,
        "Prompt injection detected",
        "high",
    ),
    "unicode": (ViolationType.PROMPT_INJECTION, "Unicode attack detected", "high"),
    "config_exfil": (
        ViolationType.CONFIG_FILE_EXFIL,
        "Config exfiltration pattern detected",
        "high",
    ),
    "ssrf": (ViolationType.SSRF_BLOCKED, "SSRF pattern detected", "high"),
}


def _log_finding_violation(
    filename: str,
    context: Optional[Dict] = None,
    secret_details: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    violation_logger=None,
):
    """Route a scanner finding to the correct violation type based on category.

    Checks the 'category' field in secret_details to determine the violation
    type. Falls back to _log_secret_detection_violation for secrets or unknown
    categories.
    """
    details = secret_details or {}
    category = details.get("category")

    if category is None or category == "secrets":
        _log_secret_detection_violation(
            filename, context, secret_details, hook_context, violation_logger
        )
        return

    mapping = _CATEGORY_VIOLATION_MAP.get(category)
    if mapping is None:
        _log_secret_detection_violation(
            filename, context, secret_details, hook_context, violation_logger
        )
        return

    if not HAS_VIOLATION_LOGGER:
        return

    try:
        vtype, reason_label, severity = mapping
        engine_name = details.get("engine", "toml-patterns")
        rule_id = details.get("rule_id", "Unknown")

        blocked_info = {
            "file_path": filename if filename != "user_prompt" else None,
            "source": "prompt" if filename == "user_prompt" else "file",
            "secret_type": rule_id,
            "reason": f"{engine_name}: {reason_label} ({rule_id})",
        }
        _enrich_blocked_from_details(blocked_info, details)

        violation_logger = violation_logger or ViolationLogger()
        if details.get("end_line") and details["end_line"] != details.get(
            "line_number"
        ):
            line_num = details.get("line_number")
            end_line = details["end_line"]
            false_positive_msg = (
                f"Add '# ai-guardian:allow' at the end of line {line_num}, "
                f"or wrap lines {line_num}-{end_line} with "
                f"ai-guardian:begin-allow / ai-guardian:end-allow"
            )
        else:
            false_positive_msg = "Add '# ai-guardian:allow' at the end of the line"

        violation_logger.log_violation(
            violation_type=vtype,
            blocked=blocked_info,
            context=_build_violation_context(context, hook_context),
            suggestion={
                "action": "review_finding",
                "false_positive": false_positive_msg,
            },
            severity=severity,
        )
    except Exception as e:
        logger.error(f"Failed to log finding violation: {e}")


def _get_directory_action_from_config():
    """Return the directory_rules.action string from config (defaults to 'block')."""
    try:
        if HAS_TOOL_POLICY:
            policy_checker = ToolPolicyChecker()
            dr = policy_checker.config.get("directory_rules", {})
            if isinstance(dr, dict):
                return dr.get("action", ActionMode.BLOCK)
    except Exception:
        pass  # intentionally silent — best-effort operation
    return ActionMode.BLOCK


def _build_permission_matched_text(tool_name, tool_input, tool_identifier):
    """Build a display string for a permission violation's matched text.

    Returns "matcher:value" format for the pattern editor pre-fill.
    """
    if not tool_input:
        return tool_identifier or tool_name or ""
    if tool_name == "Skill":
        skill_name = tool_input.get("skill", "")
        if skill_name:
            return f"Skill:{skill_name}"
    elif tool_name == "Bash":
        command = tool_input.get("command", "")
        if command:
            return f"Bash:{command[:200]}"
    elif tool_name in ("Read", "Write", "Edit"):
        fp = tool_input.get("file_path") or tool_input.get("path", "")
        if fp:
            return f"{tool_name}:{fp}"
    return tool_identifier or tool_name or ""


def _handle_ask_mode(
    action_str,
    violation_type,
    matched_text,
    config_section,
    error_msg,
    file_path=None,
    line_number=None,
    start_column=None,
    matched_pattern="",
    latency_timer=None,
    hook_context=None,
    finding_index=None,
    total_findings=None,
):
    """Handle 'ask' action mode by showing an interactive dialog.

    Returns an AskResult if action is 'ask', or None if action is not 'ask'.
    When the dialog is shown, also writes allowlist patterns if the user
    chooses "Allow Always".
    """
    primary_action, fallback_action = parse_ask_action(action_str)
    if primary_action != ActionMode.ASK:
        return None

    try:
        from ai_guardian.tui.ask_dialog import (
            show_ask_dialog,
            AskViolationInfo,
            AskDecision,
            format_hook_label,
        )

        display_text = matched_text or ""
        display_line = line_number

        if error_msg and not matched_text:
            display_text = ""

        if not display_text and file_path and error_msg:
            try:
                import re as _re

                loc_match = _re.search(r"Location:\s*[^:]+:(\d+)", error_msg)
                if loc_match:
                    display_line = int(loc_match.group(1))
            except (ValueError, AttributeError):
                pass  # intentionally silent — best-effort operation

        if not display_text and file_path and display_line:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        if i == display_line:
                            display_text = line.rstrip("\n\r")
                            break
            except (OSError, UnicodeDecodeError):
                pass  # intentionally silent — best-effort operation

        if not display_text:
            try:
                import re as _re

                type_match = _re.search(r"Secret Type:\s*(.+)", error_msg or "")
                if type_match:
                    display_text = type_match.group(1).strip()
            except (AttributeError, IndexError):
                pass  # intentionally silent — best-effort operation

        summary_lines = []
        if error_msg:
            for prefix in ("Secret Type:", "Scanner:"):
                import re as _re

                m = _re.search(rf"{prefix}\s*(.+)", error_msg)
                if m:
                    summary_lines.append(f"{prefix} {m.group(1).strip()}")
        summary = (
            " | ".join(summary_lines)
            if summary_lines
            else (error_msg[:200] if error_msg else str(violation_type))
        )

        hctx = hook_context or {}
        violation_info = AskViolationInfo(
            violation_type=violation_type,
            summary=summary,
            matched_text=display_text,
            config_section=config_section,
            error_message=error_msg or "",
            matched_pattern=matched_pattern,
            file_path=file_path,
            line_number=display_line,
            start_column=start_column,
            project_path=hctx.get("project_path") or get_project_dir(),
            session_id=hctx.get("session_id"),
            tool_name=hctx.get("tool_name"),
            hook_event=format_hook_label(hctx.get("hook_event"), hctx.get("tool_name")),
            finding_index=finding_index,
            total_findings=total_findings,
        )

        _dialog_t0 = time.perf_counter()
        result = show_ask_dialog(violation_info, fallback_action=fallback_action)
        _dialog_elapsed_ms = (time.perf_counter() - _dialog_t0) * 1000
        result.dialog_wait_ms = _dialog_elapsed_ms
        if latency_timer is not None:
            latency_timer.add_ask_wait(_dialog_elapsed_ms)

        if result.decision == AskDecision.ALLOW_ALWAYS and result.allowlist_pattern:
            if not getattr(result, "config_saved", False):
                from pathlib import Path as _Path
                from ai_guardian.config_writer import save_ask_pattern

                cp = (
                    _Path(result.config_path)
                    if getattr(result, "config_path", None)
                    else None
                )
                save_ask_pattern(
                    config_section, result.allowlist_pattern, config_path=cp
                )
            from ai_guardian.config_loaders import _clear_config_cache

            _clear_config_cache(project_key=hctx.get("project_path") or os.getcwd())

        if result.decision == AskDecision.IGNORE_FILE and result.ignore_path:
            if not getattr(result, "config_saved", False):
                from ai_guardian.tui.ask_dialog import _save_ignore_path

                _save_ignore_path(result.ignore_path, result.ignore_scanner_types)
            from ai_guardian.config_loaders import _clear_config_cache

            _clear_config_cache(project_key=hctx.get("project_path") or os.getcwd())

        return result

    except Exception as e:
        logging.warning(f"Ask dialog error, falling back to {fallback_action}: {e}")
        from ai_guardian.tui.ask_dialog import (
            AskResult,
            AskDecision,
            _map_fallback_to_decision,
        )

        return AskResult(decision=_map_fallback_to_decision(fallback_action))


def _handle_ask_mode_multi(
    action_str,
    violation_type,
    findings,
    config_section,
    error_msg,
    file_path=None,
    matched_pattern="",
    latency_timer=None,
    hook_context=None,
):
    """Handle 'ask' action mode for multiple findings.

    Loops through findings sequentially, calling _handle_ask_mode for each.
    BLOCK/BLOCK_ALL on any finding stops the loop immediately.
    Returns the final AskResult (BLOCK if any blocked, ALLOW_ONCE if all allowed).
    Also returns the per-finding results list as result.per_finding_results.
    """
    from ai_guardian.tui.ask_dialog import AskResult, AskDecision
    from ai_guardian.constants import parse_ask_action, ActionMode

    primary_action, _ = parse_ask_action(action_str)
    if primary_action != ActionMode.ASK:
        return None

    # Deduplicate findings by matched_text — the same secret value can appear
    # in both the user message scan and the transcript scan for UserPromptSubmit,
    # or be detected by multiple scanner engines, producing duplicate dialogs.
    if findings and len(findings) > 1:
        seen_values: set = set()
        deduped = []
        for f in findings:
            key = (f.get("matched_text") or "").strip()
            if key not in seen_values:
                seen_values.add(key)
                deduped.append(f)
        findings = deduped

    if not findings or len(findings) <= 1:
        single_finding = findings[0] if findings else {}
        return _handle_ask_mode(
            action_str,
            violation_type,
            matched_text=single_finding.get("matched_text", ""),
            config_section=config_section,
            error_msg=single_finding.get("error_message", error_msg),
            file_path=file_path,
            line_number=single_finding.get("line_number"),
            start_column=single_finding.get("start_column"),
            matched_pattern=single_finding.get("matched_pattern", matched_pattern),
            latency_timer=latency_timer,
            hook_context=hook_context,
        )

    per_finding_results = []
    total = len(findings)
    total_dialog_ms = 0.0

    for idx, finding in enumerate(findings):
        result = _handle_ask_mode(
            action_str,
            violation_type,
            matched_text=finding.get("matched_text", ""),
            config_section=config_section,
            error_msg=finding.get("error_message", error_msg),
            file_path=file_path,
            line_number=finding.get("line_number"),
            start_column=finding.get("start_column"),
            matched_pattern=finding.get("matched_pattern", matched_pattern),
            latency_timer=latency_timer,
            hook_context=hook_context,
            finding_index=idx,
            total_findings=total,
        )

        if result is None:
            return None

        per_finding_results.append(result)
        total_dialog_ms += result.dialog_wait_ms

        if result.decision in (AskDecision.BLOCK, AskDecision.BLOCK_ALL):
            aggregate = AskResult(decision=AskDecision.BLOCK)
            aggregate.dialog_wait_ms = total_dialog_ms
            aggregate.per_finding_results = per_finding_results
            return aggregate

        if result.decision == AskDecision.IGNORE_FILE:
            for skip_finding in findings[idx + 1 :]:
                skipped = AskResult(decision=AskDecision.IGNORE_FILE)
                skipped.dialog_wait_ms = 0.0
                per_finding_results.append(skipped)
            aggregate = AskResult(decision=AskDecision.ALLOW_ONCE)
            aggregate.dialog_wait_ms = total_dialog_ms
            aggregate.per_finding_results = per_finding_results
            return aggregate

    aggregate = AskResult(decision=AskDecision.ALLOW_ONCE)
    aggregate.dialog_wait_ms = total_dialog_ms
    aggregate.per_finding_results = per_finding_results
    return aggregate


def _handle_ask_mode_auto(
    action_str,
    violation_type,
    config_section,
    error_msg,
    file_path=None,
    matched_text=None,
    line_number=None,
    start_column=None,
    matched_pattern="",
    latency_timer=None,
    hook_context=None,
    findings=None,
):
    """Route to multi or single ask dialog based on findings count."""
    if findings and len(findings) > 1:
        return _handle_ask_mode_multi(
            action_str,
            violation_type,
            findings,
            config_section,
            error_msg,
            file_path=file_path,
            matched_pattern=matched_pattern,
            latency_timer=latency_timer,
            hook_context=hook_context,
        )
    if findings and len(findings) == 1:
        f = findings[0]
        return _handle_ask_mode(
            action_str,
            violation_type,
            matched_text=f.get("matched_text", ""),
            config_section=config_section,
            error_msg=f.get("error_message", error_msg),
            file_path=file_path,
            line_number=f.get("line_number"),
            start_column=f.get("start_column"),
            matched_pattern=f.get("matched_pattern", matched_pattern),
            latency_timer=latency_timer,
            hook_context=hook_context,
        )
    return _handle_ask_mode(
        action_str,
        violation_type,
        matched_text=matched_text or "",
        config_section=config_section,
        error_msg=error_msg,
        file_path=file_path,
        line_number=line_number,
        start_column=start_column,
        matched_pattern=matched_pattern,
        latency_timer=latency_timer,
        hook_context=hook_context,
    )


_ASK_VIOLATION_LABELS = {
    ViolationType.SECRET_DETECTED: "Secret detection",
    ViolationType.PII_DETECTED: "PII detection",
    ViolationType.TOOL_PERMISSION: "Permission rule",
    ViolationType.DIRECTORY_BLOCKING: "Directory access",
    ViolationType.PROMPT_INJECTION: "Prompt injection",
    ViolationType.CONTEXT_POISONING: "Context poisoning",
    ViolationType.SUPPLY_CHAIN: "Supply chain",
    ViolationType.CODE_SECURITY: "Code security",
    ViolationType.CONFIG_FILE_EXFIL: "Config file scanning",
    ViolationType.SSRF_BLOCKED: "SSRF protection",
    ViolationType.OFFENSIVE_LANGUAGE: "Offensive language",
    ViolationType.CANARY_DETECTED: "Canary token",
    ViolationType.EXFIL_DETECTION: "Exfil detection",
}


def _format_ask_info_message(violation_type, decision, detail=""):
    """Format an informational message for an ask-mode allow decision."""
    from ai_guardian.tui.ask_dialog import AskDecision

    label = _ASK_VIOLATION_LABELS.get(violation_type, str(violation_type))
    if decision == AskDecision.ALLOW_ALWAYS:
        msg = f"ℹ️  {label}: pattern added to allowlist (always allowed)"
    elif decision == AskDecision.SUPPRESS_IN_SOURCE:
        msg = f"ℹ️  {label}: suppressed in source (annotation added)"
    elif decision == AskDecision.IGNORE_FILE:
        msg = f"ℹ️  {label}: file added to .aiguardignore.toml"
    else:
        msg = f"ℹ️  {label}: allowed by user (this time only)"
    if detail:
        msg += f": {detail}"
    return msg


def _log_ask_decision(
    violation_type,
    decision,
    matched_text="",
    error_msg="",
    file_path=None,
    line_number=None,
    dialog_wait_ms=0.0,
    daemon_state=None,
    session_id=None,
    finding_fingerprints=None,
    invocation_allowed_findings=None,
):
    """Log an ask-mode decision (allow or block) to violations.jsonl.

    When an allow decision is made and invocation_allowed_findings is provided,
    records finding fingerprints in that set for transcript scanner dedup within
    the current hook invocation only (#1364, #1439).
    """
    if not HAS_VIOLATION_LOGGER:
        return
    try:
        from ai_guardian.tui.ask_dialog import AskDecision

        vlogger = ViolationLogger()
        blocked_info = {
            "description": (error_msg[:200] if error_msg else str(violation_type)),
            "matched_text": matched_text or "",
        }
        if file_path:
            blocked_info["file_path"] = file_path
        if line_number:
            blocked_info["line_number"] = line_number
        if decision == AskDecision.BLOCK:
            decision_str = "block"
            action_taken = "blocked"
        elif decision == AskDecision.BLOCK_ALL:
            decision_str = "block_all"
            action_taken = "blocked"
        elif decision == AskDecision.ALLOW_ALWAYS:
            decision_str = "allow_always"
            action_taken = "allowed"
        elif decision == AskDecision.SUPPRESS_IN_SOURCE:
            decision_str = "suppress_in_source"
            action_taken = "allowed"
        elif decision == AskDecision.IGNORE_FILE:
            decision_str = "ignore_file"
            action_taken = "allowed"
        else:
            decision_str = "allow_once"
            action_taken = "allowed"
        ctx = {"ask_decision": decision_str, "action_taken": action_taken}
        if dialog_wait_ms > 0:
            ctx["dialog_wait_ms"] = round(dialog_wait_ms, 1)
        vlogger.log_violation(
            violation_type=violation_type,
            blocked=blocked_info,
            context=ctx,
            severity="info",
        )

        # Record allowed findings for transcript scanner dedup within this invocation (#1364, #1439).
        # Uses invocation_allowed_findings (local set) so Allow Once does not persist to next invocation.
        if action_taken == "allowed" and invocation_allowed_findings is not None:
            _record_allowed_for_transcript(
                invocation_allowed_findings,
                violation_type,
                error_msg,
                matched_text,
                finding_fingerprints,
            )
    except Exception as e:
        logging.error(f"Failed to log ask decision: {e}")


def _record_allowed_for_transcript(
    result_set,
    violation_type,
    error_msg,
    matched_text,
    finding_fingerprints=None,
):
    """Record allowed finding fingerprints into result_set for transcript dedup.

    Uses pre-computed fingerprints if provided, otherwise auto-computes
    from violation_type and error_msg/matched_text.
    result_set is a plain set() scoped to the current hook invocation (#1439).
    """
    try:
        if finding_fingerprints:
            for fp in finding_fingerprints:
                result_set.add(fp)
            return

        if violation_type in (
            ViolationType.SECRET_DETECTED,
            ViolationType.SECRET_IN_TRANSCRIPT,
        ):
            rule_id = _extract_secret_type_from_error(error_msg)
            if rule_id and rule_id != "unknown":
                fp = _finding_fingerprint("secret", rule_id)
                result_set.add(fp)
    except Exception as e:
        logging.debug(f"Failed to record allowed finding: {e}")


def _compute_pii_transcript_fingerprints(pii_redactions, content):
    """Compute transcript-compatible fingerprints from PII redactions.

    Mirrors the fingerprint logic in _scan_transcript_text() so the
    transcript scanner recognizes allowed PII findings.
    """
    fps = []
    for r in pii_redactions or []:
        pos = r.get("position", 0)
        length = r.get("original_length", 0)
        original_value = (
            content[pos : pos + length] if length and content else r.get("type", "")
        )
        fp = _finding_fingerprint("pii", f"{r['type']}:{original_value}")
        fps.append(fp)
    return fps


def _log_prompt_injection_violation(
    filename: str,
    context: Optional[Dict] = None,
    attack_type: str = "injection",
    hook_context: Optional[Dict] = None,
    matched_pattern: Optional[str] = None,
    matched_text: Optional[str] = None,
    confidence: Optional[float] = None,
    line_number: Optional[int] = None,
    start_column: Optional[int] = None,
    end_column: Optional[int] = None,
    violation_logger=None,
):
    """
    Log a prompt injection or jailbreak violation.

    Args:
        filename: Name of the file/prompt where injection was detected
        context: Optional context dict with ide_type, hook_event, etc.
        attack_type: Type of attack - "injection" or "jailbreak"
        hook_context: Optional dict with tool_use_id, session_id for correlation
        matched_pattern: The regex or pattern name that matched
        matched_text: The text that triggered detection
        line_number: 1-based line number where the match was found
        start_column: 0-based start column within the line
        end_column: 0-based end column within the line
        confidence: Actual confidence score from the detector
    """
    if not HAS_VIOLATION_LOGGER:
        return

    try:
        ctx = context or {}
        vtype = (
            ViolationType.JAILBREAK_DETECTED
            if attack_type == "jailbreak"
            else ViolationType.PROMPT_INJECTION
        )
        reason = (
            "Jailbreak attempt detected"
            if attack_type == "jailbreak"
            else "Prompt injection pattern detected"
        )
        full_path = ctx.get("file_path")
        if not full_path and filename != "user_prompt":
            full_path = filename
        blocked_entry = {
            "file_path": full_path,
            "line_number": line_number,
            "source": "prompt" if filename == "user_prompt" else "file",
            "pattern": matched_pattern or "Unknown",
            "confidence": confidence if confidence is not None else 0.0,
            "method": "heuristic",
            "reason": reason,
        }
        if start_column is not None:
            blocked_entry["start_column"] = start_column
        if end_column is not None:
            blocked_entry["end_column"] = end_column
        if matched_text:
            blocked_entry["matched_text"] = matched_text[:100]
        violation_logger = violation_logger or ViolationLogger()
        violation_logger.log_violation(
            violation_type=vtype,
            blocked=blocked_entry,
            context=_build_violation_context(context, hook_context),
            suggestion={
                "action": "add_allowlist_pattern",
                "note": "If this is legitimate (e.g., documentation), add to allowlist in ai-guardian.json",
            },
            severity="high",
        )
    except Exception as e:
        logger.error(f"Failed to log prompt injection violation: {e}")


def _log_context_poisoning_violation(
    filename: str,
    context: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    matched_pattern: Optional[str] = None,
    matched_text: Optional[str] = None,
    confidence: Optional[float] = None,
    line_number: Optional[int] = None,
    start_column: Optional[int] = None,
    end_column: Optional[int] = None,
    violation_logger=None,
):
    """Log a context poisoning violation."""
    if not HAS_VIOLATION_LOGGER:
        return

    try:
        ctx = context or {}
        blocked_entry = {
            "file_path": ctx.get("file_path"),
            "line_number": line_number,
            "source": "prompt",
            "pattern": matched_pattern or "Unknown",
            "confidence": confidence if confidence is not None else 0.0,
            "method": "heuristic",
            "reason": "Context poisoning attempt detected",
        }
        if start_column is not None:
            blocked_entry["start_column"] = start_column
        if end_column is not None:
            blocked_entry["end_column"] = end_column
        if matched_text:
            blocked_entry["matched_text"] = matched_text[:100]
        violation_logger = violation_logger or ViolationLogger()
        violation_logger.log_violation(
            violation_type=ViolationType.CONTEXT_POISONING,
            blocked=blocked_entry,
            context=_build_violation_context(context, hook_context),
            suggestion={
                "action": "add_allowlist_pattern",
                "note": "If this is a legitimate persistent instruction, add to context_poisoning.allowlist_patterns in ai-guardian.json",
            },
            severity="medium",
        )
    except Exception as e:
        logger.error(f"Failed to log context poisoning violation: {e}")


def _log_supply_chain_violation(
    filename: str,
    context: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    matched_pattern: Optional[str] = None,
    matched_text: Optional[str] = None,
    category: Optional[str] = None,
    line_number: Optional[int] = None,
    start_column: Optional[int] = None,
    end_column: Optional[int] = None,
    violation_logger=None,
):
    """Log a supply chain threat violation."""
    if not HAS_VIOLATION_LOGGER:
        return

    try:
        ctx = context or {}
        blocked_entry = {
            "file_path": ctx.get("file_path"),
            "line_number": line_number,
            "source": "agent_config",
            "pattern": matched_pattern or "Unknown",
            "category": category or "unknown",
            "reason": "Supply chain threat detected in agent configuration",
        }
        if start_column is not None:
            blocked_entry["start_column"] = start_column
        if end_column is not None:
            blocked_entry["end_column"] = end_column
        if matched_text:
            blocked_entry["matched_text"] = matched_text[:100]
        violation_logger = violation_logger or ViolationLogger()
        violation_logger.log_violation(
            violation_type=ViolationType.SUPPLY_CHAIN,
            blocked=blocked_entry,
            context=_build_violation_context(context, hook_context),
            suggestion={
                "action": "add_allowlist_path",
                "note": "If this is a trusted config file, add to supply_chain.allowlist_paths in ai-guardian.json",
            },
            severity="high",
        )
    except Exception as e:
        logger.error(f"Failed to log supply chain violation: {e}")


def _log_exfil_detection_violation(
    command: str,
    context: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    matched_pattern: Optional[str] = None,
    matched_text: Optional[str] = None,
    category: Optional[str] = None,
    line_number: Optional[int] = None,
    start_column: Optional[int] = None,
    end_column: Optional[int] = None,
    violation_logger=None,
):
    """Log a credential exfiltration detection violation."""
    if not HAS_VIOLATION_LOGGER:
        return

    try:
        blocked_entry = {
            "command": command[:500],
            "line_number": line_number,
            "source": "bash_command",
            "pattern": matched_pattern or "Unknown",
            "category": category or "unknown",
            "reason": "Credential exfiltration behavior detected in bash command",
        }
        if start_column is not None:
            blocked_entry["start_column"] = start_column
        if end_column is not None:
            blocked_entry["end_column"] = end_column
        if matched_text:
            blocked_entry["matched_text"] = matched_text[:100]
        violation_logger = violation_logger or ViolationLogger()
        violation_logger.log_violation(
            violation_type=ViolationType.EXFIL_DETECTION,
            blocked=blocked_entry,
            context=_build_violation_context(context, hook_context),
            suggestion={
                "action": "add_allowlist_pattern",
                "note": "If this is a legitimate command, add a regex to exfil_detection.allowlist_patterns in ai-guardian.json",
            },
            severity="high",
        )
    except Exception as e:
        logger.error(f"Failed to log exfil detection violation: {e}")


def _log_offensive_language_violation(
    result,
    hook_name: str,
    hook_event: str,
    tool_identifier: Optional[str] = None,
    hook_tool_use_id: Optional[str] = None,
    hook_session_id: Optional[str] = None,
    violation_logger=None,
):
    """Log an offensive language violation."""
    if not HAS_VIOLATION_LOGGER:
        return
    try:
        findings = result.findings or []
        first = findings[0] if findings else {}
        blocked_entry = {
            "file_path": result.file_path,
            "line_number": result.line_number,
            "rule_id": result.rule_id,
            "category": result.attack_type,
            "matched_text": result.matched_text[:100] if result.matched_text else "",
            "suggestion": first.get("suggestion", ""),
            "total_findings": result.total_findings,
        }
        if result.start_column is not None:
            blocked_entry["start_column"] = result.start_column
        if result.end_column is not None:
            blocked_entry["end_column"] = result.end_column
        ctx = {
            "action": result.extra.get("action", "log"),
            "hook_event": hook_event,
            "hook": hook_name,
            "tool": tool_identifier,
        }
        if hook_tool_use_id:
            ctx["tool_use_id"] = hook_tool_use_id
        if hook_session_id:
            ctx["session_id"] = hook_session_id
        vl = violation_logger or ViolationLogger()
        vl.log_violation(
            violation_type=ViolationType.OFFENSIVE_LANGUAGE,
            blocked=blocked_entry,
            context=ctx,
            suggestion={
                "action": "review_offensive_language",
                "note": (
                    "Replace the term with a neutral alternative. "
                    "Add '# ai-guardian:allow' inline or use scan_offensive.allowlist_patterns "
                    "to suppress known-safe uses."
                ),
            },
        )
    except Exception as e:
        logger.error(f"Failed to log offensive language violation: {e}")


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

        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Count [[rules]] sections (each represents one detection rule)
        rule_count = content.count("[[rules]]")
        return rule_count

    except Exception as e:
        logging.debug(f"Error counting patterns in {config_path}: {e}")
        return 0


def _log_pii_violation(
    violation_logger,
    pii_config,
    pii_redactions,
    tool_identifier,
    hook_name,
    file_path,
    snippet_text,
    hook_event,
    hook_tool_use_id=None,
    hook_session_id=None,
    bash_command=None,
    pretool_ctx=None,
):
    """Log a PII violation and return (pii_action, pii_types)."""
    pii_action = pii_config.get("action", "block")
    pii_types = list(set(r["type"] for r in pii_redactions))
    pii_first_line = pii_redactions[0].get("line_number") if pii_redactions else None

    first_redaction = pii_redactions[0] if pii_redactions else {}
    pii_start_column = first_redaction.get("column")
    if pii_start_column is not None:
        pii_start_column = pii_start_column - 1
    pii_end_column = None
    if pii_start_column is not None:
        orig_len = first_redaction.get("original_length", 0)
        if orig_len:
            pii_end_column = pii_start_column + orig_len

    pii_blocked = {
        "tool": tool_identifier,
        "hook": hook_name,
        "file_path": file_path,
        "line_number": pii_first_line,
        "pii_count": len(pii_redactions),
        "pii_types": pii_types,
    }
    if pii_start_column is not None:
        pii_blocked["start_column"] = pii_start_column
    if pii_end_column is not None:
        pii_blocked["end_column"] = pii_end_column
    if bash_command:
        pii_blocked["command"] = bash_command
    snippet = _extract_context_snippet(snippet_text, pii_first_line)
    if snippet:
        pii_blocked["context_snippet"] = snippet

    pii_ctx = {"action": pii_action, "hook_event": hook_event}
    if hook_tool_use_id:
        pii_ctx["tool_use_id"] = hook_tool_use_id
    if hook_session_id:
        pii_ctx["session_id"] = hook_session_id
    if pretool_ctx:
        pii_ctx["pretool_context"] = pretool_ctx

    if violation_logger:
        violation_logger.log_violation(
            violation_type=ViolationType.PII_DETECTED,
            blocked=pii_blocked,
            context=pii_ctx,
            suggestion={
                "action": "review_pii_detection",
                "false_positive": (
                    "Allowlist the value in scan_pii.allowlist_patterns, "
                    "disable specific PII types in scan_pii.pii_types, "
                    "or add '# ai-guardian:allow' inline"
                ),
            },
        )

    return pii_action, pii_types


_CATEGORY_BANNER = {
    "pii": {
        "title": "PII Detected",
        "type_label": "PII Type",
        "why": (
            "Personally identifiable information (PII) must not be exposed to AI\n"
            "assistants or committed to version control."
        ),
        "recommendations": [
            "Redact or mask PII before sharing with AI",
            "Use synthetic/test data instead of real PII",
            "Review scan_pii settings in ai-guardian.json",
        ],
        "footer": "",
        "protection": "PII Scanning",
    },
    "prompt_injection": {
        "title": "Prompt Injection Detected",
        "type_label": "Pattern",
        "why": (
            "Prompt injection patterns can manipulate AI assistant behavior\n"
            "and bypass security controls."
        ),
        "recommendations": [
            "Remove or sanitize the injection pattern",
            "Add to allowlist if this is legitimate documentation",
        ],
        "footer": "",
        "protection": "Prompt Injection Detection",
    },
    "unicode": {
        "title": "Unicode Attack Detected",
        "type_label": "Pattern",
        "why": (
            "Invisible or misleading Unicode characters can be used to obfuscate\n"
            "malicious content and bypass text-based security checks."
        ),
        "recommendations": [
            "Remove invisible/zero-width characters",
            "Replace homoglyphs with ASCII equivalents",
            "Add to allowlist if this is legitimate Unicode content",
        ],
        "footer": "",
        "protection": "Unicode Attack Detection",
    },
    "config_exfil": {
        "title": "Config Exfiltration Detected",
        "type_label": "Pattern",
        "why": (
            "This pattern may exfiltrate configuration data, environment variables,\n"
            "or credentials to external services."
        ),
        "recommendations": [
            "Review the command for unintended data exposure",
            "Avoid piping secrets or env vars to external URLs",
        ],
        "footer": "",
        "protection": "Config Exfiltration Detection",
    },
    "ssrf": {
        "title": "SSRF Pattern Detected",
        "type_label": "Pattern",
        "why": (
            "Server-Side Request Forgery (SSRF) patterns target internal networks,\n"
            "cloud metadata endpoints, or private services."
        ),
        "recommendations": [
            "Avoid requests to internal/private IP ranges",
            "Do not access cloud metadata endpoints",
            "Use allowlisted URLs only",
        ],
        "footer": "",
        "protection": "SSRF Protection",
    },
    "offensive_language": {
        "title": "Offensive Language Detected",
        "type_label": "Category",
        "why": (
            "Offensive, discriminatory, or non-inclusive language in code,\n"
            "comments, or variable names can harm team culture and violate\n"
            "enterprise content policies."
        ),
        "recommendations": [
            "Replace offensive terms with neutral alternatives",
            "Check the 'suggestion' field in the violation for recommended replacements",
            "Use scan_offensive.categories to enable only relevant checks",
            "Add '# ai-guardian:allow' inline to suppress known-safe uses",
        ],
        "footer": "",
        "protection": "Offensive Language Scanning",
    },
}


def _build_secret_detected_message(
    scanner_name,
    secret_details,
    pattern_description,
    protection_label="Secret Scanning",
):
    """Build a category-aware detection error banner."""
    category = secret_details.get("category") if secret_details else None
    banner = _CATEGORY_BANNER.get(category) if category else None

    if banner:
        title = banner["title"]
        type_label = banner["type_label"]
        why_text = banner["why"]
        recommendations = banner["recommendations"]
        footer_text = banner["footer"]
        if protection_label == "Secret Scanning":
            protection_label = banner["protection"]
    else:
        title = "Secret Detected"
        type_label = "Secret Type"
        why_text = (
            "Hard-coded secrets in source code can leak to version control\n"
            "and be accessed by unauthorized users."
        )
        recommendations = [
            "Move secrets to environment variables",
            "Use secret management (AWS Secrets Manager, HashiCorp Vault)",
            "Add to .gitignore if in config file",
            "Never commit secrets to git",
        ]
        footer_text = "⚠️  Secret value NOT shown in this message for security\n"

    error_msg = (
        f"\n{'='*70}\n"
        f"🛡️ {title}\n"
        f"{'='*70}\n\n"
        f"Protection: {protection_label}\n"
    )

    if secret_details:
        from ai_guardian.secret_type_names import get_secret_type_display

        display_name = get_secret_type_display(secret_details["rule_id"])
        error_msg += f"{type_label}: {display_name}\n"
        if secret_details.get("line_number"):
            _loc = f"{secret_details['file']}:{secret_details['line_number']}"
            if secret_details.get("start_column") is not None:
                _loc += f":{secret_details['start_column'] + 1}"
            error_msg += f"Location: {_loc}\n"
        else:
            error_msg += f"Location: {secret_details['file']}\n"
    else:
        error_msg += f"{type_label}: (multiple or unknown)\n"

    error_msg += f"Scanner: {scanner_name}\n"
    error_msg += f"Patterns: {pattern_description}\n"

    error_msg += (
        f"\nWhy blocked: {why_text}\n\n"
        f"This operation has been blocked for security.\n"
        f"Please remove the flagged content and try again.\n\n"
        f"DO NOT attempt to bypass this protection.\n\n"
        f"Recommendation:\n"
    )
    for rec in recommendations:
        error_msg += f"  • {rec}\n"
    error_msg += "\n"

    if footer_text:
        error_msg += f"{footer_text}\n"

    if not secret_details and not banner:
        error_msg += (
            "Common secret types:\n"
            "  • API keys and tokens\n"
            "  • Private keys (SSH, RSA, PGP)\n"
            "  • Database credentials\n"
            "  • Cloud provider keys (AWS, GCP, Azure)\n\n"
        )

    error_msg += f"{'='*70}\n"
    return error_msg


def _describe_patterns(
    engine_config, resolved_config_path, config_source, pattern_config
):
    """Return a user-facing description of which patterns a scanner engine uses."""
    engine_type = engine_config.type if engine_config else "gitleaks"

    if (
        HAS_SCANNER_ENGINE
        and engine_config
        and engine_config.pattern_server is not PATTERN_SERVER_UNSET
    ):
        if engine_config.pattern_server is None:
            return f"Built-in {engine_type} rules"
        ps = engine_config.pattern_server
        if isinstance(ps, dict) and ps.get("url"):
            return f"{engine_type} Pattern Server ({ps['url']})"
        return f"Built-in {engine_type} rules"

    if resolved_config_path and config_source == "pattern server" and pattern_config:
        return f"LeakTK Pattern Server ({pattern_config.get('url', 'N/A')})"
    if resolved_config_path and config_source == "project config":
        return f"{resolved_config_path}"

    return f"Built-in {engine_type} rules"


def _apply_secret_validation(
    secret_config: Optional[Dict],
    secrets_info: list,
    content: str,
    context: Optional[Dict] = None,
) -> Optional[Dict]:
    """Apply secret liveness validation if enabled (Issue #971, #983).

    Called after detection + allowlist filtering, before the block decision.
    Validates detected secrets against provider APIs to check if they're
    still active.

    Args:
        secret_config: Secret scanning config dict (may contain validate_secrets, etc.)
        secrets_info: List of secret dicts with at least 'rule_id' and 'line_number'.
                      May also contain 'secret' or 'matched_text'.
        content: Full scanned content (for extracting secret values by line number).
        context: Optional context dict for logging.

    Returns:
        None  — validation disabled or not applicable, no validation field in violation
        dict  — {"skip_block": bool, "validation_info": {"status": ..., "message": ..., "elapsed_ms": ...}}
    """
    if not secret_config or not secret_config.get("validate_secrets", False):
        return None  # Validation not enabled

    if not secrets_info:
        return None

    try:
        from ai_guardian.scanners.secret_validator import (
            SecretValidator,
            ValidationStatus,
        )

        validator = SecretValidator(config=secret_config)
        if not validator.enabled:
            return None

        # Check if any secrets have validators
        has_any_validator = any(
            validator.has_validator(s.get("rule_id", "")) for s in secrets_info
        )
        if not has_any_validator:
            return {
                "skip_block": False,
                "validation_info": {
                    "status": "unverified",
                    "message": "No validator for this rule",
                    "elapsed_ms": 0,
                },
            }

        results = validator.validate_secrets(secrets_info, content)
        active_secrets, inactive_secrets = validator.filter_inactive(
            secrets_info, results
        )

        # Build validation_info from first result (matches primary secret in violation)
        primary_result = results[0] if results else None

        if not active_secrets and inactive_secrets:
            # All secrets are inactive — log and skip blocking
            on_inactive = validator.on_inactive
            for result in results:
                if result.status == ValidationStatus.INACTIVE:
                    if on_inactive == "warn":
                        logging.warning(
                            f"Secret '{result.rule_id}' is inactive (revoked/expired): "
                            f"{result.message} [{result.elapsed_ms:.0f}ms]"
                        )
                    else:
                        logging.info(
                            f"Secret '{result.rule_id}' is inactive: {result.message}"
                        )
            logging.info(
                f"All {len(inactive_secrets)} detected secret(s) validated as inactive — "
                f"skipping block (on_inactive={on_inactive})"
            )
            return {
                "skip_block": True,
                "validation_info": {
                    "status": (
                        primary_result.status.value if primary_result else "inactive"
                    ),
                    "message": primary_result.message if primary_result else "",
                    "elapsed_ms": primary_result.elapsed_ms if primary_result else 0,
                },
            }

        # At least one secret is active or unverified — block
        for result in results:
            if result.status == ValidationStatus.VERIFIED:
                logging.warning(
                    f"Secret '{result.rule_id}' VERIFIED ACTIVE "
                    f"[{result.elapsed_ms:.0f}ms]"
                )
            elif result.status == ValidationStatus.INACTIVE:
                logging.info(
                    f"Secret '{result.rule_id}' inactive but other secrets "
                    f"still active — blocking all"
                )

        # Use first active/verified result for validation_info, fall back to primary
        active_result = next(
            (r for r in results if r.status == ValidationStatus.VERIFIED),
            primary_result,
        )
        return {
            "skip_block": False,
            "validation_info": {
                "status": active_result.status.value if active_result else "unverified",
                "message": active_result.message if active_result else "",
                "elapsed_ms": active_result.elapsed_ms if active_result else 0,
            },
        }

    except ImportError:
        logging.debug("Secret validator module not available — skipping validation")
        return None
    except Exception as e:
        logging.warning(f"Secret validation error (fail-closed): {e}")
        return {
            "skip_block": False,
            "validation_info": {
                "status": "error",
                "message": str(e),
                "elapsed_ms": 0,
            },
        }


def _run_secret_validation(secret_config, secrets_list, content, context):
    """Run secret liveness validation and return (validation_info, should_skip).

    Shared helper for the 4 code paths in check_secrets_with_gitleaks that
    perform secret validation after detection.
    """
    validation_result = _apply_secret_validation(
        secret_config,
        secrets_list,
        content if isinstance(content, str) else str(content),
        context=context,
    )
    validation_info = (
        validation_result.get("validation_info") if validation_result else None
    )
    should_skip = bool(validation_result and validation_result.get("skip_block"))
    return validation_info, should_skip


_last_secret_matched_text = ""
_last_secret_line_number = None
_last_secret_start_column = None
_last_secret_findings = []


def _extract_matched_text_for_ask(secret_details, content):
    """Extract matched text from secret_details or content for ask-mode display."""
    if not secret_details:
        return ""
    mt = secret_details.get("matched_text")
    if mt:
        return mt.strip()
    line_num = secret_details.get("line_number", 0)
    if line_num > 0 and content:
        lines = (content if isinstance(content, str) else str(content)).splitlines()
        if 0 < line_num <= len(lines):
            return lines[line_num - 1].strip()
    return ""


def _extract_pii_matched_text(pii_redactions, content):
    """Extract actual PII text from content using redaction position data."""
    if not pii_redactions or not content:
        return ""
    r = pii_redactions[0]
    pos = r.get("position", -1)
    length = r.get("original_length", 0)
    if pos >= 0 and length > 0 and pos + length <= len(content):
        return content[pos : pos + length]
    return ""


def _pii_redactions_to_findings(pii_redactions, content, error_msg=""):
    """Convert PII redaction list to findings format for multi-finding ask dialog."""
    if not pii_redactions or not content:
        return None
    findings = []
    for r in pii_redactions:
        pos = r.get("position", -1)
        length = r.get("original_length", 0)
        matched = ""
        if pos >= 0 and length > 0 and pos + length <= len(content):
            matched = content[pos : pos + length]
        findings.append(
            {
                "matched_text": matched,
                "line_number": r.get("line_number"),
                "start_column": r.get("column"),
                "error_message": f"PII: {r.get('type', 'unknown')}",
            }
        )
    return findings if findings else None


def _extract_file_path_from_pii_warning(pii_warning):
    """Extract file path from PII warning message as fallback when tool_input has no file_path."""
    if not pii_warning:
        return None
    match = re.search(r"File:\s*(\S+)", pii_warning)
    return match.group(1) if match else None


def check_secrets_with_gitleaks(
    content,
    filename="temp_file",
    context: Optional[Dict] = None,
    file_path: Optional[str] = None,
    tool_name: Optional[str] = None,
    ignore_files: Optional[list] = None,
    ignore_tools: Optional[list] = None,
    allowlist_patterns: Optional[list] = None,
    secret_config: Optional[Dict] = None,
):
    """
    Check content for secrets using Gitleaks binary.

    Scans content for secrets using the open-source Gitleaks tool.
    Uses in-memory temp files on Linux for better performance.

    Supports optional pattern server integration for enhanced detection patterns.

    Multi-engine support (#91): Supports multiple scanner engines via
    secret_scanning.engines config and execution strategies (first-match,
    any-match, consensus). See docs/MULTI_ENGINE_SUPPORT.md for details.

    Args:
        content: The text content to scan for secrets
        filename: Optional filename for context in error messages
        context: Optional context dict for violation logging (ide_type, hook_event, etc.)
        file_path: Optional file path being scanned (for ignore_files matching)
        tool_name: Optional tool name being used (for ignore_tools matching)
        ignore_files: Optional list of glob patterns for files to skip
        ignore_tools: Optional list of tool name patterns to skip
        allowlist_patterns: Optional list of regex patterns for known-safe values to ignore

    Returns:
        tuple: (has_secrets: bool, error_message: str or None)
            - has_secrets: True if secrets detected, False otherwise
            - error_message: Detailed error if secrets found, None otherwise

    Note:
        Secret scanning ALWAYS blocks when secrets are detected (no "log" mode).
        This prevents secrets from reaching Claude's API or being exposed in sessions.
    """
    global _last_secret_matched_text, _last_secret_line_number, _last_secret_start_column, _last_secret_findings
    _last_secret_matched_text = ""
    _last_secret_line_number = None
    _last_secret_start_column = None
    _last_secret_findings = []
    try:
        # Check if tool should be ignored
        if ignore_tools and tool_name:
            for pattern in ignore_tools:
                if fnmatch.fnmatch(tool_name, pattern):
                    logging.info(
                        f"Skipping secret scanning for ignored tool: {tool_name}"
                    )
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
                    expanded_pattern = os.path.expanduser(pattern)
                    matched = file_path_obj.match(expanded_pattern)

                if matched:
                    logging.info(
                        f"Skipping secret scanning for ignored file: {file_path}"
                    )
                    return False, None

        # Convert content to string if it's not already
        # Agent tool outputs can be lists, dicts, or other types
        if isinstance(content, list):
            content = "\n".join(str(item) for item in content)
        elif not isinstance(content, str):
            content = str(content)

        # Skip scanning if file is a gitleaks config file (path-based check)
        # This prevents false positives when viewing pattern files
        # Use path-based detection instead of content-based to prevent bypass
        if file_path and file_path.endswith(".gitleaks.toml"):
            logging.debug(f"Skipping scan - file is a gitleaks config: {file_path}")
            return False, None

        # Check project .gitleaks.toml path allowlist (Issue #488)
        _gitleaks_allowlist = None
        if HAS_GITLEAKS_CONFIG:
            _gitleaks_allowlist = _gitleaks_cfg.load_gitleaks_allowlist()
            if _gitleaks_allowlist and file_path:
                if _gitleaks_cfg.should_skip_file(file_path, _gitleaks_allowlist):
                    logging.info(
                        f"Skipping secret scanning for .gitleaks.toml allowlisted path: {file_path}"
                    )
                    return False, None

        # AST-aware scanning: for code files, extract only comments and strings
        if HAS_AST_SCANNER and file_path:
            extracted = extract_scannable_content(content, file_path)
            if extracted is not None:
                content = extracted
                if not content.strip():
                    return False, None

        # Use in-memory filesystem on Linux for better performance
        tmp_base_dir = "/dev/shm" if os.path.exists("/dev/shm") else None

        # Create temporary file with content
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=f"_{filename}",
            prefix="aiguardian_",
            dir=tmp_base_dir,
            delete=False,
        ) as tmp_file:
            tmp_file.write(content)
            tmp_file.flush()
            tmp_file_path = tmp_file.name

        # Load stopwords + entropy threshold for external scanner filtering (#1245)
        from ai_guardian.patterns.validators import (
            load_stopwords,
            filter_findings_by_stopwords_entropy,
            filter_findings_dicts_by_stopwords_entropy,
            filter_findings_by_hash,
            filter_findings_dicts_by_hash,
        )

        _ext_stopwords = load_stopwords(secret_config)
        _ext_min_entropy = (
            float(secret_config.get("min_entropy", 3.0))
            if secret_config and secret_config.get("min_entropy") is not None
            else 3.0
        )

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
            pattern_server_url = None

            # Priority 1: Pattern server (if enabled and available)
            if HAS_PATTERN_SERVER:
                pattern_config = _load_pattern_server_config()
                if pattern_config:
                    pattern_server_attempted = True
                    pattern_server_url = pattern_config.get("url")
                    try:
                        pattern_client = PatternServerClient(pattern_config)
                        server_patterns = pattern_client.get_patterns_path()
                        if server_patterns:
                            # SUCCESS: Use pattern server
                            gitleaks_config_path = server_patterns
                            config_source = "pattern server"
                            logging.info(
                                f"Using pattern server config: {server_patterns}"
                            )
                        else:
                            # Pattern server failed - will try scanner engines below
                            logging.warning(
                                f"Pattern server unavailable ({pattern_config.get('url')}), "
                                f"falling back to scanner engines"
                            )
                    except Exception as e:
                        logging.warning(
                            f"Pattern server error, trying scanner engines: {e}"
                        )

            # Priority 2: Scanner Engines (if pattern server not used)
            engine_config = None
            execution_strategy_name = "first-match"
            consensus_threshold = 2
            _all_available_engines = None
            if not gitleaks_config_path and HAS_SCANNER_ENGINE:
                try:
                    scanner_config = (
                        secret_config
                        if secret_config
                        else (_load_secret_scanning_config()[0])
                    )
                    engines_list = (
                        scanner_config.get("engines", DEFAULT_ENGINES)
                        if scanner_config
                        else DEFAULT_ENGINES
                    )
                    execution_strategy_name = (
                        scanner_config.get("execution_strategy", "first-match")
                        if scanner_config
                        else "first-match"
                    )
                    consensus_threshold = (
                        scanner_config.get("consensus_threshold", 2)
                        if scanner_config
                        else 2
                    )

                    # Select first available engine (logs warnings for unavailable ones)
                    engine_config = select_engine(
                        engines_list, parent_config=scanner_config
                    )

                    # For first-match strategy, get all available engines for fallthrough
                    _all_available_engines = None
                    if (
                        execution_strategy_name == "first-match"
                        and len(engines_list) > 1
                    ):
                        try:
                            _all_available_engines = select_all_engines(
                                engines_list, parent_config=scanner_config
                            )
                        except RuntimeError:
                            pass  # Only primary engine available

                    # Log context about why we're using scanner engines
                    if pattern_server_attempted:
                        logging.warning(
                            f"Using {engine_config.type} scanner (pattern server unavailable)"
                        )
                    else:
                        logging.info(f"Using {engine_config.type} scanner")

                    config_source = f"{engine_config.type} defaults"

                except RuntimeError:
                    # NO SCANNER AVAILABLE - WARN (allow operation to continue)
                    default_scanner = engines_list[0] if engines_list else "gitleaks"
                    if pattern_server_attempted:
                        warning_msg = (
                            f"⚠️  WARNING: No secret scanning available\n\n"
                            f"Pattern server: {pattern_server_url} — unavailable\n"
                            f"Scanner engines: {engines_list} — none installed\n\n"
                            f"Please install a scanner with:\n"
                            f"  ai-guardian scanner install {default_scanner}\n\n"
                            f"Until a scanner is installed, you may leak secrets."
                        )
                    else:
                        warning_msg = (
                            f"⚠️  WARNING: No secret scanning available\n\n"
                            f"No scanner engine is installed.\n"
                            f"Tried engines: {engines_list} — none found\n\n"
                            f"Please install a scanner with:\n"
                            f"  ai-guardian scanner install {default_scanner}\n\n"
                            f"Until a scanner is installed, you may leak secrets."
                        )
                    on_error = _get_on_scan_error_action()
                    if on_error == ActionMode.BLOCK:
                        logging.error(
                            "No scanner available (fail-closed, on_scan_error=block)"
                        )
                        return (
                            True,
                            warning_msg
                            + "\n\nOperation BLOCKED (on_scan_error=block).",
                        )
                    logging.warning("No scanner available - warning user")
                    return False, warning_msg

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
                mode="w",
                suffix=".json",
                prefix="scanner_report_",
                dir=tmp_base_dir,
                delete=False,
            ) as rf:
                report_file = rf.name

            # Multi-engine strategy execution path (any-match, consensus)
            # For these strategies, run all engines via the strategy framework
            # and return the combined result directly.
            if (
                execution_strategy_name in ("first-match", "any-match", "consensus")
                and HAS_SCANNER_ENGINE
                and not gitleaks_config_path
            ):
                try:
                    all_engines = select_all_engines(
                        engines_list, parent_config=scanner_config
                    )
                    strategy_kwargs = {}
                    if execution_strategy_name == "consensus":
                        strategy_kwargs["threshold"] = consensus_threshold
                    strategy = get_strategy(execution_strategy_name, **strategy_kwargs)

                    strategy_result = strategy.execute(
                        engine_configs=all_engines,
                        scanner_fn=run_engine,
                        source_file=tmp_file_path,
                        report_file_prefix=report_file.replace(".json", ""),
                        config_path=gitleaks_config_path,
                        context={"filename": filename},
                    )

                    if strategy_result.has_secrets and strategy_result.secrets:
                        # Apply allowlist filtering
                        if allowlist_patterns:
                            from ai_guardian import allowlist_utils

                            compiled_allowlist = allowlist_utils.compile_allowlist(
                                allowlist_patterns
                            )
                            if compiled_allowlist:
                                content_str = (
                                    content
                                    if isinstance(content, str)
                                    else str(content)
                                )
                                content_lines = content_str.splitlines()
                                all_allowlisted = True
                                for secret in strategy_result.secrets:
                                    line_num = secret.line_number
                                    if line_num > 0 and line_num <= len(content_lines):
                                        if not allowlist_utils.check_allowlist(
                                            content_lines[line_num - 1],
                                            compiled_allowlist,
                                        ):
                                            all_allowlisted = False
                                            break
                                    else:
                                        all_allowlisted = False
                                        break
                                if all_allowlisted:
                                    logging.info(
                                        "All strategy findings matched allowlist — skipping"
                                    )
                                    return False, None

                        # Apply .gitleaks.toml allowlist filtering (Issue #488)
                        if _gitleaks_allowlist and strategy_result.secrets:
                            content_str = (
                                content if isinstance(content, str) else str(content)
                            )
                            gl_lines = content_str.splitlines()
                            findings_dicts = [
                                {
                                    "rule_id": s.rule_id,
                                    "line_number": s.line_number,
                                    "file": s.file,
                                }
                                for s in strategy_result.secrets
                            ]
                            remaining = _gitleaks_cfg.filter_findings(
                                findings_dicts, gl_lines, file_path, _gitleaks_allowlist
                            )
                            if not remaining:
                                logging.info(
                                    "All strategy findings matched .gitleaks.toml allowlist — skipping"
                                )
                                return False, None

                        # Filter external scanner findings by stopwords/entropy (#1245)
                        if _ext_stopwords or _ext_min_entropy is not None:
                            strategy_result.secrets, _sw_n, _ent_n = (
                                filter_findings_by_stopwords_entropy(
                                    strategy_result.secrets,
                                    _ext_stopwords,
                                    _ext_min_entropy,
                                )
                            )
                            if _sw_n or _ent_n:
                                logging.info(
                                    f"External scanner: filtered {_sw_n} stopword + "
                                    f"{_ent_n} low-entropy findings (strategy path)"
                                )
                            if not strategy_result.secrets:
                                logging.info(
                                    "All external scanner findings filtered by stopwords/entropy — skipping"
                                )
                                return False, None

                        # Filter hash false positives (#1378)
                        strategy_result.secrets, _hash_n = filter_findings_by_hash(
                            strategy_result.secrets, content
                        )
                        if _hash_n:
                            logging.info(
                                f"External scanner: filtered {_hash_n} hash value findings (strategy path)"
                            )
                        if not strategy_result.secrets:
                            logging.info(
                                "All external scanner findings filtered as hash values — skipping"
                            )
                            return False, None

                        # Secret liveness validation (Issue #971, #983)
                        secrets_for_validation = [
                            {
                                "rule_id": s.rule_id,
                                "line_number": s.line_number,
                                "secret": s.secret,
                            }
                            for s in strategy_result.secrets
                        ]
                        validation_info, should_skip = _run_secret_validation(
                            secret_config,
                            secrets_for_validation,
                            content,
                            context,
                        )

                        first_secret = strategy_result.secrets[0]
                        secret_findings_list = [
                            {
                                "matched_text": (
                                    _extract_matched_text_for_ask(
                                        {
                                            "matched_text": s.secret,
                                            "line_number": s.line_number,
                                        },
                                        content,
                                    )
                                    if content
                                    else s.secret
                                ),
                                "matched_pattern": s.rule_id or "",
                                "rule_id": s.rule_id,
                                "line_number": s.line_number,
                                "start_column": s.start_column,
                                "end_column": s.end_column,
                                "category": s.category,
                            }
                            for s in strategy_result.secrets
                        ]
                        secret_details = {
                            "rule_id": first_secret.rule_id,
                            "file": file_path or filename,
                            "line_number": first_secret.line_number,
                            "end_line": first_secret.end_line or 0,
                            "start_column": first_secret.start_column,
                            "end_column": first_secret.end_column,
                            "commit": first_secret.commit or "N/A",
                            "total_findings": len(strategy_result.secrets),
                            "engine": strategy_result.engine,
                            "category": first_secret.category,
                            "matched_text": first_secret.secret,
                            "findings": secret_findings_list,
                        }
                        if validation_info:
                            secret_details["validation"] = validation_info

                        if should_skip:
                            _log_finding_violation(
                                file_path or filename,
                                context,
                                secret_details,
                                hook_context=context,
                            )
                            logging.info(
                                "All secrets validated as inactive (strategy path) — allowing"
                            )
                            return False, None

                        scanner_name = strategy_result.engine
                        error_msg = _build_secret_detected_message(
                            scanner_name,
                            secret_details,
                            f"Built-in {scanner_name} rules",
                            f"Secret Scanning ({execution_strategy_name} strategy)",
                        )

                        _log_finding_violation(
                            file_path or filename,
                            context,
                            secret_details,
                            hook_context=context,
                        )
                        logging.error(
                            f"Secret detected ({execution_strategy_name}): {first_secret.rule_id}"
                        )
                        _last_secret_matched_text = _extract_matched_text_for_ask(
                            secret_details, content
                        )
                        _last_secret_line_number = secret_details.get("line_number")
                        _last_secret_start_column = secret_details.get("start_column")
                        _last_secret_findings = secret_findings_list
                        return True, error_msg

                    # No secrets found — check for engine errors that need user attention
                    if strategy_result.error:
                        error_lower = (strategy_result.error or "").lower()

                        # Auth errors → block (user can fix credentials)
                        is_auth_error = any(
                            kw in error_lower for kw in _AUTH_ERROR_KEYWORDS
                        )
                        if is_auth_error:
                            error_msg = (
                                f"\n{'='*70}\n"
                                f"🚨 BLOCKED BY POLICY\n"
                                f"🔒 AUTHENTICATION ERROR\n"
                                f"{'='*70}\n\n"
                                f"Scanner authentication failed.\n"
                                f"\nError: {strategy_result.error[:200]}\n"
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
                            return True, error_msg

                        # Network errors → warn but allow (fail-open)
                        is_network_error = any(
                            kw in error_lower for kw in _NETWORK_ERROR_KEYWORDS
                        )
                        if is_network_error:
                            warning_msg = (
                                f"\n{'='*70}\n"
                                f"⚠️  SECRET SCANNING WARNING\n"
                                f"{'='*70}\n"
                                f"Scanner error: {strategy_result.error[:200]}\n"
                                "\n💡 Network or server issue detected.\n"
                                "   If using pattern-servers, the server may be temporarily unavailable.\n"
                                "   You can disable pattern-servers in ~/.config/ai-guardian/ai-guardian.json\n"
                                "\nOperation will continue, but secret scanning may not be functioning.\n"
                                f"{'='*70}\n"
                            )
                            print(warning_msg, file=sys.stderr)
                            on_error = _get_on_scan_error_action()
                            if on_error == ActionMode.BLOCK:
                                return (
                                    True,
                                    warning_msg
                                    + "\nOperation BLOCKED (on_scan_error=block).",
                                )
                            return False, None

                        # Binary not found → warn but allow (fail-open)
                        if "not found" in error_lower or "no scanners" in error_lower:
                            scanner_name = (
                                engines_list[0] if engines_list else "gitleaks"
                            )
                            warning_msg = (
                                f"\n{'='*70}\n"
                                f"⚠️  SECRET SCANNING DISABLED\n"
                                f"{'='*70}\n\n"
                                f"Gitleaks binary not found.\n"
                                f"Secret scanning will not run until Gitleaks is installed.\n\n"
                                f"Install with:\n"
                                f"  brew install {scanner_name}  (macOS)\n"
                                f"\nOperation will continue without secret scanning.\n"
                                f"{'='*70}\n"
                            )
                            print(warning_msg, file=sys.stderr)
                            return False, None

                    return False, None

                except RuntimeError as e:
                    logging.warning(f"Multi-engine strategy failed: {e}")
                    return False, str(e)
                except Exception as e:
                    logging.error(f"Unexpected error in multi-engine strategy: {e}")
                    return False, None

            # If we have pattern server config, select engine for using it
            # (engine_config already set above if using scanner defaults)
            if gitleaks_config_path and not engine_config and HAS_SCANNER_ENGINE:
                try:
                    scanner_config = (
                        secret_config
                        if secret_config
                        else (_load_secret_scanning_config()[0])
                    )
                    engines_list = (
                        scanner_config.get("engines", DEFAULT_ENGINES)
                        if scanner_config
                        else DEFAULT_ENGINES
                    )
                    execution_strategy_name = (
                        scanner_config.get("execution_strategy", "first-match")
                        if scanner_config
                        else "first-match"
                    )
                    engine_config = select_engine(
                        engines_list, parent_config=scanner_config
                    )

                    # For first-match: get all engines for fallthrough (Issue #523)
                    if (
                        execution_strategy_name == "first-match"
                        and len(engines_list) > 1
                    ):
                        try:
                            _all_available_engines = select_all_engines(
                                engines_list, parent_config=scanner_config
                            )
                        except RuntimeError:
                            pass  # intentionally silent — best-effort operation
                except RuntimeError as e:
                    # No scanner found - warn (allow operation to continue)
                    # Path 2: Pattern server succeeded but no engine to run patterns
                    default_scanner = engines_list[0] if engines_list else "gitleaks"
                    warning_msg = (
                        f"⚠️  WARNING: Scanner engine required\n\n"
                        f"Enterprise patterns are available from the pattern server,\n"
                        f"but no scanner engine is installed to use them.\n\n"
                        f"Please install a scanner with:\n"
                        f"  ai-guardian scanner install {default_scanner}\n\n"
                        f"Until a scanner is installed, you may leak secrets."
                    )
                    logging.warning(f"Scanner engine selection failed: {e}")
                    return False, warning_msg
                except Exception as e:
                    logging.error(f"Unexpected error selecting scanner engine: {e}")
                    return False, None

            # Build scanner command
            resolved_config_path = None
            if engine_config and HAS_SCANNER_ENGINE:
                # Use flexible engine builder (Issue #154)
                resolved_config_path = resolve_engine_config_path(
                    engine_config, gitleaks_config_path
                )
                cmd = build_scanner_command(
                    engine_config=engine_config,
                    source_file=tmp_file_path,
                    report_file=report_file,
                    config_path=resolved_config_path,
                )
            else:
                # Legacy fallback: hardcoded gitleaks command
                logging.debug(
                    "Using legacy gitleaks command (scanner engine not available)"
                )
                cmd = [
                    "gitleaks",
                    "detect",
                    "--no-git",  # Don't use git history
                    "--verbose",  # Detailed output
                    "--redact",  # Defense-in-depth: redact Match/Secret fields in JSON
                    # (we don't extract these fields, but safeguard against future changes)
                    "--report-format",
                    "json",  # JSON output for parsing
                    "--report-path",
                    report_file,  # Write JSON to file
                    "--exit-code",
                    "42",  # Custom exit code for found secrets
                    "--source",
                    tmp_file_path,
                ]
                # Add custom config if we have one
                if gitleaks_config_path:
                    cmd.extend(["--config", str(Path(gitleaks_config_path).absolute())])

            # Run scanner
            logging.debug(f"Scanner command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30  # Prevent hanging
            )

            # Determine expected exit codes for secrets found/success
            # Use engine-specific codes if available, otherwise use gitleaks defaults
            expected_secrets_code = (
                engine_config.secrets_found_exit_code if engine_config else 42
            )
            expected_success_codes = (
                [engine_config.success_exit_code] if engine_config else [0]
            )

            logging.debug(
                f"Scanner exit code: {result.returncode}, expected_secrets={expected_secrets_code}, expected_success={expected_success_codes}"
            )

            # Gitleaks/betterleaks use exit code 1 as default "secrets found" code
            # when --exit-code flag is not honored. Treat exit 1 as secrets found
            # for these engines to prevent bypass (Issue #411).
            _is_gitleaks_like = (
                engine_config and engine_config.type in ("gitleaks", "betterleaks")
            ) or not engine_config  # legacy path uses gitleaks
            _is_secrets_found = result.returncode == expected_secrets_code or (
                result.returncode == 1 and _is_gitleaks_like
            )

            # Check exit code
            if _is_secrets_found:  # Secrets found
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
                            first_finding = (
                                scan_result["findings"][0]
                                if scan_result["findings"]
                                else {}
                            )
                            secret_details = {
                                "rule_id": first_finding.get("rule_id", "Unknown"),
                                "file": file_path or filename,
                                "line_number": first_finding.get("line_number", 0),
                                "end_line": first_finding.get("end_line", 0),
                                "start_column": first_finding.get("start_column"),
                                "end_column": first_finding.get("end_column"),
                                "commit": first_finding.get("commit", "N/A"),
                                "total_findings": scan_result.get("total_findings", 0),
                                "matched_text": first_finding.get("matched_text", ""),
                            }
                    except Exception as e:
                        logging.error(
                            f"Failed to parse scanner output with {engine_config.output_parser} parser: {e}"
                        )
                else:
                    # Legacy parser for gitleaks
                    try:
                        if os.path.exists(report_file):
                            with open(report_file, "r", encoding="utf-8") as f:
                                findings = json.load(f)
                            if findings and len(findings) > 0:
                                # Get first finding for details
                                first_finding = findings[0]
                                secret_details = {
                                    "rule_id": first_finding.get("RuleID", "Unknown"),
                                    "file": file_path or filename,
                                    "line_number": first_finding.get("StartLine", 0),
                                    "end_line": first_finding.get("EndLine", 0),
                                    "start_column": first_finding.get("StartColumn"),
                                    "end_column": first_finding.get("EndColumn"),
                                    "commit": first_finding.get("Commit", "N/A"),
                                    "total_findings": len(findings),
                                    "matched_text": first_finding.get("Match", ""),
                                }
                    except Exception as e:
                        logging.debug(f"Failed to parse scanner JSON report: {e}")

                # Guard: exit code said secrets but report is empty/unparseable (Issue #532)
                # Don't return immediately — fall through to first-match fallthrough (Issue #523)
                if secret_details is None and (
                    scan_result is None or not scan_result.get("has_secrets")
                ):
                    logging.warning(
                        f"Scanner exited with secrets-found code ({result.returncode}) "
                        f"but produced no findings — treating as clean"
                    )
                    if (
                        execution_strategy_name == "first-match"
                        and _all_available_engines
                        and len(_all_available_engines) > 1
                    ):
                        remaining = [
                            e
                            for e in _all_available_engines
                            if e.type != engine_config.type
                        ]
                        if remaining:
                            logging.info(
                                f"Engine {engine_config.type} found no secrets, "
                                f"trying remaining engines: {[e.type for e in remaining]}"
                            )
                            strategy = get_strategy("first-match")
                            fallback_result = strategy.execute(
                                engine_configs=remaining,
                                scanner_fn=run_engine,
                                source_file=tmp_file_path,
                                report_file_prefix=report_file.replace(".json", ""),
                                config_path=None,
                                context={"filename": filename},
                            )
                            if fallback_result.has_secrets and fallback_result.secrets:
                                # Filter by stopwords/entropy (#1245) — fallthrough path 1
                                if _ext_stopwords or _ext_min_entropy is not None:
                                    fallback_result.secrets, _sw_n, _ent_n = (
                                        filter_findings_by_stopwords_entropy(
                                            fallback_result.secrets,
                                            _ext_stopwords,
                                            _ext_min_entropy,
                                        )
                                    )
                                    if _sw_n or _ent_n:
                                        logging.info(
                                            f"External scanner: filtered {_sw_n} stopword + "
                                            f"{_ent_n} low-entropy findings (fallthrough 1)"
                                        )
                                    if not fallback_result.secrets:
                                        logging.info(
                                            "All fallthrough-1 findings filtered by stopwords/entropy — skipping"
                                        )
                                        return False, None

                                # Filter hash false positives (#1378) — fallthrough path 1
                                fallback_result.secrets, _hash_n = (
                                    filter_findings_by_hash(
                                        fallback_result.secrets, content
                                    )
                                )
                                if _hash_n:
                                    logging.info(
                                        f"External scanner: filtered {_hash_n} hash value findings (fallthrough 1)"
                                    )
                                if not fallback_result.secrets:
                                    logging.info(
                                        "All fallthrough-1 findings filtered as hash values — skipping"
                                    )
                                    return False, None

                                # Secret liveness validation (Issue #971, #983) — fallthrough path 1
                                fb_secrets = [
                                    {
                                        "rule_id": s.rule_id,
                                        "line_number": s.line_number,
                                        "secret": s.secret,
                                    }
                                    for s in fallback_result.secrets
                                ]
                                fb_validation_info, fb_should_skip = (
                                    _run_secret_validation(
                                        secret_config,
                                        fb_secrets,
                                        content,
                                        context,
                                    )
                                )

                                first_secret = fallback_result.secrets[0]
                                secret_details = {
                                    "rule_id": first_secret.rule_id,
                                    "file": file_path or filename,
                                    "line_number": first_secret.line_number,
                                    "end_line": first_secret.end_line or 0,
                                    "start_column": first_secret.start_column,
                                    "end_column": first_secret.end_column,
                                    "commit": first_secret.commit or "N/A",
                                    "total_findings": len(fallback_result.secrets),
                                    "engine": fallback_result.engine,
                                    "category": first_secret.category,
                                    "matched_text": first_secret.secret,
                                }
                                if fb_validation_info:
                                    secret_details["validation"] = fb_validation_info

                                if fb_should_skip:
                                    _log_finding_violation(
                                        file_path or filename,
                                        context,
                                        secret_details,
                                        hook_context=context,
                                    )
                                    logging.info(
                                        "All secrets validated as inactive (fallthrough 1) — allowing"
                                    )
                                    return False, None

                                scanner_name = fallback_result.engine
                                error_msg = _build_secret_detected_message(
                                    scanner_name,
                                    secret_details,
                                    "Built-in Defaults",
                                    "Secret Scanning (first-match fallthrough)",
                                )
                                _log_finding_violation(
                                    file_path or filename,
                                    context,
                                    secret_details,
                                    hook_context=context,
                                )
                                logging.error(
                                    f"Secret detected (first-match fallthrough): {first_secret.rule_id}"
                                )
                                _last_secret_matched_text = (
                                    _extract_matched_text_for_ask(
                                        secret_details, content
                                    )
                                )
                                _last_secret_line_number = secret_details.get(
                                    "line_number"
                                )
                                _last_secret_start_column = secret_details.get(
                                    "start_column"
                                )
                                return True, error_msg
                    return False, None

                # Filter findings through allowlist patterns (Issue #357)
                if allowlist_patterns and secret_details:
                    from ai_guardian import allowlist_utils

                    compiled_allowlist = allowlist_utils.compile_allowlist(
                        allowlist_patterns
                    )
                    if compiled_allowlist:
                        content_str = (
                            content if isinstance(content, str) else str(content)
                        )
                        content_lines = content_str.splitlines()

                        all_allowlisted = True
                        # Check findings from modern parser
                        if scan_result and scan_result.get("findings"):
                            for finding in scan_result["findings"]:
                                line_num = finding.get("line_number", 0)
                                if line_num > 0 and line_num <= len(content_lines):
                                    line_text = content_lines[line_num - 1]
                                    if not allowlist_utils.check_allowlist(
                                        line_text, compiled_allowlist
                                    ):
                                        all_allowlisted = False
                                        break
                                else:
                                    all_allowlisted = False
                                    break
                        else:
                            # Legacy parser or single finding — check via line number
                            line_num = secret_details.get("line_number", 0)
                            if line_num > 0 and line_num <= len(content_lines):
                                line_text = content_lines[line_num - 1]
                                if not allowlist_utils.check_allowlist(
                                    line_text, compiled_allowlist
                                ):
                                    all_allowlisted = False
                            else:
                                all_allowlisted = False

                        if all_allowlisted:
                            logging.info(
                                "All secret findings matched allowlist patterns — skipping"
                            )
                            return False, None

                # Apply .gitleaks.toml allowlist filtering (Issue #488)
                if _gitleaks_allowlist and secret_details:
                    content_str = content if isinstance(content, str) else str(content)
                    gl_lines = content_str.splitlines()
                    if scan_result and scan_result.get("findings"):
                        gl_remaining = _gitleaks_cfg.filter_findings(
                            scan_result["findings"],
                            gl_lines,
                            file_path,
                            _gitleaks_allowlist,
                        )
                    else:
                        gl_remaining = _gitleaks_cfg.filter_findings(
                            [secret_details], gl_lines, file_path, _gitleaks_allowlist
                        )
                    if not gl_remaining:
                        logging.info(
                            "All secret findings matched .gitleaks.toml allowlist — skipping"
                        )
                        return False, None

                # Filter external scanner findings by stopwords/entropy (#1245) — legacy path
                if secret_details and (_ext_stopwords or _ext_min_entropy is not None):
                    if scan_result and scan_result.get("findings"):
                        _filt, _sw_n, _ent_n = (
                            filter_findings_dicts_by_stopwords_entropy(
                                scan_result["findings"],
                                _ext_stopwords,
                                _ext_min_entropy,
                            )
                        )
                        if _sw_n or _ent_n:
                            logging.info(
                                f"External scanner: filtered {_sw_n} stopword + "
                                f"{_ent_n} low-entropy findings (legacy path)"
                            )
                        if not _filt:
                            logging.info(
                                "All external scanner findings filtered by stopwords/entropy — skipping"
                            )
                            return False, None
                        # Filter hash false positives (#1378) — legacy path (findings)
                        _filt, _hash_n = filter_findings_dicts_by_hash(_filt, content)
                        if _hash_n:
                            logging.info(
                                f"External scanner: filtered {_hash_n} hash value findings (legacy path)"
                            )
                        if not _filt:
                            logging.info(
                                "All legacy findings filtered as hash values — skipping"
                            )
                            return False, None
                        scan_result["findings"] = _filt
                        scan_result["total_findings"] = len(_filt)
                        first_finding = _filt[0]
                        secret_details = {
                            "rule_id": first_finding.get(
                                "rule_id", secret_details.get("rule_id")
                            ),
                            "file": secret_details.get("file"),
                            "line_number": first_finding.get(
                                "line_number", secret_details.get("line_number")
                            ),
                            "end_line": first_finding.get(
                                "end_line", secret_details.get("end_line", 0)
                            ),
                            "start_column": first_finding.get(
                                "start_column", secret_details.get("start_column")
                            ),
                            "end_column": first_finding.get(
                                "end_column", secret_details.get("end_column")
                            ),
                            "commit": first_finding.get(
                                "commit", secret_details.get("commit", "N/A")
                            ),
                            "total_findings": len(_filt),
                            "matched_text": first_finding.get("matched_text", ""),
                        }
                    else:
                        _filt, _sw_n, _ent_n = (
                            filter_findings_dicts_by_stopwords_entropy(
                                [secret_details], _ext_stopwords, _ext_min_entropy
                            )
                        )
                        if _sw_n or _ent_n:
                            logging.info(
                                f"External scanner: filtered {_sw_n} stopword + "
                                f"{_ent_n} low-entropy findings (legacy path)"
                            )
                        if not _filt:
                            logging.info(
                                "All external scanner findings filtered by stopwords/entropy — skipping"
                            )
                            return False, None
                        # Filter hash false positives (#1378) — legacy path (single)
                        _filt, _hash_n = filter_findings_dicts_by_hash(_filt, content)
                        if _hash_n:
                            logging.info(
                                f"External scanner: filtered {_hash_n} hash value findings (legacy single)"
                            )
                        if not _filt:
                            logging.info(
                                "All legacy findings filtered as hash values — skipping"
                            )
                            return False, None

                # Secret liveness validation (Issue #971, #983) — legacy subprocess path
                if secret_details:
                    secrets_for_validation = [secret_details]
                    if scan_result and scan_result.get("findings"):
                        secrets_for_validation = scan_result["findings"]
                    legacy_validation_info, legacy_should_skip = _run_secret_validation(
                        secret_config,
                        secrets_for_validation,
                        content,
                        context,
                    )
                    if legacy_validation_info:
                        secret_details["validation"] = legacy_validation_info

                    if legacy_should_skip:
                        scanner_name = (
                            engine_config.type if engine_config else "Gitleaks"
                        )
                        if secret_details is not None:
                            secret_details.setdefault("engine", scanner_name)
                        _log_finding_violation(
                            file_path or filename,
                            context,
                            secret_details,
                            hook_context=context,
                        )
                        logging.info(
                            "All secrets validated as inactive (legacy path) — allowing"
                        )
                        return False, None

                # Build error message with details if available
                scanner_name = engine_config.type if engine_config else "Gitleaks"
                pattern_config_for_msg = pattern_config if HAS_PATTERN_SERVER else None
                error_msg = _build_secret_detected_message(
                    scanner_name,
                    secret_details,
                    _describe_patterns(
                        engine_config,
                        resolved_config_path,
                        config_source,
                        pattern_config_for_msg,
                    ),
                )

                # Log violation with category-aware routing (Issue #984)
                if secret_details is not None:
                    secret_details.setdefault("engine", scanner_name)
                _log_finding_violation(
                    file_path or filename, context, secret_details, hook_context=context
                )

                # Always block - secret scanning does not support "log" mode
                # (unless validation confirmed all secrets are inactive - Issue #971)
                # Rationale: Allowing secrets through (even in audit mode) creates security risk:
                #   - UserPromptSubmit: secrets reach Claude's API
                #   - PostToolUse: secrets in tool outputs go to Claude's session
                logging.error(
                    f"Secret detected: {secret_details.get('rule_id') if secret_details else 'unknown'}"
                )
                _last_secret_matched_text = _extract_matched_text_for_ask(
                    secret_details, content
                )
                _last_secret_line_number = (
                    secret_details.get("line_number") if secret_details else None
                )
                _last_secret_start_column = (
                    secret_details.get("start_column") if secret_details else None
                )
                return True, error_msg

            elif result.returncode in expected_success_codes:
                # No secrets found by primary engine.
                # For first-match: try remaining engines (Issue #523)
                if (
                    execution_strategy_name == "first-match"
                    and _all_available_engines
                    and len(_all_available_engines) > 1
                ):
                    remaining = [
                        e
                        for e in _all_available_engines
                        if e.type != engine_config.type
                    ]
                    if remaining:
                        logging.info(
                            f"Engine {engine_config.type} found no secrets, "
                            f"trying remaining engines: {[e.type for e in remaining]}"
                        )
                        strategy = get_strategy("first-match")
                        fallback_result = strategy.execute(
                            engine_configs=remaining,
                            scanner_fn=run_engine,
                            source_file=tmp_file_path,
                            report_file_prefix=report_file.replace(".json", ""),
                            config_path=None,
                            context={"filename": filename},
                        )
                        if fallback_result.has_secrets and fallback_result.secrets:
                            # Filter by stopwords/entropy (#1245) — fallthrough path 2
                            if _ext_stopwords or _ext_min_entropy is not None:
                                fallback_result.secrets, _sw_n, _ent_n = (
                                    filter_findings_by_stopwords_entropy(
                                        fallback_result.secrets,
                                        _ext_stopwords,
                                        _ext_min_entropy,
                                    )
                                )
                                if _sw_n or _ent_n:
                                    logging.info(
                                        f"External scanner: filtered {_sw_n} stopword + "
                                        f"{_ent_n} low-entropy findings (fallthrough 2)"
                                    )
                                if not fallback_result.secrets:
                                    logging.info(
                                        "All fallthrough-2 findings filtered by stopwords/entropy — skipping"
                                    )
                                    return False, None

                            # Filter hash false positives (#1378) — fallthrough path 2
                            fallback_result.secrets, _hash_n = filter_findings_by_hash(
                                fallback_result.secrets, content
                            )
                            if _hash_n:
                                logging.info(
                                    f"External scanner: filtered {_hash_n} hash value findings (fallthrough 2)"
                                )
                            if not fallback_result.secrets:
                                logging.info(
                                    "All fallthrough-2 findings filtered as hash values — skipping"
                                )
                                return False, None

                            # Secret liveness validation (Issue #971, #983) — fallthrough path 2
                            fb2_secrets = [
                                {
                                    "rule_id": s.rule_id,
                                    "line_number": s.line_number,
                                    "secret": s.secret,
                                }
                                for s in fallback_result.secrets
                            ]
                            fb2_validation_info, fb2_should_skip = (
                                _run_secret_validation(
                                    secret_config,
                                    fb2_secrets,
                                    content,
                                    context,
                                )
                            )

                            first_secret = fallback_result.secrets[0]
                            secret_details = {
                                "rule_id": first_secret.rule_id,
                                "file": file_path or filename,
                                "line_number": first_secret.line_number,
                                "end_line": first_secret.end_line or 0,
                                "start_column": first_secret.start_column,
                                "end_column": first_secret.end_column,
                                "commit": first_secret.commit or "N/A",
                                "total_findings": len(fallback_result.secrets),
                                "engine": fallback_result.engine,
                                "category": first_secret.category,
                                "matched_text": first_secret.secret,
                            }
                            if fb2_validation_info:
                                secret_details["validation"] = fb2_validation_info

                            if fb2_should_skip:
                                _log_finding_violation(
                                    file_path or filename,
                                    context,
                                    secret_details,
                                    hook_context=context,
                                )
                                logging.info(
                                    "All secrets validated as inactive (fallthrough 2) — allowing"
                                )
                                return False, None

                            scanner_name = fallback_result.engine
                            fallback_engine_config = next(
                                (e for e in remaining if e.type == scanner_name), None
                            )
                            fallback_resolved = (
                                resolve_engine_config_path(
                                    fallback_engine_config, gitleaks_config_path
                                )
                                if fallback_engine_config
                                else None
                            )
                            fallback_pattern_desc = _describe_patterns(
                                fallback_engine_config,
                                fallback_resolved,
                                config_source,
                                pattern_config if HAS_PATTERN_SERVER else None,
                            )
                            error_msg = _build_secret_detected_message(
                                scanner_name,
                                secret_details,
                                fallback_pattern_desc,
                                "Secret Scanning (first-match fallthrough)",
                            )
                            _log_finding_violation(
                                file_path or filename,
                                context,
                                secret_details,
                                hook_context=context,
                            )
                            logging.error(
                                f"Secret detected (first-match fallthrough): {first_secret.rule_id}"
                            )
                            _last_secret_matched_text = _extract_matched_text_for_ask(
                                secret_details, content
                            )
                            _last_secret_line_number = secret_details.get("line_number")
                            _last_secret_start_column = secret_details.get(
                                "start_column"
                            )
                            return True, error_msg

                return False, None

            else:
                # Unexpected error - analyze and decide whether to block or warn
                logging.warning(
                    f"Gitleaks returned unexpected exit code: {result.returncode}"
                )

                # Extract error details (sanitized - don't log full stderr to avoid leaking secrets)
                stderr_preview = ""
                if result.stderr:
                    # Only log sanitized error info, not full stderr
                    logging.debug(
                        f"Gitleaks stderr present (length: {len(result.stderr)} chars)"
                    )
                    stderr_lines = [
                        line.strip()
                        for line in result.stderr.split("\n")
                        if line.strip()
                    ]
                    if stderr_lines:
                        # Only show first line (error summary), truncated
                        stderr_preview = stderr_lines[0][:200]

                # Check if this is an authentication/authorization error (user can fix)
                is_auth_error = False
                if result.stderr:
                    stderr_lower = result.stderr.lower()
                    is_auth_error = any(
                        keyword in stderr_lower for keyword in _AUTH_ERROR_KEYWORDS
                    )

                # Check if this is a network error (user cannot fix)
                is_network_error = False
                if result.stderr:
                    stderr_lower = result.stderr.lower()
                    is_network_error = any(
                        keyword in stderr_lower for keyword in _NETWORK_ERROR_KEYWORDS
                    )

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

                    on_error = _get_on_scan_error_action()
                    if on_error == ActionMode.BLOCK:
                        logging.error(
                            "Secret scanning error (fail-closed, on_scan_error=block)"
                        )
                        return (
                            True,
                            warning_msg + "\nOperation BLOCKED (on_scan_error=block).",
                        )
                    return False, None

        finally:
            # Secure cleanup: overwrite file before deletion
            if os.path.exists(tmp_file_path):
                try:
                    # Make file writable
                    os.chmod(tmp_file_path, 0o600)

                    # Overwrite with zeros to prevent recovery
                    file_size = os.path.getsize(tmp_file_path)
                    with open(tmp_file_path, "wb") as f:
                        f.write(b"\x00" * file_size)
                        f.flush()
                        os.fsync(f.fileno())

                    # Delete the file
                    os.unlink(tmp_file_path)

                except Exception as cleanup_error:
                    logging.warning(
                        f"Failed to securely cleanup temp file: {cleanup_error}"
                    )
                    # Still try basic deletion
                    try:
                        if os.path.exists(tmp_file_path):
                            os.unlink(tmp_file_path)
                    except Exception:
                        pass  # Silent fail on final cleanup

            # Securely clean up report files (contains scanner findings)
            # Handles both single-engine report and multi-engine strategy report files
            report_files_to_clean = []
            if report_file:
                report_files_to_clean.append(report_file)
                # Multi-engine strategies create per-engine report files
                report_prefix = report_file.replace(".json", "")
                report_files_to_clean.extend(glob.glob(f"{report_prefix}_*.json"))

            for rf_path in report_files_to_clean:
                if os.path.exists(rf_path):
                    try:
                        os.chmod(rf_path, 0o600)
                        file_size = os.path.getsize(rf_path)
                        with open(rf_path, "wb") as f:
                            f.write(b"\x00" * file_size)
                            f.flush()
                            os.fsync(f.fileno())
                        os.unlink(rf_path)
                    except Exception as cleanup_error:
                        logging.debug(
                            f"Failed to securely cleanup report file {rf_path}: {cleanup_error}"
                        )
                        try:
                            if os.path.exists(rf_path):
                                os.unlink(rf_path)
                        except Exception:
                            pass  # intentionally silent — best-effort operation

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


def run_prompt_injection_scan(
    content,
    *,
    config=None,
    file_path=None,
    tool_name=None,
    source_type="file_content",
    latency_timer=None,
):
    """Run prompt injection scan on content.

    Args:
        content: Text to scan for prompt injection.
        config: Pre-loaded PI config dict, or None to load internally.
        file_path: File path associated with the content (for ignore checks).
        tool_name: Tool identifier (for ignore checks).
        source_type: 'user_prompt' or 'file_content' — controls thresholds.
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if scanner unavailable, disabled, or skipped.
        ScanResult with detection details otherwise.
    """
    if not HAS_PROMPT_INJECTION:
        return None
    if not content:
        return None

    now = datetime.now(timezone.utc)
    if config is None:
        config, config_error = _load_prompt_injection_config()
        if config_error:
            logging.warning(f"PI config error: {config_error}")
    if not config or not is_feature_enabled(config.get("enabled"), now, default=True):
        return None

    detector = PromptInjectionDetector(config)
    if latency_timer:
        with latency_timer.check("prompt_injection"):
            should_block, error_msg, detected = detector.detect(
                content,
                file_path=file_path,
                tool_name=tool_name,
                source_type=source_type,
            )
    else:
        should_block, error_msg, detected = detector.detect(
            content,
            file_path=file_path,
            tool_name=tool_name,
            source_type=source_type,
        )

    result = ScanResult.from_prompt_injection(
        should_block=should_block,
        error_message=error_msg,
        detected=detected,
        matched_text=detector.last_matched_text or "",
        matched_pattern=detector.last_matched_pattern or "",
        line_number=detector.last_line_number,
        start_column=detector.last_start_column,
        end_column=detector.last_end_column,
        confidence=detector.last_confidence or 0.0,
        findings=detector.findings if detector.findings else None,
        attack_type=detector.last_attack_type or "",
    )
    result.extra["action"] = config.get("action", "block")
    return result


def run_context_poisoning_scan(
    content,
    *,
    config=None,
    file_path=None,
    tool_name=None,
    tool_identifier=None,
    latency_timer=None,
):
    """Run context poisoning scan on content.

    Args:
        content: Text to scan for context poisoning patterns.
        config: Pre-loaded CP config dict, or None to load internally.
        file_path: File path for ignore checks.
        tool_name: Tool name for ignore checks.
        tool_identifier: Tool identifier for skip checks.
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if scanner unavailable, disabled, or skipped.
        ScanResult with detection details otherwise.
    """
    if not HAS_CONTEXT_POISONING:
        return None
    if not content:
        return None

    now = datetime.now(timezone.utc)
    if config is None:
        config, config_error = _load_context_poisoning_config()
        if config_error:
            logging.warning(f"CP config error: {config_error}")
    if not config or not is_feature_enabled(config.get("enabled"), now, default=True):
        return None

    if _should_skip_context_poisoning(config, tool_identifier, file_path):
        return None

    detector = ContextPoisoningDetector(config)
    if latency_timer:
        with latency_timer.check("context_poisoning"):
            should_block, error_msg, detected = detector.detect(content)
    else:
        should_block, error_msg, detected = detector.detect(content)

    result = ScanResult.from_context_poisoning(
        should_block=should_block,
        error_message=error_msg,
        detected=detected,
        matched_text=detector.last_matched_text or "",
        matched_pattern=detector.last_matched_pattern or "",
        line_number=detector.last_line_number,
        start_column=detector.last_start_column,
        end_column=detector.last_end_column,
        confidence=detector.last_confidence or 0.0,
        findings=(
            detector.findings
            if hasattr(detector, "findings") and detector.findings
            else None
        ),
    )
    result.extra["action"] = config.get("action", "warn")
    return result


def run_supply_chain_scan(
    content,
    file_path,
    *,
    config=None,
    hook_event=None,
    latency_timer=None,
):
    """Run supply chain scan on content.

    Args:
        content: Text to scan for supply chain threats.
        file_path: File path being scanned.
        config: Pre-loaded SC config dict, or None to load internally.
        hook_event: Hook event type (skips on PROMPT).
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if scanner unavailable, disabled, or skipped.
        ScanResult with detection details otherwise.
    """
    if not HAS_SUPPLY_CHAIN:
        return None
    if not content:
        return None
    if hook_event == HookEvent.PROMPT:
        return None

    now = datetime.now(timezone.utc)
    if config is None:
        config, config_error = _load_supply_chain_config()
        if config_error:
            logging.warning(f"Supply chain config error: {config_error}")
    if not config or not is_feature_enabled(config.get("enabled"), now, default=True):
        return None

    scanner = SupplyChainScanner(config)
    scan_path = file_path or "unknown"

    if latency_timer:
        with latency_timer.check("supply_chain"):
            should_block, error_msg, detected = scanner.scan(scan_path, content)
    else:
        should_block, error_msg, detected = scanner.scan(scan_path, content)

    result = ScanResult.from_supply_chain(
        should_block=should_block,
        error_message=error_msg,
        details=(
            {
                "matched_text": scanner.last_matched_text or "",
                "pattern": scanner.last_matched_pattern or "",
                "category": scanner.last_category or "",
                "line_number": scanner.last_line_number,
                "start_column": scanner.last_start_column,
                "end_column": scanner.last_end_column,
            }
            if detected
            else None
        ),
        file_path=scan_path,
    )
    result.extra["action"] = config.get("action", "block")
    return result


def _should_skip_offensive_language_scan(config, tool_identifier=None, file_path=None):
    """Return True if offensive language scan should be skipped for this tool/file."""
    ignore_tools = config.get("ignore_tools", [])
    if tool_identifier and ignore_tools:
        if any(t.lower() in tool_identifier.lower() for t in ignore_tools):
            return True
    if file_path and _matches_ignore_files(file_path, config.get("ignore_files", [])):
        return True
    return False


def run_offensive_language_scan(
    content,
    *,
    config=None,
    file_path=None,
    tool_name=None,
    tool_identifier=None,
    latency_timer=None,
):
    """Run offensive language scan on content.

    Args:
        content: Text to scan.
        config: Pre-loaded scan_offensive config dict, or None to load internally.
        file_path: File path for ignore checks.
        tool_name: Tool name for ignore checks.
        tool_identifier: Tool identifier for skip checks.
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if scanner unavailable, disabled, or skipped.
        ScanResult with detection details otherwise.
    """
    if not HAS_OFFENSIVE_LANGUAGE:
        return None
    if not content:
        return None

    now = datetime.now(timezone.utc)
    if config is None:
        config, config_error = _load_offensive_language_config()
        if config_error:
            logging.warning(f"Offensive language config error: {config_error}")
    if not config or not is_feature_enabled(config.get("enabled"), now, default=False):
        return None

    if _should_skip_offensive_language_scan(config, tool_identifier, file_path):
        return None

    scanner = OffensiveLanguageScanner(config)
    action = config.get("action", "log")

    if latency_timer:
        with latency_timer.check("offensive_language"):
            findings = scanner.scan(content, file_path=file_path)
    else:
        findings = scanner.scan(content, file_path=file_path)

    result = ScanResult.from_offensive_language(
        findings=findings,
        action=action,
        file_path=file_path,
    )
    return result


def _log_canary_detection_violation(
    source: str,
    matched_token: Optional[str] = None,
    matched_text: Optional[str] = None,
    description: Optional[str] = None,
    line_number: Optional[int] = None,
    start_column: Optional[int] = None,
    end_column: Optional[int] = None,
    context: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    violation_logger=None,
):
    """Log a canary token detection violation."""
    if not HAS_VIOLATION_LOGGER:
        return
    try:
        ctx = context or {}
        blocked_entry = {
            "file_path": ctx.get("file_path", source),
            "line_number": line_number,
            "token": matched_token or "unknown",
            "description": description or "canary token",
            "reason": "Canary token detected — possible data exfiltration",
        }
        if start_column is not None:
            blocked_entry["start_column"] = start_column
        if end_column is not None:
            blocked_entry["end_column"] = end_column
        if matched_text:
            blocked_entry["matched_text"] = matched_text[:100]
        violation_logger = violation_logger or ViolationLogger()
        violation_logger.log_violation(
            violation_type=ViolationType.CANARY_DETECTED,
            blocked=blocked_entry,
            context=_build_violation_context(context, hook_context),
            suggestion={
                "action": "investigate_exfiltration",
                "note": (
                    "A registered canary token was detected in AI output. "
                    "This may indicate data exfiltration. Check your canary_detection.tokens config."
                ),
            },
            severity="high",
        )
    except Exception as e:
        logger.error(f"Failed to log canary detection violation: {e}")


def run_canary_detection_scan(
    content,
    source,
    *,
    config=None,
    latency_timer=None,
):
    """Run canary token detection scan on content.

    Args:
        content: Text to scan for canary tokens.
        source: Label for source (file path, tool name, etc.).
        config: Pre-loaded canary_detection config dict, or None to load internally.
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if scanner unavailable, disabled, no tokens configured, or no content.
        ScanResult with detection details otherwise.
    """
    if not HAS_CANARY_DETECTION:
        return None
    if not content:
        return None

    now = datetime.now(timezone.utc)
    if config is None:
        config, config_error = _load_canary_detection_config()
        if config_error:
            logging.warning(f"Canary detection config error: {config_error}")
    if not config or not is_feature_enabled(config.get("enabled"), now, default=False):
        return None
    if not config.get("tokens"):
        return None

    scanner = CanaryTokenScanner(config)

    if latency_timer:
        with latency_timer.check("canary_detection"):
            should_block, error_msg, detected = scanner.scan(content, source)
    else:
        should_block, error_msg, detected = scanner.scan(content, source)

    result = ScanResult.from_canary_detection(
        should_block=should_block,
        error_message=error_msg,
        details=(
            {
                "matched_text": scanner.last_matched_text or "",
                "token": scanner.last_matched_token or "",
                "description": scanner.last_description or "",
                "line_number": scanner.last_line_number,
                "start_column": scanner.last_start_column,
                "end_column": scanner.last_end_column,
            }
            if detected
            else None
        ),
        source=source,
    )
    result.extra["action"] = config.get("action", "block")
    return result


def _log_code_security_violation(
    file_path,
    rule_id,
    description,
    severity,
    line_number=None,
    start_column=None,
    hook_context=None,
    violation_logger=None,
):
    """Log a code security (Bandit) violation."""
    if not HAS_VIOLATION_LOGGER:
        return
    try:
        blocked_entry = {
            "file_path": file_path,
            "rule_id": rule_id,
            "line_number": line_number,
            "severity": severity,
            "reason": description,
        }
        if start_column is not None:
            blocked_entry["start_column"] = start_column
        violation_logger = violation_logger or ViolationLogger()
        violation_logger.log_violation(
            violation_type=ViolationType.CODE_SECURITY,
            blocked=blocked_entry,
            context=_build_violation_context(
                {"file_path": file_path, "hook_event": "pretooluse"},
                hook_context,
            ),
            suggestion={
                "action": "nosec_or_allowlist",
                "note": (
                    f"Suppress with  # nosec {rule_id}  or add to "
                    "code_scanning.allowlist in ai-guardian.json"
                ),
            },
            severity="high" if severity == "HIGH" else "medium",
        )
    except Exception as e:
        logger.error(f"Failed to log code security violation: {e}")


def run_code_security_scan(
    content,
    file_path,
    *,
    config=None,
    latency_timer=None,
):
    """Run Bandit code security scan on Python content.

    Called from PreToolUse on Write/Edit tools when the target file is .py.

    Args:
        content: Python source code to scan (new_string for Edit, content for Write).
        file_path: Target file path.
        config: Pre-loaded code_scanning config dict, or None to load internally.
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if disabled or no Python file.
        ScanResult with detection details otherwise (one entry per finding).
    """
    if not content:
        return None
    if not file_path or not file_path.endswith(".py"):
        return None

    if config is None:
        try:
            from ai_guardian.config_loaders import _load_code_scanning_config

            config, config_error = _load_code_scanning_config()
            if config_error:
                logging.warning(f"Code scanning config error: {config_error}")
        except ImportError:
            try:
                full_cfg, _ = _load_config()
                config = (full_cfg or {}).get("code_scanning", {})
            except Exception:
                config = {}

    if not config or not is_feature_enabled(config.get("enabled"), default=True):
        return None

    from ai_guardian.bandit_scanner import BanditScanner

    scanner = BanditScanner(config)

    if latency_timer:
        with latency_timer.check("code_security"):
            findings = scanner.scan(content, file_path=file_path)
    else:
        findings = scanner.scan(content, file_path=file_path)

    if not findings:
        return ScanResult.clean("code_security", file_path=file_path)

    # Wrap first finding; caller iterates all findings from scanner directly.
    # Store full list in extra for multi-finding consumers.
    first = findings[0]
    result = ScanResult(
        detected=True,
        violation_type="code_security",
        should_block=True,
        error_message=f"[{first.rule_id}] {first.description}",
        rule_id=first.rule_id,
        line_number=first.line_number,
        start_column=first.start_column,
        severity=first.severity,
        file_path=file_path,
        total_findings=len(findings),
    )
    result.extra["action"] = config.get("action", "warn")
    result.extra["all_findings"] = findings
    return result


def run_config_file_scan(
    file_path,
    content,
    *,
    config=None,
    latency_timer=None,
):
    """Run config file exfiltration scan on content.

    Args:
        file_path: File path being scanned.
        content: File content to scan.
        config: Pre-loaded config scanner config, or None to load internally.
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if scanner unavailable, disabled, or skipped.
        ScanResult with detection details otherwise.
    """
    if not HAS_CONFIG_SCANNER:
        return None
    if not file_path or not content:
        return None

    now = datetime.now(timezone.utc)
    if config is None:
        config, config_error = _load_config_scanner_config()
        if config_error:
            logging.warning(f"Config scanner config error: {config_error}")
    is_enabled = is_feature_enabled(
        config.get("enabled") if config else None, now, default=True
    )
    if not is_enabled:
        return None

    if latency_timer:
        with latency_timer.check("config_file_scanning"):
            should_block, error_msg, details = check_config_file_threats(
                file_path, content, config
            )
    else:
        should_block, error_msg, details = check_config_file_threats(
            file_path, content, config
        )

    result = ScanResult.from_config_exfil(
        should_block=should_block,
        error_message=error_msg,
        details=details,
        file_path=file_path,
    )
    result.extra["action"] = config.get("action", "block") if config else "block"
    result.extra["details"] = details
    return result


def run_bash_exfil_scan(
    command,
    *,
    config=None,
    latency_timer=None,
):
    """Run bash command exfiltration scan.

    Args:
        command: Bash command string to scan.
        config: Pre-loaded config scanner config, or None to load internally.
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if scanner unavailable, disabled, or skipped.
        ScanResult with detection details otherwise.
    """
    if not HAS_CONFIG_SCANNER:
        return None
    if not command:
        return None

    now = datetime.now(timezone.utc)
    if config is None:
        config, config_error = _load_config_scanner_config()
        if config_error:
            logging.warning(f"Config scanner config error: {config_error}")
    if not config or not is_feature_enabled(config.get("enabled"), now, default=True):
        return None

    if latency_timer:
        with latency_timer.check("bash_command_exfil_check"):
            should_block, error_msg, details = check_bash_command_threats(
                command, config
            )
    else:
        should_block, error_msg, details = check_bash_command_threats(command, config)

    return ScanResult.from_config_exfil(
        should_block=should_block,
        error_message=error_msg,
        details=details,
    )


def run_exfil_detection_scan(
    command,
    *,
    config=None,
    latency_timer=None,
):
    """Run exfiltration behavior detection scan on a bash command.

    Args:
        command: Bash command string to scan.
        config: Pre-loaded exfil detection config, or None to load internally.
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if scanner unavailable, disabled, or skipped.
        ScanResult with detection details otherwise.
    """
    if not HAS_EXFIL_DETECTION:
        return None
    if not command:
        return None

    now = datetime.now(timezone.utc)
    if config is None:
        config, config_error = _load_exfil_detection_config()
        if config_error:
            logging.warning(f"Exfil detection config error: {config_error}")
    if not config or not is_feature_enabled(config.get("enabled"), now, default=True):
        return None

    if latency_timer:
        with latency_timer.check("exfil_detection"):
            should_block, error_msg, details = ExfilDetectionScanner(
                config
            ).check_command(command)
    else:
        should_block, error_msg, details = ExfilDetectionScanner(config).check_command(
            command
        )

    result = ScanResult.from_exfil_detection(
        should_block=should_block,
        error_message=error_msg,
        details=details,
    )
    result.extra["action"] = config.get("action", "block")
    result.extra["details"] = details
    return result


def run_image_scan(
    file_path,
    *,
    config=None,
    tool_identifier=None,
    latency_timer=None,
):
    """Run image scanning (OCR text extraction) on an image file.

    Args:
        file_path: Path to image file to scan.
        config: Pre-loaded image scanning config, or None to load internally.
        tool_identifier: Tool identifier for ignore checks.
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if scanner unavailable, disabled, skipped, or not an image file.
        Tuple of (extracted_text, image_scan_result) otherwise.
        extracted_text may be empty string if OCR found nothing.
    """
    if not HAS_IMAGE_SCANNER:
        return None
    if not file_path or not ImageDetector.is_image_file(file_path):
        return None

    now = datetime.now(timezone.utc)
    if config is None:
        config, config_error = _load_image_scanning_config()
        if config_error:
            logging.warning(f"Image scanning config error: {config_error}")
    if not config or not is_feature_enabled(
        config.get("enabled", True), now, default=True
    ):
        return None

    ignore_files = config.get("ignore_files", [])
    ignore_tools = config.get("ignore_tools", [])
    if _matches_ignore_files(file_path, ignore_files):
        logging.info(f"Image scanning skipped for {file_path} (ignore pattern match)")
        return None
    if tool_identifier and ignore_tools:
        for pattern in ignore_tools:
            if fnmatch.fnmatch(tool_identifier, pattern):
                logging.info(
                    f"Image scanning skipped for {file_path} (ignore pattern match)"
                )
                return None

    logging.info(f"Image file detected: {file_path}, running OCR scan...")
    with open(file_path, "rb") as f:
        image_data = f.read()

    if latency_timer:
        with latency_timer.check("image_scanning"):
            result = scan_image(image_data, config)
    else:
        result = scan_image(image_data, config)

    logging.info(
        f"OCR extracted {len(result.extracted_text)} chars "
        f"in {result.elapsed_ms:.0f}ms"
    )

    extracted_text = result.extracted_text or ""
    if result.qr_texts:
        qr_text = "\n".join(result.qr_texts)
        extracted_text = f"{extracted_text}\n{qr_text}" if extracted_text else qr_text

    return extracted_text, result


def run_pii_scan(
    content,
    *,
    config=None,
    file_path=None,
    tool_name=None,
    tool_identifier=None,
    latency_timer=None,
):
    """Run PII scan on content.

    Args:
        content: Text to scan for PII.
        config: Pre-loaded PII config dict, or None to load internally.
        file_path: File path for ignore checks and violation context.
        tool_name: Tool name for ignore checks.
        tool_identifier: Tool identifier for skip checks.
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if scanner disabled or skipped.
        ScanResult with redacted_content and redactions if scanned.
    """
    if not content:
        return None

    now = datetime.now(timezone.utc)
    if config is None:
        config, config_error = _load_pii_config()
        if config_error:
            logging.warning(f"PII config error: {config_error}")
    if not config or not is_feature_enabled(config.get("enabled"), now, default=True):
        return None

    if _should_skip_pii_scan(config, tool_identifier, file_path):
        return ScanResult.clean("pii_detected", extra={"skipped": True})

    if latency_timer:
        with latency_timer.check("pii_detection"):
            has_pii, redacted_text, redactions, warning = _scan_for_pii(
                content, config, file_path=file_path
            )
    else:
        has_pii, redacted_text, redactions, warning = _scan_for_pii(
            content, config, file_path=file_path
        )

    result = ScanResult.from_pii_scan(
        has_pii=has_pii,
        redacted_text=redacted_text,
        redactions=redactions,
        warning_message=warning,
        file_path=file_path,
    )
    result.extra["action"] = config.get("action", "block")
    return result


def run_secret_scan(
    content,
    filename="temp_file",
    *,
    config=None,
    context=None,
    file_path=None,
    tool_name=None,
    ignore_files=None,
    ignore_tools=None,
    allowlist_patterns=None,
    latency_timer=None,
):
    """Run secret scan on content using gitleaks/scanner engines.

    Args:
        content: Text to scan for secrets.
        filename: Label for the content being scanned.
        config: Pre-loaded secret scanning config dict, or None to load.
        context: Additional context dict for violation logging.
        file_path: File path for ignore checks.
        tool_name: Tool name for ignore checks.
        ignore_files: Ignore file patterns (extracted from config if None).
        ignore_tools: Ignore tool patterns (extracted from config if None).
        allowlist_patterns: Secret allowlist patterns (extracted from config if None).
        latency_timer: Optional _CheckTimer for performance tracking.

    Returns:
        None if scanner disabled or no content.
        ScanResult with secret detection details otherwise.
    """
    if not content:
        return None

    now = datetime.now(timezone.utc)
    if config is None:
        config, config_error = _load_secret_scanning_config()
        if config_error:
            logging.warning(f"Secret scanning config error: {config_error}")
    if config and not is_feature_enabled(config.get("enabled"), now, default=True):
        return None

    if ignore_files is None:
        ignore_files = config.get("ignore_files", []) if config else []
    if ignore_tools is None:
        ignore_tools = config.get("ignore_tools", []) if config else []
    if allowlist_patterns is None:
        allowlist_patterns = config.get("allowlist_patterns", []) if config else []

    if latency_timer:
        with latency_timer.check("secret_scanning"):
            has_secrets, error_message = check_secrets_with_gitleaks(
                content,
                filename,
                context=context,
                file_path=file_path,
                tool_name=tool_name,
                ignore_files=ignore_files,
                ignore_tools=ignore_tools,
                allowlist_patterns=allowlist_patterns,
                secret_config=config,
            )
    else:
        has_secrets, error_message = check_secrets_with_gitleaks(
            content,
            filename,
            context=context,
            file_path=file_path,
            tool_name=tool_name,
            ignore_files=ignore_files,
            ignore_tools=ignore_tools,
            allowlist_patterns=allowlist_patterns,
            secret_config=config,
        )

    global _last_secret_matched_text, _last_secret_line_number
    global _last_secret_start_column, _last_secret_findings
    result = ScanResult.from_secret_scan(
        has_secrets=has_secrets,
        error_message=error_message,
        matched_text=_last_secret_matched_text or "",
        line_number=_last_secret_line_number,
        start_column=_last_secret_start_column,
        findings=_last_secret_findings if _last_secret_findings else None,
        file_path=file_path,
    )
    result.extra["action"] = config.get("action", "block") if config else "block"
    return result


def run_directory_check(
    file_path,
    *,
    config=None,
):
    """Run directory rules check on a file path.

    Args:
        file_path: File path to check against directory rules.
        config: Pre-loaded config dict, or None to use global config.

    Returns:
        None if no file path provided.
        ScanResult with directory blocking details otherwise.
    """
    if not file_path:
        return None

    decision, action, matched_pattern = _check_directory_rules(file_path, config)
    return ScanResult.from_directory_rules(
        decision=decision,
        action=action,
        matched_pattern=matched_pattern,
        file_path=file_path,
    )


def _run_bootstrap_scan(cwd: str, config=None) -> list:
    """Scan agent config files in cwd for exfiltration threats at session start.

    Called once per session via DaemonState.is_new_session(). Returns a list of
    ScanResult objects for each config file that triggered a detection.
    """
    if not HAS_CONFIG_SCANNER:
        return []

    from ai_guardian.config_scanner import ConfigFileScanner
    from pathlib import Path as _Path

    if config is None:
        config, _ = _load_config_scanner_config()

    scanner = ConfigFileScanner(config)
    cwd_path = _Path(cwd)
    results = []

    for pattern in scanner.DEFAULT_CONFIG_FILES:
        file_path = cwd_path / pattern
        if not file_path.is_file():
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        result = run_config_file_scan(str(file_path), content, config=config)
        if result is not None and result.detected:
            results.append(result)

    return results


def process_hook_data(hook_data, daemon_state=None):
    """
    Process parsed hook data and return response.

    Core processing logic usable by both the direct CLI path and the daemon
    server. Accepts a pre-parsed dict rather than reading from stdin.

    Args:
        hook_data: Parsed JSON hook data dict from IDE
        daemon_state: Optional DaemonState for cross-hook context passing

    Returns:
        dict: Response with 'output' (str or None) and 'exit_code' (int)
              - For Claude Code: output=None, exit_code=0 (allow) or 2 (block)
              - For Cursor: output=JSON string, exit_code=0
    """
    _latency_timer = None
    _latency_event = None
    _latency_tool = ""
    try:
        now = datetime.now(timezone.utc)
        violation_logger = ViolationLogger() if HAS_VIOLATION_LOGGER else None

        # Detect adapter and normalize input in a single pass
        adapter = detect_adapter(hook_data)
        ide_type = adapter.ide_type
        normalized = adapter.normalize_input(hook_data)
        hook_event = normalized.event
        tool_name = None

        # Disable logging for Cursor (it's sensitive to stderr output)
        if ide_type == IDEType.CURSOR:
            logging.disable(logging.CRITICAL)
        else:
            logging.info(
                f"Detected IDE type: {ide_type.value} (adapter: {adapter.name})"
            )
            logging.info(f"Detected hook event: {hook_event}")

        # Use correlation IDs from normalized input
        hook_tool_use_id = normalized.tool_use_id or hook_data.get("tool_use_id")
        hook_session_id = normalized.session_id or hook_data.get("session_id")

        # Allowed findings scoped to this invocation only — prevents Allow Once
        # from persisting to the next hook invocation via daemon_state (#1439).
        _invocation_allowed: set = set()

        # Handle session lifecycle events — early return, no scanning
        if hook_event == HookEvent.SESSION_END:
            return _handle_session_end(
                hook_data, daemon_state, hook_session_id, adapter
            )

        if hook_event == HookEvent.POST_COMPACT:
            try:
                from ai_guardian.session_state import (
                    SessionStateManager,
                    derive_session_key,
                )

                session_key = derive_session_key(hook_data)
                state_mgr = SessionStateManager(daemon_state=daemon_state)
                state_mgr.mark_security_reinject(session_key)
                logging.info(
                    f"PostCompact: flagged session {session_key[:16]}... for security re-injection"
                )
            except Exception as e:
                logging.debug(
                    f"PostCompact: security reinject flag failed (non-fatal): {e}"
                )
            return {"output": None, "exit_code": 0}

        if hook_event == HookEvent.STOP:
            return {"output": None, "exit_code": 0}

        _latency_timer = _CheckTimer(enabled=_is_latency_enabled())
        _latency_event = hook_event

        # Bootstrap scan: scan agent config files on first hook of a new session (#1394)
        if daemon_state:
            try:
                _bs_cwd = get_project_dir()
                if daemon_state.is_new_session(hook_session_id, _bs_cwd):
                    logging.info(
                        f"Bootstrap scan: new session detected (cwd={_bs_cwd})"
                    )
                    _bs_config, _ = _load_config_scanner_config()
                    _bs_results = _run_bootstrap_scan(_bs_cwd, config=_bs_config)
                    for _bs_result in _bs_results:
                        _bs_action = _bs_result.extra.get("action", "block")
                        _bs_file = _bs_result.file_path or _bs_cwd
                        _bs_error = _bs_result.error_message or (
                            "Agent config file contains credential exfiltration pattern"
                        )
                        _bs_details = _bs_result.extra.get("details") or {}
                        logging.warning(
                            f"Bootstrap scan: threat in {_bs_file}: {_bs_error}"
                        )
                        if violation_logger:
                            try:
                                violation_logger.log_violation(
                                    violation_type=ViolationType.CONFIG_FILE_EXFIL,
                                    blocked={
                                        "file_path": _bs_file,
                                        "line_number": _bs_details.get("line_number"),
                                        "reason": _bs_error,
                                        "details": _bs_details,
                                    },
                                    context={
                                        "source": "bootstrap_scan",
                                        "ide_type": (
                                            ide_type.value
                                            if hasattr(ide_type, "value")
                                            else str(ide_type)
                                        ),
                                        "hook_event": hook_event,
                                        "project_path": _bs_cwd,
                                        "session_id": hook_session_id or "",
                                    },
                                    suggestion={
                                        "action": "review_config_file",
                                        "false_positive": (
                                            "Move to examples/ directory, or add to "
                                            "config_file_scanning.ignore_files"
                                        ),
                                    },
                                    severity="critical",
                                )
                            except Exception:
                                pass
                        if _bs_action == "block":
                            return _format_response(
                                adapter,
                                has_secrets=True,
                                error_message=_bs_error,
                                hook_event=hook_event,
                                violation_type=ViolationType.CONFIG_FILE_EXFIL,
                            )
            except Exception as _bs_exc:
                logging.debug(f"Bootstrap scan error (non-fatal): {_bs_exc}")

        # Resolve transcript path from adapter defaults (Issue #935)
        # When hook_data has no transcript_path, agents like Copilot CLI and Codex
        # have known default locations where JSONL transcripts are stored.
        # Inject early so _advance_transcript_position (PostToolUse) sees the path too.
        if not _get_transcript_path(hook_data) and adapter:
            adapter_default_paths = adapter.get_default_transcript_paths()
            if adapter_default_paths:
                hook_data["transcript_path"] = adapter_default_paths[0]
                logging.debug(
                    "Resolved transcript path from %s adapter: %s",
                    adapter.name,
                    adapter_default_paths[0],
                )

        # Create cross-hook context manager for PreToolUse/PostToolUse correlation
        context_mgr = None
        try:
            from ai_guardian.hook_context import HookContextManager

            context_mgr = HookContextManager(
                session_id=hook_session_id, daemon_state=daemon_state
            )
        except Exception as e:
            logging.debug(f"Hook context manager init failed (non-fatal): {e}")

        # Load security instructions for systemMessage injection (#580, #584)
        # Inject only on first prompt per session + after blocks (not every prompt)
        security_message = None
        if ide_type == IDEType.CLAUDE_CODE and hook_event == HookEvent.PROMPT:
            try:
                si_config, si_error = _load_security_instructions_config()
                if si_error:
                    logging.warning(f"Security instructions config error: {si_error}")
                inject = True
                if si_config is not None:
                    inject = is_feature_enabled(
                        si_config.get("inject_on_prompt"), now, default=True
                    )
                if inject:
                    try:
                        from ai_guardian.session_state import (
                            SessionStateManager,
                            derive_session_key,
                        )

                        session_key = derive_session_key(hook_data)
                        state_mgr = SessionStateManager(daemon_state=daemon_state)
                        if state_mgr.should_inject_security(session_key):
                            security_message = _SECURITY_SYSTEM_MESSAGE
                            state_mgr.mark_security_injected(session_key)
                            logging.info(
                                f"Security rules injected for session {session_key[:16]}..."
                            )
                        else:
                            logging.info(
                                f"Security rules already injected for session {session_key[:16]}..., skipping"
                            )
                    except Exception as e:
                        logging.debug(
                            f"Session state check failed, injecting as fallback: {e}"
                        )
                        security_message = _SECURITY_SYSTEM_MESSAGE
            except Exception as e:
                logging.debug(
                    f"Security instructions config load failed (non-fatal): {e}"
                )

        # Handle PostToolUse event - scan tool output before sending to AI
        # Note: PreToolUse does NOT need _advance_transcript_position because
        # every allowed PreToolUse is followed by a PostToolUse that advances
        # past both the PreToolUse and PostToolUse content.  Blocked PreToolUse
        # events add minimal content that is deduplicated on rescan.
        if hook_event == HookEvent.POST_TOOL_USE:
            logging.info("Processing PostToolUse hook...")

            # Extract tool output
            tool_output, tool_name = extract_tool_result(hook_data)
            _latency_tool = tool_name or ""
            logging.info(
                f"PostToolUse: tool_name={tool_name}, has_output={tool_output is not None}"
            )

            if tool_output is None:
                # No output to scan - allow
                _advance_transcript_position(hook_data)
                return _format_response(
                    adapter, has_secrets=False, hook_event=hook_event
                )

            # Create composite tool identifier for more granular ignore patterns
            # This allows ignore_tools to match both PreToolUse (input) and PostToolUse (output)
            # For Skill tool: "Skill:code-review"
            # For MCP tools: already have composite name like "mcp__notebooklm__chat"
            tool_identifier = tool_name

            # Get tool_input from either tool_use.input or tool_input field
            tool_input = {}
            if "tool_use" in hook_data and isinstance(hook_data["tool_use"], dict):
                tool_input = hook_data["tool_use"].get("input", {})
            elif "tool_input" in hook_data and isinstance(
                hook_data["tool_input"], dict
            ):
                tool_input = hook_data["tool_input"]

            if tool_name == "Skill" and tool_input.get("skill"):
                tool_identifier = f"Skill:{tool_input['skill']}"
                logging.info(
                    f"PostToolUse (with output): Created composite identifier {tool_identifier}"
                )

            logging.info(f"PostToolUse tool_identifier: {tool_identifier}")

            # Extract command for Bash tool (for violation context)
            bash_command = None
            if tool_name == "Bash":
                raw_cmd = tool_input.get("command", "")
                if raw_cmd:
                    bash_command = raw_cmd[:500]

            # Load PreToolUse context for cross-hook correlation (#366)
            pretool_ctx = None
            if context_mgr and hook_tool_use_id:
                pretool_ctx = context_mgr.get_pretool_context(hook_tool_use_id)
                if pretool_ctx:
                    logging.info(
                        f"PostToolUse: loaded PreToolUse context for {hook_tool_use_id}"
                    )
                    # Inherit file_path from PreToolUse if not available in PostToolUse
                    if not tool_input.get("file_path") and not tool_input.get("path"):
                        pretool_file = pretool_ctx.get("file_path")
                        if pretool_file:
                            logging.info(
                                f"PostToolUse: inherited file_path={pretool_file}"
                            )

            logging.info(f"Scanning {tool_identifier} output for secrets...")

            # Apply annotation suppression for file-reading tools (Issue #481)
            # If PreToolUse was a file read, annotations in the output should be honored
            # to prevent blocking/redaction of suppressed lines
            post_annotations_config = None
            post_secret_content = None
            post_all_suppressed = set()
            post_secret_suppressed = set()
            original_tool_output = tool_output
            if (
                HAS_ANNOTATIONS
                and pretool_ctx
                and pretool_ctx.get("file_path")
                and tool_output
            ):
                post_annotations_config, _ = _load_annotations_config()
                if post_annotations_config and is_feature_enabled(
                    post_annotations_config.get("enabled"), now, default=True
                ):
                    post_all_content, post_secret_content_sup, post_ann_info, _ = (
                        process_annotations(
                            tool_output,
                            file_path=pretool_ctx.get("file_path"),
                            config=post_annotations_config,
                        )
                    )
                    if post_ann_info:
                        tool_output = post_all_content
                        post_secret_content = post_secret_content_sup
                        total_suppressed = sum(
                            len(s.get("lines", [])) for s in post_ann_info
                        )
                        logging.info(
                            f"PostToolUse: annotation suppression applied "
                            f"({total_suppressed} line(s) suppressed)"
                        )

            # Load secret scanning config for ignore lists
            secret_config, config_error = _load_secret_scanning_config()

            # If config has errors, log warning and continue with defaults
            # (ignore lists default to [] when secret_config is None)
            if config_error:
                logging.warning(f"Config error in PostToolUse: {config_error}")

            # Check if secret scanning is enabled (respect disabled_until)
            if secret_config and not is_feature_enabled(
                secret_config.get("enabled", True), now, default=True
            ):
                logging.info("Secret scanning is disabled - skipping PostToolUse scan")
                _advance_transcript_position(hook_data)
                return _format_response(
                    adapter, has_secrets=False, hook_event=hook_event
                )

            ignore_files = (
                secret_config.get("ignore_files", []) if secret_config else []
            )
            ignore_tools = (
                secret_config.get("ignore_tools", []) if secret_config else []
            )
            secret_allowlist = (
                secret_config.get("allowlist_patterns", []) if secret_config else []
            )

            # Cross-hook optimization: skip secret scan if PreToolUse already scanned clean (#366)
            pretool_scan = pretool_ctx.get("scan_results", {}) if pretool_ctx else {}
            skip_secret_scan = pretool_scan.get(
                "secrets_scanned"
            ) and not pretool_scan.get("secrets_found")
            if skip_secret_scan:
                logging.info(
                    "PostToolUse: skipping secret scan (PreToolUse already scanned clean)"
                )

            # Cross-hook optimization: respect ignore_files from PreToolUse (#366)
            if pretool_ctx and pretool_ctx.get("ignore_files_matched"):
                logging.info(
                    "PostToolUse: skipping scans (file matched ignore_files in PreToolUse)"
                )
                skip_secret_scan = True

            post_secret_ctx = {
                "ide_type": ide_type.value,
                "hook_event": HookEvent.POST_TOOL_USE,
            }
            if hook_tool_use_id:
                post_secret_ctx["tool_use_id"] = hook_tool_use_id
            if hook_session_id:
                post_secret_ctx["session_id"] = hook_session_id

            if skip_secret_scan:
                has_secrets = False
                error_message = None
            else:
                post_scan_content = (
                    post_secret_content
                    if post_secret_content is not None
                    else tool_output
                )
                post_secret_result = run_secret_scan(
                    post_scan_content,
                    f"{tool_identifier}_output",
                    config=secret_config,
                    context=post_secret_ctx,
                    tool_name=tool_identifier,
                    ignore_files=ignore_files,
                    ignore_tools=ignore_tools,
                    allowlist_patterns=secret_allowlist,
                    latency_timer=_latency_timer,
                )
                has_secrets = (
                    post_secret_result.detected if post_secret_result else False
                )
                error_message = (
                    post_secret_result.error_message if post_secret_result else None
                )

            if not has_secrets and error_message:
                # Scanner not available - display warning but allow operation
                _advance_transcript_position(hook_data)
                return _format_response(
                    adapter,
                    has_secrets=False,
                    hook_event=hook_event,
                    warning_message=error_message,
                )

            if has_secrets:
                secret_action = (
                    secret_config.get("action", "block") if secret_config else "block"
                )
                ask_result = _handle_ask_mode_auto(
                    secret_action,
                    ViolationType.SECRET_DETECTED,
                    config_section="secret_scanning",
                    error_msg=error_message,
                    file_path=file_path if "file_path" in dir() else None,
                    matched_text=(
                        post_secret_result.matched_text if post_secret_result else ""
                    ),
                    start_column=(
                        post_secret_result.start_column if post_secret_result else None
                    ),
                    latency_timer=_latency_timer,
                    hook_context={
                        "session_id": hook_session_id,
                        "project_path": get_project_dir(),
                        "hook_event": hook_event,
                        "tool_name": tool_name,
                    },
                    findings=(
                        post_secret_result.findings if post_secret_result else None
                    ),
                )
                logging.debug(f"[ASK-DEBUG] ask_result={ask_result}")
                if ask_result is not None:
                    from ai_guardian.tui.ask_dialog import AskDecision

                    if ask_result.decision not in (
                        AskDecision.BLOCK,
                        AskDecision.BLOCK_ALL,
                    ):
                        _advance_transcript_position(hook_data)
                        info_msg = _format_ask_info_message(
                            ViolationType.SECRET_DETECTED, ask_result.decision
                        )
                        _log_ask_decision(
                            ViolationType.SECRET_DETECTED,
                            ask_result.decision,
                            matched_text=(
                                post_secret_result.matched_text
                                if post_secret_result
                                else ""
                            ),
                            error_msg=error_message or "",
                            file_path=file_path if "file_path" in dir() else None,
                            line_number=(
                                post_secret_result.line_number
                                if post_secret_result
                                else None
                            ),
                            dialog_wait_ms=ask_result.dialog_wait_ms,
                            invocation_allowed_findings=_invocation_allowed,
                        )
                        return _format_response(
                            adapter,
                            has_secrets=False,
                            hook_event=hook_event,
                            warning_message=info_msg,
                        )
                    else:
                        _log_ask_decision(
                            ViolationType.SECRET_DETECTED,
                            ask_result.decision,
                            matched_text=(
                                post_secret_result.matched_text
                                if post_secret_result
                                else ""
                            ),
                            error_msg=error_message or "",
                            file_path=file_path if "file_path" in dir() else None,
                            line_number=(
                                post_secret_result.line_number
                                if post_secret_result
                                else None
                            ),
                            dialog_wait_ms=ask_result.dialog_wait_ms,
                        )
                        result = _format_response(
                            adapter,
                            has_secrets=True,
                            error_message=error_message,
                            hook_event=hook_event,
                            violation_type=ViolationType.SECRET_DETECTED,
                        )
                        _advance_transcript_position(hook_data)
                        return result

                # Check if redaction is enabled
                redaction_config, redaction_error = _load_secret_redaction_config()

                if redaction_error:
                    logging.warning(
                        f"Config error loading secret_redaction: {redaction_error}"
                    )
                    # Fall back to blocking
                    logging.warning(
                        f"Secrets detected in {tool_identifier} output - blocking"
                    )
                    result = _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=error_message,
                        hook_event=hook_event,
                        violation_type=ViolationType.SECRET_DETECTED,
                    )
                    _advance_transcript_position(hook_data)
                    return result

                # Determine action mode (always redact when secrets detected)
                if redaction_config is None:
                    redaction_config = {}

                action = redaction_config.get("action", ActionMode.WARN)
                enabled = redaction_config.get("enabled", True)

                if enabled:
                    # REDACT instead of block
                    logging.info(f"Secret redaction enabled with action={action}")

                    try:
                        from ai_guardian.secret_redactor import SecretRedactor

                        # Also load PII config so secrets+PII are handled in one pass
                        pii_config_for_redactor, _ = _load_pii_config()
                        pii_cfg = (
                            pii_config_for_redactor
                            if pii_config_for_redactor
                            and pii_config_for_redactor.get("enabled", True)
                            else None
                        )
                        redactor = SecretRedactor(redaction_config, pii_config=pii_cfg)
                        with _latency_timer.check("secret_redaction"):
                            result = redactor.redact(tool_output)

                        redacted_text = result["redacted_text"]
                        redactions = result["redactions"]

                        # Restore original content on annotation-suppressed lines
                        if post_all_suppressed or post_secret_suppressed:
                            all_post_suppressed = (
                                post_all_suppressed | post_secret_suppressed
                            )
                            redacted_lines = redacted_text.splitlines()
                            original_lines = original_tool_output.splitlines()
                            for idx in all_post_suppressed:
                                if 0 <= idx < len(redacted_lines) and idx < len(
                                    original_lines
                                ):
                                    redacted_lines[idx] = original_lines[idx]
                            redacted_text = "\n".join(redacted_lines)

                        # Log redaction event
                        logging.warning(
                            f"Redacted {len(redactions)} secret(s) from {tool_identifier} output"
                        )
                        for r in redactions:
                            logging.info(
                                f"  - {r['type']} at position {r['position']} using {r['strategy']}"
                            )

                        # Log to violation logger
                        redaction_file_path = tool_input.get(
                            "file_path"
                        ) or tool_input.get("path")
                        # Inherit file_path from PreToolUse context (#366)
                        if not redaction_file_path and pretool_ctx:
                            redaction_file_path = pretool_ctx.get("file_path")
                        first_line = (
                            redactions[0].get("line_number") if redactions else None
                        )
                        blocked_info = {
                            "tool": tool_identifier,
                            "file_path": redaction_file_path,
                            "line_number": first_line,
                            "redaction_count": len(redactions),
                            "redacted_types": [r["type"] for r in redactions],
                        }
                        if bash_command:
                            blocked_info["command"] = bash_command
                        snippet = _extract_context_snippet(redacted_text, first_line)
                        if snippet:
                            blocked_info["context_snippet"] = snippet
                        ctx = {
                            "action": "redacted",
                            "mode": action,
                            "hook_event": HookEvent.POST_TOOL_USE,
                        }
                        if hook_tool_use_id:
                            ctx["tool_use_id"] = hook_tool_use_id
                        if hook_session_id:
                            ctx["session_id"] = hook_session_id
                        if pretool_ctx:
                            ctx["pretool_context"] = pretool_ctx
                        if violation_logger:
                            violation_logger.log_violation(
                                violation_type=ViolationType.SECRET_REDACTION,
                                blocked=blocked_info,
                                context=ctx,
                            )

                        # Return redacted output (allow, with modifications)
                        # For warn mode, include a warning message
                        warning_msg = None
                        if action == ActionMode.WARN:
                            warning_msg = (
                                f"⚠️  Redacted {len(redactions)} secret(s) from output:\n"
                                + "\n".join(
                                    [f"  - {r['type']}" for r in redactions[:5]]
                                )
                                + ("\n  - ..." if len(redactions) > 5 else "")
                            )
                            logging.warning(f"WARN mode: {warning_msg}")

                        logging.info("✓ Secrets redacted, allowing output to continue")
                        result = _format_response(
                            adapter,
                            has_secrets=False,
                            hook_event=hook_event,
                            warning_message=warning_msg,
                            modified_output=redacted_text,
                        )
                        result["_warning"] = True
                        result["_violation_type"] = ViolationType.SECRET_REDACTION
                        _advance_transcript_position(hook_data)
                        return result

                    except Exception as redact_error:
                        logging.error(f"Error during secret redaction: {redact_error}")
                        import traceback

                        logging.error(traceback.format_exc())
                        # Fall back to blocking on redaction errors
                        logging.warning("Redaction failed, falling back to blocking")
                        result = _format_response(
                            adapter,
                            has_secrets=True,
                            error_message=error_message,
                            hook_event=hook_event,
                            violation_type=ViolationType.SECRET_REDACTION,
                        )
                        _advance_transcript_position(hook_data)
                        return result
                else:
                    # Redaction disabled - block to prevent secrets from reaching AI model
                    logging.warning(
                        "Secrets detected and redaction disabled - blocking output"
                    )
                    result = _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=error_message,
                        hook_event=hook_event,
                        violation_type=ViolationType.SECRET_DETECTED,
                    )
                    _advance_transcript_position(hook_data)
                    return result

            logging.info(f"✓ No secrets detected in {tool_identifier} output")

            # PII scanning in PostToolUse (Issue #262)
            pii_file_path = tool_input.get("file_path") or tool_input.get("path")
            if not pii_file_path and pretool_ctx:
                pii_file_path = pretool_ctx.get("file_path")

            # Cross-hook optimization: skip PII scan if PreToolUse skipped via ignore_files (#366)
            pii_skip_from_pretool = (
                pretool_ctx
                and pretool_ctx.get("scan_results", {}).get("pii_skipped_reason")
                == "ignore_files match"
            )
            if not pii_skip_from_pretool:
                logging.info("Scanning tool output for PII...")
                post_pii_result = run_pii_scan(
                    tool_output,
                    file_path=pii_file_path,
                    tool_identifier=tool_identifier,
                    latency_timer=_latency_timer,
                )

                if post_pii_result is not None and not post_pii_result.extra.get(
                    "skipped"
                ):
                    has_pii = post_pii_result.detected
                    redacted_text = post_pii_result.redacted_content
                    pii_redactions = post_pii_result.redactions
                    pii_warning = post_pii_result.error_message

                    # Scan error with on_scan_error=block: block without logging a false violation (#507)
                    if has_pii and not pii_redactions:
                        result = _format_response(
                            adapter,
                            has_secrets=True,
                            hook_event=hook_event,
                            error_message=pii_warning,
                            violation_type=ViolationType.PII_DETECTED,
                        )
                        _advance_transcript_position(hook_data)
                        return result

                    if has_pii and pii_redactions:
                        if not pii_file_path:
                            pii_file_path = _extract_file_path_from_pii_warning(
                                pii_warning
                            )
                        pii_snippet_text = (
                            redacted_text if redacted_text else tool_output
                        )
                        post_pii_config, _ = _load_pii_config()
                        pii_action, pii_types = _log_pii_violation(
                            violation_logger,
                            post_pii_config
                            or {"action": post_pii_result.extra.get("action", "block")},
                            pii_redactions,
                            tool_identifier,
                            "PostToolUse",
                            pii_file_path,
                            pii_snippet_text,
                            HookEvent.POST_TOOL_USE,
                            hook_tool_use_id=hook_tool_use_id,
                            hook_session_id=hook_session_id,
                            bash_command=bash_command,
                            pretool_ctx=pretool_ctx,
                        )
                        logging.warning(
                            f"PII detected in {tool_identifier} output: {pii_types}"
                        )

                        # Build multi-finding list from PII redactions
                        pii_matched_text = _extract_pii_matched_text(
                            pii_redactions, tool_output
                        )
                        pii_findings = _pii_redactions_to_findings(
                            pii_redactions, tool_output, pii_warning
                        )

                        # Check ask action mode before standard routing
                        pii_line_number = (
                            pii_redactions[0].get("line_number")
                            if pii_redactions
                            else None
                        )
                        pii_ask_result = _handle_ask_mode_auto(
                            pii_action,
                            ViolationType.PII_DETECTED,
                            config_section="scan_pii",
                            error_msg=pii_warning,
                            file_path=pii_file_path,
                            matched_text=pii_matched_text,
                            line_number=pii_line_number,
                            latency_timer=_latency_timer,
                            hook_context={
                                "session_id": hook_session_id,
                                "project_path": get_project_dir(),
                                "hook_event": hook_event,
                                "tool_name": tool_name,
                            },
                            findings=pii_findings,
                        )
                        if pii_ask_result is not None:
                            from ai_guardian.tui.ask_dialog import AskDecision

                            if pii_ask_result.decision not in (
                                AskDecision.BLOCK,
                                AskDecision.BLOCK_ALL,
                            ):
                                pii_action = "warn"
                                pii_info_msg = _format_ask_info_message(
                                    ViolationType.PII_DETECTED, pii_ask_result.decision
                                )
                                warning_messages.append(pii_info_msg)
                                _log_ask_decision(
                                    ViolationType.PII_DETECTED,
                                    pii_ask_result.decision,
                                    matched_text=pii_matched_text,
                                    error_msg=pii_warning or "",
                                    file_path=pii_file_path,
                                    line_number=pii_line_number,
                                    dialog_wait_ms=pii_ask_result.dialog_wait_ms,
                                    invocation_allowed_findings=_invocation_allowed,
                                    finding_fingerprints=_compute_pii_transcript_fingerprints(
                                        pii_redactions, tool_output
                                    ),
                                )
                            else:
                                pii_action = "block"
                                _log_ask_decision(
                                    ViolationType.PII_DETECTED,
                                    pii_ask_result.decision,
                                    matched_text=pii_matched_text,
                                    error_msg=pii_warning or "",
                                    file_path=pii_file_path,
                                    line_number=pii_line_number,
                                    dialog_wait_ms=pii_ask_result.dialog_wait_ms,
                                )

                        if pii_action == "block":
                            result = _format_response(
                                adapter,
                                has_secrets=True,
                                hook_event=hook_event,
                                error_message=pii_warning,
                                violation_type=ViolationType.PII_DETECTED,
                            )
                            _advance_transcript_position(hook_data)
                            return result
                        elif pii_action == "redact":
                            # Restore original content on annotation-suppressed lines
                            if post_all_suppressed:
                                pii_redacted_lines = redacted_text.splitlines()
                                pii_original_lines = original_tool_output.splitlines()
                                for idx in post_all_suppressed:
                                    if 0 <= idx < len(pii_redacted_lines) and idx < len(
                                        pii_original_lines
                                    ):
                                        pii_redacted_lines[idx] = pii_original_lines[
                                            idx
                                        ]
                                redacted_text = "\n".join(pii_redacted_lines)
                            result = _format_response(
                                adapter,
                                has_secrets=False,
                                hook_event=hook_event,
                                warning_message=pii_warning,
                                modified_output=redacted_text,
                            )
                            result["_warning"] = True
                            result["_violation_type"] = ViolationType.PII_DETECTED
                            _advance_transcript_position(hook_data)
                            return result
                        elif pii_action == "warn":
                            result = _format_response(
                                adapter,
                                has_secrets=False,
                                hook_event=hook_event,
                                warning_message=pii_warning,
                            )
                            result["_warning"] = True
                            result["_violation_type"] = ViolationType.PII_DETECTED
                            _advance_transcript_position(hook_data)
                            return result
                        elif pii_action == "log-only":
                            result = _format_response(
                                adapter, has_secrets=False, hook_event=hook_event
                            )
                            result["_log_only"] = 1
                            result["_violation_type"] = ViolationType.PII_DETECTED
                            _advance_transcript_position(hook_data)
                            return result
                        else:
                            logging.warning(
                                f"Unknown PII action '{pii_action}', allowing through"
                            )
                            _advance_transcript_position(hook_data)
                            return _format_response(
                                adapter, has_secrets=False, hook_event=hook_event
                            )

            # Prompt injection and context poisoning scanning on PostToolUse output (#1285)
            post_warning_messages = []
            post_pi_cp_filename = (
                f"{tool_identifier}_output" if tool_identifier else "tool_output"
            )
            if tool_output:
                try:
                    # Cross-hook optimization: skip if PreToolUse already scanned clean (#366)
                    post_pi_skip = pretool_scan.get(
                        "prompt_injection_scanned"
                    ) and not pretool_scan.get("prompt_injection_found")
                    if pretool_ctx and pretool_ctx.get("ignore_files_matched"):
                        post_pi_skip = True

                    if post_pi_skip:
                        logging.info(
                            "PostToolUse: skipping PI scan (PreToolUse already scanned clean)"
                        )
                    else:
                        post_pi_file = tool_input.get("file_path") or tool_input.get(
                            "path"
                        )
                        if not post_pi_file and pretool_ctx:
                            post_pi_file = pretool_ctx.get("file_path")

                        post_pi_result = run_prompt_injection_scan(
                            tool_output,
                            file_path=post_pi_file,
                            tool_name=tool_identifier,
                            latency_timer=_latency_timer,
                        )

                        if post_pi_result is not None:
                            post_pi_detected = post_pi_result.detected
                            post_pi_block = post_pi_result.should_block
                            post_pi_error_msg = post_pi_result.error_message

                            if post_pi_detected:
                                post_pi_hook_ctx = {
                                    "hook_event": hook_event,
                                    "tool_name": tool_name,
                                }
                                if hook_tool_use_id:
                                    post_pi_hook_ctx["tool_use_id"] = hook_tool_use_id
                                if hook_session_id:
                                    post_pi_hook_ctx["session_id"] = hook_session_id
                                _log_prompt_injection_violation(
                                    post_pi_cp_filename,
                                    context={
                                        "ide_type": ide_type.value,
                                        "hook_event": hook_event,
                                        "file_path": post_pi_file,
                                    },
                                    attack_type=post_pi_result.attack_type,
                                    hook_context=(
                                        post_pi_hook_ctx if post_pi_hook_ctx else None
                                    ),
                                    matched_pattern=post_pi_result.matched_pattern,
                                    matched_text=post_pi_result.matched_text,
                                    confidence=post_pi_result.confidence,
                                    line_number=post_pi_result.line_number,
                                    start_column=post_pi_result.start_column,
                                    end_column=post_pi_result.end_column,
                                )

                            if post_pi_block:
                                post_pi_action = post_pi_result.extra.get(
                                    "action", "block"
                                )
                                post_pi_ask = _handle_ask_mode_auto(
                                    post_pi_action,
                                    ViolationType.PROMPT_INJECTION,
                                    config_section="prompt_injection",
                                    error_msg=post_pi_error_msg,
                                    file_path=post_pi_file,
                                    matched_text=post_pi_result.matched_text,
                                    line_number=post_pi_result.line_number,
                                    matched_pattern=post_pi_result.matched_pattern,
                                    latency_timer=_latency_timer,
                                    hook_context={
                                        "session_id": hook_session_id,
                                        "project_path": get_project_dir(),
                                        "hook_event": hook_event,
                                        "tool_name": tool_name,
                                    },
                                    findings=post_pi_result.findings,
                                )
                                if post_pi_ask is not None:
                                    from ai_guardian.tui.ask_dialog import AskDecision

                                    if post_pi_ask.decision not in (
                                        AskDecision.BLOCK,
                                        AskDecision.BLOCK_ALL,
                                    ):
                                        pi_info = _format_ask_info_message(
                                            ViolationType.PROMPT_INJECTION,
                                            post_pi_ask.decision,
                                        )
                                        post_warning_messages.append(pi_info)
                                        post_pi_block = False
                                        _log_ask_decision(
                                            ViolationType.PROMPT_INJECTION,
                                            post_pi_ask.decision,
                                            matched_text=post_pi_result.matched_text,
                                            error_msg=post_pi_error_msg or "",
                                            file_path=post_pi_file,
                                            line_number=post_pi_result.line_number,
                                            dialog_wait_ms=post_pi_ask.dialog_wait_ms,
                                        )

                                if post_pi_block:
                                    logging.info(
                                        "PostToolUse: blocking due to prompt injection"
                                    )
                                    result = _format_response(
                                        adapter,
                                        has_secrets=True,
                                        error_message=post_pi_error_msg,
                                        hook_event=hook_event,
                                        violation_type=ViolationType.PROMPT_INJECTION,
                                    )
                                    _advance_transcript_position(hook_data)
                                    return result
                            elif post_pi_detected and post_pi_error_msg:
                                post_warning_messages.append(post_pi_error_msg)

                            if not post_pi_detected:
                                logging.info(
                                    "PostToolUse: no prompt injection detected in output"
                                )
                except Exception as e:
                    on_error = _get_on_scan_error_action()
                    if on_error == ActionMode.BLOCK:
                        logging.error(f"PostToolUse PI check error (fail-closed): {e}")
                        result = _format_response(
                            adapter,
                            has_secrets=True,
                            hook_event=hook_event,
                            error_message=f"PostToolUse prompt injection check failed (blocked): {e}",
                            violation_type=ViolationType.PROMPT_INJECTION,
                        )
                        _advance_transcript_position(hook_data)
                        return result
                    logging.warning(f"PostToolUse PI check error (fail-open): {e}")

            # Context poisoning scanning on PostToolUse output (#1285)
            if tool_output:
                try:
                    # Cross-hook optimization: skip if PreToolUse already scanned clean
                    post_cp_skip = pretool_scan.get(
                        "context_poisoning_scanned"
                    ) and not pretool_scan.get("context_poisoning_found")
                    if pretool_ctx and pretool_ctx.get("ignore_files_matched"):
                        post_cp_skip = True

                    if post_cp_skip:
                        logging.info(
                            "PostToolUse: skipping CP scan (PreToolUse already scanned clean)"
                        )
                    else:
                        post_cp_file = tool_input.get("file_path") or tool_input.get(
                            "path"
                        )
                        if not post_cp_file and pretool_ctx:
                            post_cp_file = pretool_ctx.get("file_path")

                        post_cp_result = run_context_poisoning_scan(
                            tool_output,
                            file_path=post_cp_file,
                            tool_identifier=tool_identifier,
                            latency_timer=_latency_timer,
                        )

                        if post_cp_result is not None:
                            post_cp_detected = post_cp_result.detected
                            post_cp_block = post_cp_result.should_block
                            post_cp_error_msg = post_cp_result.error_message

                            if post_cp_detected:
                                post_cp_hook_ctx = {
                                    "hook_event": hook_event,
                                    "tool_name": tool_name,
                                }
                                if hook_tool_use_id:
                                    post_cp_hook_ctx["tool_use_id"] = hook_tool_use_id
                                if hook_session_id:
                                    post_cp_hook_ctx["session_id"] = hook_session_id
                                _log_context_poisoning_violation(
                                    post_pi_cp_filename,
                                    context={
                                        "ide_type": ide_type.value,
                                        "hook_event": hook_event,
                                        "file_path": post_cp_file,
                                    },
                                    hook_context=(
                                        post_cp_hook_ctx if post_cp_hook_ctx else None
                                    ),
                                    matched_pattern=post_cp_result.matched_pattern,
                                    matched_text=post_cp_result.matched_text,
                                    confidence=post_cp_result.confidence,
                                    line_number=post_cp_result.line_number,
                                    start_column=post_cp_result.start_column,
                                    end_column=post_cp_result.end_column,
                                )

                            if post_cp_block:
                                cp_action = post_cp_result.extra.get("action", "warn")
                                post_cp_ask = _handle_ask_mode_auto(
                                    cp_action,
                                    ViolationType.CONTEXT_POISONING,
                                    config_section="context_poisoning",
                                    error_msg=post_cp_error_msg,
                                    file_path=post_cp_file,
                                    matched_text=post_cp_result.matched_text,
                                    line_number=post_cp_result.line_number,
                                    matched_pattern=post_cp_result.matched_pattern,
                                    latency_timer=_latency_timer,
                                    hook_context={
                                        "session_id": hook_session_id,
                                        "project_path": get_project_dir(),
                                        "hook_event": hook_event,
                                        "tool_name": tool_name,
                                    },
                                )
                                if post_cp_ask is not None:
                                    from ai_guardian.tui.ask_dialog import AskDecision

                                    if post_cp_ask.decision not in (
                                        AskDecision.BLOCK,
                                        AskDecision.BLOCK_ALL,
                                    ):
                                        cp_info = _format_ask_info_message(
                                            ViolationType.CONTEXT_POISONING,
                                            post_cp_ask.decision,
                                        )
                                        post_warning_messages.append(cp_info)
                                        post_cp_block = False
                                        _log_ask_decision(
                                            ViolationType.CONTEXT_POISONING,
                                            post_cp_ask.decision,
                                            matched_text=post_cp_result.matched_text,
                                            error_msg=post_cp_error_msg or "",
                                            file_path=post_cp_file,
                                            line_number=post_cp_result.line_number,
                                            dialog_wait_ms=post_cp_ask.dialog_wait_ms,
                                        )

                                if post_cp_block:
                                    logging.info(
                                        "PostToolUse: blocking due to context poisoning"
                                    )
                                    result = _format_response(
                                        adapter,
                                        has_secrets=True,
                                        error_message=post_cp_error_msg,
                                        hook_event=hook_event,
                                        violation_type=ViolationType.CONTEXT_POISONING,
                                    )
                                    _advance_transcript_position(hook_data)
                                    return result
                            elif post_cp_detected and post_cp_error_msg:
                                post_warning_messages.append(post_cp_error_msg)
                except Exception as e:
                    logging.warning(f"PostToolUse CP check error (fail-open): {e}")

            # Check for offensive language in PostToolUse output
            try:
                post_ol_result = run_offensive_language_scan(
                    tool_output,
                    file_path=post_cp_file if "post_cp_file" in dir() else None,
                    tool_identifier=(
                        tool_identifier if "tool_identifier" in dir() else None
                    ),
                    latency_timer=_latency_timer,
                )
                if post_ol_result is not None and post_ol_result.detected:
                    _log_offensive_language_violation(
                        post_ol_result,
                        hook_name="PostToolUse",
                        hook_event=hook_event,
                        hook_tool_use_id=hook_tool_use_id,
                        hook_session_id=hook_session_id,
                    )
                    post_ol_action = post_ol_result.extra.get("action", "log")
                    post_ol_should_block = post_ol_result.should_block
                    post_ol_error_msg = post_ol_result.error_message
                    post_ol_ask = _handle_ask_mode_auto(
                        post_ol_action,
                        ViolationType.OFFENSIVE_LANGUAGE,
                        config_section="scan_offensive",
                        error_msg=post_ol_error_msg,
                        file_path=post_ol_result.file_path,
                        matched_text=post_ol_result.matched_text,
                        line_number=post_ol_result.line_number,
                        matched_pattern=post_ol_result.matched_pattern,
                        latency_timer=_latency_timer,
                        hook_context={
                            "session_id": hook_session_id,
                            "project_path": get_project_dir(),
                            "hook_event": hook_event,
                        },
                    )
                    if post_ol_ask is not None:
                        from ai_guardian.tui.ask_dialog import AskDecision

                        if post_ol_ask.decision not in (
                            AskDecision.BLOCK,
                            AskDecision.BLOCK_ALL,
                        ):
                            post_ol_should_block = False
                            post_warning_messages.append(
                                _format_ask_info_message(
                                    ViolationType.OFFENSIVE_LANGUAGE,
                                    post_ol_ask.decision,
                                )
                            )
                            _log_ask_decision(
                                ViolationType.OFFENSIVE_LANGUAGE,
                                post_ol_ask.decision,
                                matched_text=post_ol_result.matched_text,
                                error_msg=post_ol_error_msg or "",
                                file_path=post_ol_result.file_path,
                                line_number=post_ol_result.line_number,
                                dialog_wait_ms=post_ol_ask.dialog_wait_ms,
                            )
                    if post_ol_should_block:
                        logging.info(
                            "PostToolUse: blocking due to offensive language detection"
                        )
                        result = _format_response(
                            adapter,
                            has_secrets=True,
                            error_message=post_ol_error_msg,
                            hook_event=hook_event,
                            violation_type=ViolationType.OFFENSIVE_LANGUAGE,
                        )
                        _advance_transcript_position(hook_data)
                        return result
                    elif post_ol_error_msg:
                        post_warning_messages.append(post_ol_error_msg)
            except Exception as e:
                logging.warning(
                    f"PostToolUse offensive language check error (fail-open): {e}"
                )

            _advance_transcript_position(hook_data)
            if post_warning_messages:
                combined = "\n\n".join(post_warning_messages)
                result = _format_response(
                    adapter,
                    has_secrets=False,
                    hook_event=hook_event,
                    warning_message=combined,
                )
                result["_warning"] = True
                result["_violation_type"] = "mixed"
                return result
            return _format_response(adapter, has_secrets=False, hook_event=hook_event)

        # Accumulate warning messages from log mode checks (tool policy, prompt injection, etc.)
        warning_messages = []
        log_only_count = 0

        # Extract tool name for PreToolUse events (needed for permissions and prompt injection)
        tool_name = None
        tool_identifier = (
            None  # Composite identifier like "Skill:code-review" or "mcp__server__tool"
        )
        if hook_event in (HookEvent.PRE_TOOL_USE, HookEvent.BEFORE_READ_FILE):
            tool_name = normalized.tool_name
            tool_input = normalized.tool_input
            _latency_tool = tool_name or ""

            # Normalize mcp: prefix to mcp__ format (agent-agnostic)
            if tool_name and tool_name.startswith("mcp:"):
                tool_name = "mcp__" + tool_name[4:].replace(":", "__")

            # Create composite tool identifier for more granular ignore patterns
            # For Skill tool: "Skill:code-review"
            # For MCP tools: already have composite name like "mcp__notebooklm__chat"
            # For other tools: just use tool_name
            if tool_name == "Skill" and tool_input.get("skill"):
                tool_identifier = f"Skill:{tool_input['skill']}"
            else:
                tool_identifier = tool_name

        # Check tool permissions for PreToolUse events (MCP servers and Skills)
        if (
            hook_event in (HookEvent.PRE_TOOL_USE, HookEvent.BEFORE_READ_FILE)
            and HAS_TOOL_POLICY
        ):
            try:
                permissions_config, config_error = _load_permissions_config()
                if config_error:
                    warning_messages.append(config_error)

                # Check if permissions enforcement is enabled (supports time-based disabling)
                if is_feature_enabled(
                    permissions_config.get("enabled") if permissions_config else None,
                    now,
                    default=True,
                ):
                    policy_checker = ToolPolicyChecker()
                    with _latency_timer.check("permissions"):
                        is_allowed, error_message, checked_tool_name = (
                            policy_checker.check_tool_allowed(hook_data)
                        )

                    if not is_allowed:
                        deny_action = (
                            getattr(policy_checker, "last_deny_action", "block")
                            or "block"
                        )
                        perm_ask_allowed = False

                        if isinstance(deny_action, str) and deny_action.startswith(
                            "ask"
                        ):
                            perm_matched_text = _build_permission_matched_text(
                                tool_name, tool_input, tool_identifier
                            )
                            perm_ask_result = _handle_ask_mode_auto(
                                deny_action,
                                ViolationType.TOOL_PERMISSION,
                                config_section="permissions",
                                error_msg=error_message,
                                matched_text=perm_matched_text,
                                matched_pattern=getattr(
                                    policy_checker, "last_deny_matched_pattern", ""
                                )
                                or "",
                                latency_timer=_latency_timer,
                                hook_context={
                                    "session_id": hook_session_id,
                                    "project_path": get_project_dir(),
                                    "hook_event": hook_event,
                                    "tool_name": tool_name,
                                },
                            )
                            if perm_ask_result is not None:
                                from ai_guardian.tui.ask_dialog import AskDecision

                                if perm_ask_result.decision not in (
                                    AskDecision.BLOCK,
                                    AskDecision.BLOCK_ALL,
                                ):
                                    perm_ask_allowed = True
                                    warning_messages.append(
                                        _format_ask_info_message(
                                            ViolationType.TOOL_PERMISSION,
                                            perm_ask_result.decision,
                                            detail=checked_tool_name,
                                        )
                                    )
                                    _log_ask_decision(
                                        ViolationType.TOOL_PERMISSION,
                                        perm_ask_result.decision,
                                        matched_text=perm_matched_text or "",
                                        error_msg=error_message or "",
                                        dialog_wait_ms=perm_ask_result.dialog_wait_ms,
                                    )

                        if not perm_ask_allowed:
                            # Extract reason summary for logging
                            reason_summary = (
                                _extract_block_reason(error_message)
                                if error_message
                                else "policy violation"
                            )

                            # Extract tool-specific parameters for better logging
                            tool_details = ""
                            if tool_input:
                                if checked_tool_name == "Skill" or (
                                    tool_name == "Skill"
                                    and checked_tool_name.startswith("Skill:")
                                ):
                                    skill_name = tool_input.get("skill", "unknown")
                                    skill_args = tool_input.get("args", "")
                                    args_preview = (
                                        skill_args[:50] + "..."
                                        if len(skill_args) > 50
                                        else skill_args
                                    )
                                    tool_details = f" (skill='{skill_name}', args='{args_preview}')"
                                elif tool_name == "Bash":
                                    command = tool_input.get("command", "")
                                    cmd_preview = (
                                        command[:100] + "..."
                                        if len(command) > 100
                                        else command
                                    )
                                    tool_details = f" (command='{cmd_preview}')"
                                elif tool_name in ["Read", "Write", "Edit"]:
                                    file_path = tool_input.get(
                                        "file_path"
                                    ) or tool_input.get("path", "")
                                    if file_path:
                                        tool_details = f" (file_path='{file_path}')"

                            logging.warning(
                                f"🚨 BLOCKED BY POLICY: Tool '{checked_tool_name}'{tool_details} - {reason_summary}"
                            )
                            combined_warning = (
                                "\n\n".join(warning_messages)
                                if warning_messages
                                else None
                            )
                            result = _format_response(
                                adapter,
                                has_secrets=True,
                                error_message=error_message,
                                hook_event=hook_event,
                                warning_message=combined_warning,
                                violation_type=ViolationType.TOOL_PERMISSION,
                                security_message=security_message,
                            )
                            return result
                    elif is_allowed and error_message:
                        # Log mode: allowed but violation logged - display warning to user
                        logging.warning(
                            f"⚠️  Policy violation (log mode): Tool '{checked_tool_name}' - execution allowed"
                        )
                        # Accumulate warning message to display at the end
                        warning_messages.append(error_message)

                    if checked_tool_name and ide_type != IDEType.CURSOR:
                        logging.info(f"✓ Tool '{checked_tool_name}' allowed by policy")
                elif permissions_config and ide_type != IDEType.CURSOR:
                    # Permissions enforcement is temporarily disabled
                    logging.info(
                        "⚠️  Tool permissions enforcement temporarily disabled"
                    )
            except Exception as e:
                on_error = _get_on_scan_error_action()
                if on_error == ActionMode.BLOCK:
                    logging.error(
                        f"Tool policy check error (fail-closed, on_scan_error=block): {e}"
                    )
                    return _format_response(
                        adapter,
                        has_secrets=True,
                        hook_event=hook_event,
                        error_message=f"Tool policy check failed (blocked by on_scan_error=block): {e}",
                        violation_type=ViolationType.TOOL_PERMISSION,
                        security_message=security_message,
                    )
                logging.warning(f"Tool policy check error (fail-open): {e}")

        content_to_scan = None
        filename = "unknown"
        file_path = None

        if hook_event in (HookEvent.PRE_TOOL_USE, HookEvent.BEFORE_READ_FILE):
            # PreToolUse or beforeReadFile hook
            logging.info(f"Processing {hook_event} hook...")

            # Bash command exfiltration detection (Issue #1100)
            if hook_event == HookEvent.PRE_TOOL_USE and tool_name == "Bash":
                bash_command = tool_input.get("command", "") if tool_input else ""
                if bash_command:
                    bash_exfil_result = run_bash_exfil_scan(
                        bash_command,
                        latency_timer=_latency_timer,
                    )

                    if bash_exfil_result is not None and bash_exfil_result.should_block:
                        exfil_details = bash_exfil_result.extra.get("details")
                        logging.warning(
                            "🚨 BLOCKED: Credential exfiltration detected in Bash command"
                        )

                        if violation_logger:
                            try:
                                exfil_ctx = {
                                    "pattern_name": (
                                        exfil_details.get("pattern_name", "unknown")
                                        if exfil_details
                                        else "unknown"
                                    ),
                                    "pattern_description": (
                                        exfil_details.get("pattern_description", "")
                                        if exfil_details
                                        else ""
                                    ),
                                    "command": bash_command[:500],
                                    "matched_text": (
                                        exfil_details.get("matched_text", "")
                                        if exfil_details
                                        else ""
                                    ),
                                }
                                violation_logger.log_violation(
                                    hook_name="PreToolUse",
                                    tool_identifier=f"Bash: {bash_command[:100]}",
                                    violation_type=ViolationType.CONFIG_FILE_EXFIL,
                                    pattern_name=exfil_ctx["pattern_name"],
                                    action=ActionMode.BLOCK,
                                    context=exfil_ctx,
                                    hook_session_id=hook_session_id,
                                    hook_tool_use_id=hook_tool_use_id,
                                )
                            except Exception as e:
                                logging.warning(
                                    f"Failed to log bash exfil violation: {e}"
                                )

                        combined_warning = (
                            "\n\n".join(warning_messages) if warning_messages else None
                        )
                        result = _format_response(
                            adapter,
                            has_secrets=True,
                            error_message=bash_exfil_result.error_message,
                            hook_event=hook_event,
                            warning_message=combined_warning,
                            violation_type=ViolationType.CONFIG_FILE_EXFIL,
                            security_message=security_message,
                        )
                        return result

                    # Exfiltration behavior detection (Issue #1393)
                    exfil_detection_result = run_exfil_detection_scan(
                        bash_command,
                        latency_timer=_latency_timer,
                    )

                    if (
                        exfil_detection_result is not None
                        and exfil_detection_result.should_block
                    ):
                        ed_details = exfil_detection_result.extra.get("details") or {}
                        logging.warning(
                            "🚨 BLOCKED: Credential exfiltration behavior detected"
                        )
                        _log_exfil_detection_violation(
                            command=bash_command,
                            matched_pattern=ed_details.get("pattern"),
                            matched_text=ed_details.get("matched_text"),
                            category=ed_details.get("category"),
                            line_number=ed_details.get("line_number"),
                            start_column=ed_details.get("start_column"),
                            end_column=ed_details.get("end_column"),
                            violation_logger=violation_logger,
                        )
                        combined_warning = (
                            "\n\n".join(warning_messages) if warning_messages else None
                        )
                        result = _format_response(
                            adapter,
                            has_secrets=True,
                            error_message=exfil_detection_result.error_message,
                            hook_event=hook_event,
                            warning_message=combined_warning,
                            violation_type=ViolationType.EXFIL_DETECTION,
                            security_message=security_message,
                        )
                        return result

            # Only extract file content for file-reading tools
            # Bash, Write, Edit, etc. don't read files in PreToolUse - they have command/content parameters
            # Bug #94: Bash commands were incorrectly treated as file paths
            # Bug #174: Glob removed - uses 'pattern' parameter, not 'file_path', doesn't read content in PreToolUse
            if (
                tool_name in FILE_READING_TOOLS
                or hook_event == HookEvent.BEFORE_READ_FILE
            ):
                # Extract file content for tools that read files
                with _latency_timer.check("directory_rules"):
                    (
                        content_to_scan,
                        filename,
                        file_path,
                        is_denied,
                        deny_reason,
                        dir_warning,
                    ) = extract_file_content_from_tool(hook_data)

                # Check if directory access is denied
                if is_denied:
                    dir_action = _get_directory_action_from_config()
                    dir_ask_result = _handle_ask_mode_auto(
                        dir_action,
                        ViolationType.DIRECTORY_BLOCKING,
                        config_section="directory_rules",
                        error_msg=deny_reason,
                        file_path=file_path,
                        matched_text=file_path or "",
                        latency_timer=_latency_timer,
                        hook_context={
                            "session_id": hook_session_id,
                            "project_path": get_project_dir(),
                            "hook_event": hook_event,
                            "tool_name": tool_name,
                        },
                    )
                    if dir_ask_result is not None:
                        from ai_guardian.tui.ask_dialog import AskDecision

                        if dir_ask_result.decision not in (
                            AskDecision.BLOCK,
                            AskDecision.BLOCK_ALL,
                        ):
                            is_denied = False
                            warning_messages.append(
                                _format_ask_info_message(
                                    ViolationType.DIRECTORY_BLOCKING,
                                    dir_ask_result.decision,
                                    detail=file_path,
                                )
                            )
                            _log_ask_decision(
                                ViolationType.DIRECTORY_BLOCKING,
                                dir_ask_result.decision,
                                matched_text=file_path or "",
                                error_msg=deny_reason or "",
                                file_path=file_path,
                                dialog_wait_ms=dir_ask_result.dialog_wait_ms,
                            )

                if is_denied:
                    logging.warning(f"Directory access denied for file '{file_path}'")
                    combined_warning = (
                        "\n\n".join(warning_messages) if warning_messages else None
                    )
                    result = _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=deny_reason,
                        hook_event=hook_event,
                        warning_message=combined_warning,
                        violation_type=ViolationType.DIRECTORY_BLOCKING,
                        security_message=security_message,
                    )
                    return result
                elif dir_warning:
                    # Log mode: directory violation detected but execution allowed
                    # Accumulate warning message to display at the end
                    warning_messages.append(dir_warning)

                # Skip scanning ai-guardian's own test files (contain example secrets)
                # IMPORTANT: Only skips ai-guardian tests, not user project tests
                if file_path and _is_ai_guardian_test_file(file_path):
                    logging.debug(
                        f"Skipping scan for ai-guardian test file: {file_path}"
                    )

                    combined_warning = (
                        "\n\n".join(warning_messages) if warning_messages else None
                    )
                    return _format_response(
                        adapter,
                        has_secrets=False,
                        hook_event=hook_event,
                        warning_message=combined_warning,
                        security_message=security_message,
                    )

                if content_to_scan is None:
                    # Could not extract file content - allow operation (fail-open)
                    logging.warning(
                        "Could not extract file content, allowing operation"
                    )

                    combined_warning = (
                        "\n\n".join(warning_messages) if warning_messages else None
                    )
                    return _format_response(
                        adapter,
                        has_secrets=False,
                        hook_event=hook_event,
                        warning_message=combined_warning,
                        security_message=security_message,
                    )

                # Image scanning: if file is an image, extract text via OCR (Issue #720)
                is_image_file = False
                image_scan_result = None
                if (
                    HAS_IMAGE_SCANNER
                    and file_path
                    and ImageDetector.is_image_file(file_path)
                ):
                    is_image_file = True
                    content_to_scan = None
                    try:
                        img_scan = run_image_scan(
                            file_path,
                            tool_identifier=tool_identifier,
                            latency_timer=_latency_timer,
                        )

                        if img_scan is not None:
                            extracted_text, image_scan_result = img_scan
                            content_to_scan = extracted_text if extracted_text else None

                            if not content_to_scan:
                                logging.info(
                                    "No text extracted from image, allowing through"
                                )
                                combined_warning = (
                                    "\n\n".join(warning_messages)
                                    if warning_messages
                                    else None
                                )
                                return _format_response(
                                    adapter,
                                    has_secrets=False,
                                    hook_event=hook_event,
                                    warning_message=combined_warning,
                                    security_message=security_message,
                                )

                    except Exception as e:
                        on_error = _get_on_scan_error_action()
                        if on_error == ActionMode.BLOCK:
                            logging.error(f"Image scanning error (fail-closed): {e}")
                            return _format_response(
                                adapter,
                                has_secrets=True,
                                hook_event=hook_event,
                                error_message=f"Image scanning failed (blocked by on_scan_error=block): {e}",
                                violation_type=ViolationType.IMAGE_SECRET_DETECTED,
                                security_message=security_message,
                            )
                        logging.warning(f"Image scanning error (fail-open): {e}")
                        combined_warning = (
                            "\n\n".join(warning_messages) if warning_messages else None
                        )
                        return _format_response(
                            adapter,
                            has_secrets=False,
                            hook_event=hook_event,
                            warning_message=combined_warning,
                            security_message=security_message,
                        )

                # Log with full path for debugging false positives
                if file_path:
                    logging.info(
                        f"Scanning file '{filename}' ({file_path}) for secrets..."
                    )
                else:
                    logging.info(f"Scanning file '{filename}' for secrets...")

                # Apply annotation-based suppression (Issue #481)
                # Only for file content (PreToolUse/beforeReadFile), never for prompts or PostToolUse
                secret_content_to_scan = None
                pii_content_to_scan = None
                annotations_config = None
                if HAS_ANNOTATIONS and content_to_scan:
                    annotations_config, ann_config_error = _load_annotations_config()
                    if ann_config_error:
                        warning_messages.append(ann_config_error)

                    if annotations_config and is_feature_enabled(
                        annotations_config.get("enabled"), now, default=True
                    ):
                        (
                            content_all_sup,
                            content_secret_sup,
                            ann_suppressions,
                            ann_warnings,
                        ) = process_annotations(
                            content_to_scan,
                            file_path=file_path,
                            config=annotations_config,
                        )

                        if ann_suppressions:
                            # content_to_scan stays ORIGINAL for prompt injection, jailbreak, config exfil
                            # Suppressed content only used for secrets and PII scanners
                            pii_content_to_scan = content_all_sup
                            secret_content_to_scan = content_secret_sup

                            # Log suppressions for audit trail
                            if violation_logger:
                                try:
                                    ann_ctx = {
                                        "ide_type": ide_type.value,
                                        "hook_event": hook_event,
                                        "file_path": file_path,
                                    }
                                    if hook_tool_use_id:
                                        ann_ctx["tool_use_id"] = hook_tool_use_id
                                    if hook_session_id:
                                        ann_ctx["session_id"] = hook_session_id
                                    violation_logger.log_violation(
                                        violation_type="annotation_suppressed",
                                        blocked={
                                            "file_path": file_path,
                                            "suppressions": ann_suppressions,
                                            "total_lines_suppressed": sum(
                                                len(s.get("lines", []))
                                                for s in ann_suppressions
                                            ),
                                        },
                                        context=ann_ctx,
                                        severity="info",
                                    )
                                except Exception as e:
                                    logging.error(
                                        f"Failed to log annotation suppression: {e}"
                                    )

                        for w in ann_warnings:
                            warning_messages.append(w)
            else:
                # Non-file-reading tool (Bash, Write, Edit, etc.)
                # These tools don't read files in PreToolUse, so no content to scan here
                # They are checked by tool_policy.py for command patterns
                logging.info(
                    f"Tool '{tool_name}' does not read files - skipping file content scan"
                )

                # Save minimal PreToolUse context for correlation (#366)
                if context_mgr and hook_tool_use_id:
                    try:
                        context_mgr.save_pretool_context(
                            hook_tool_use_id,
                            {
                                "file_path": None,
                                "tool_name": tool_identifier or tool_name,
                                "scan_results": {
                                    "secrets_scanned": False,
                                    "secrets_found": False,
                                    "pii_scanned": False,
                                    "pii_skipped_reason": None,
                                    "prompt_injection_scanned": False,
                                    "prompt_injection_found": False,
                                    "context_poisoning_scanned": False,
                                    "context_poisoning_found": False,
                                },
                                "ignore_files_matched": False,
                            },
                        )
                    except Exception:
                        pass  # intentionally silent — best-effort operation

                # Code security scan for Write/Edit writing Python files
                if tool_name in ("Write", "Edit") and isinstance(tool_input, dict):
                    cs_file_path = tool_input.get("file_path", "") or ""
                    if cs_file_path.endswith(".py"):
                        cs_content = (
                            tool_input.get("content", "")
                            if tool_name == "Write"
                            else tool_input.get("new_string", "")
                        )
                        if cs_content:
                            try:
                                cs_config, cs_config_err = _load_code_scanning_config()
                                if cs_config_err:
                                    logging.warning(
                                        f"Code scanning config error: {cs_config_err}"
                                    )
                                cs_result = run_code_security_scan(
                                    cs_content,
                                    cs_file_path,
                                    config=cs_config,
                                    latency_timer=_latency_timer,
                                )
                                if cs_result is not None and cs_result.detected:
                                    all_findings = cs_result.extra.get(
                                        "all_findings", []
                                    )
                                    cs_hook_ctx = {
                                        "hook_event": hook_event,
                                        "tool_name": tool_name,
                                    }
                                    if hook_tool_use_id:
                                        cs_hook_ctx["tool_use_id"] = hook_tool_use_id
                                    if hook_session_id:
                                        cs_hook_ctx["session_id"] = hook_session_id
                                    for f in all_findings:
                                        _log_code_security_violation(
                                            cs_file_path,
                                            rule_id=f.rule_id,
                                            description=f.description,
                                            severity=f.severity,
                                            line_number=f.line_number,
                                            start_column=f.start_column,
                                            hook_context=cs_hook_ctx,
                                        )
                                    cs_action = cs_result.extra.get("action", "warn")
                                    cs_ask_result = _handle_ask_mode_auto(
                                        cs_action,
                                        ViolationType.CODE_SECURITY,
                                        config_section="code_scanning",
                                        error_msg=cs_result.error_message,
                                        file_path=cs_file_path,
                                        matched_text=cs_result.matched_text,
                                        line_number=cs_result.line_number,
                                        matched_pattern=cs_result.rule_id,
                                        latency_timer=_latency_timer,
                                        hook_context={
                                            "session_id": hook_session_id,
                                            "project_path": get_project_dir(),
                                            "hook_event": hook_event,
                                            "tool_name": tool_name,
                                        },
                                    )
                                    cs_should_block = cs_result.should_block
                                    if cs_ask_result is not None:
                                        from ai_guardian.tui.ask_dialog import (
                                            AskDecision,
                                        )

                                        if cs_ask_result.decision not in (
                                            AskDecision.BLOCK,
                                            AskDecision.BLOCK_ALL,
                                        ):
                                            cs_should_block = False
                                            warning_messages.append(
                                                _format_ask_info_message(
                                                    ViolationType.CODE_SECURITY,
                                                    cs_ask_result.decision,
                                                )
                                            )
                                        _log_ask_decision(
                                            ViolationType.CODE_SECURITY,
                                            cs_ask_result.decision,
                                            matched_text=cs_result.matched_text,
                                            error_msg=cs_result.error_message,
                                            file_path=cs_file_path,
                                            line_number=cs_result.line_number,
                                            dialog_wait_ms=cs_ask_result.dialog_wait_ms,
                                        )

                                    if cs_should_block and cs_action == "block":
                                        combined_warning = (
                                            "\n\n".join(warning_messages)
                                            if warning_messages
                                            else None
                                        )
                                        return _format_response(
                                            adapter,
                                            has_secrets=True,
                                            error_message=cs_result.error_message,
                                            hook_event=hook_event,
                                            warning_message=combined_warning,
                                            violation_type=ViolationType.CODE_SECURITY,
                                            security_message=security_message,
                                        )
                                    elif cs_should_block or cs_action in (
                                        "warn",
                                        "log-only",
                                    ):
                                        if cs_action != "log-only":
                                            n = cs_result.total_findings
                                            warning_messages.append(
                                                f"Code security: {n} issue(s) found in "
                                                f"{cs_file_path} — {cs_result.error_message}"
                                            )
                            except Exception as e:
                                logging.warning(
                                    f"Code security check error (fail-open): {e}"
                                )

                # No content to scan for these tools in PreToolUse
                # Allow operation (secret scanning happens for Bash in PostToolUse if enabled)
                combined_warning = (
                    "\n\n".join(warning_messages) if warning_messages else None
                )
                return _format_response(
                    adapter,
                    has_secrets=False,
                    hook_event=hook_event,
                    warning_message=combined_warning,
                    security_message=security_message,
                )

        else:
            # Prompt hook - scan the user's prompt
            logging.info("Processing prompt submission hook...")
            content_to_scan = hook_data.get(
                "prompt", hook_data.get("userMessage", hook_data.get("message", ""))
            )
            filename = "user_prompt"

            if not content_to_scan:
                # No content to check - allow operation
                return _format_response(
                    adapter,
                    has_secrets=False,
                    hook_event=hook_event,
                    security_message=security_message,
                )

            # Image scanning: check for base64-encoded images in prompt (Issue #720)
            if HAS_IMAGE_SCANNER and content_to_scan:
                try:
                    image_bytes_list = ImageDetector.extract_base64_images(
                        content_to_scan
                    )
                except Exception as e:
                    image_bytes_list = []
                    logging.warning(f"Prompt image extraction error (fail-open): {e}")
                if image_bytes_list:
                    img_config, img_config_error = _load_image_scanning_config()
                    if img_config_error:
                        warning_messages.append(img_config_error)
                    if img_config and is_feature_enabled(
                        img_config.get("enabled", True),
                        now,
                        default=True,
                    ):
                        try:
                            for img_bytes in image_bytes_list:
                                with _latency_timer.check("image_scanning"):
                                    img_result = scan_image(img_bytes, img_config)
                                if img_result.extracted_text:
                                    content_to_scan = f"{content_to_scan}\n{img_result.extracted_text}"
                                    logging.info(
                                        f"OCR extracted {len(img_result.extracted_text)} chars from prompt image"
                                    )
                                if img_result.qr_texts:
                                    content_to_scan = (
                                        f"{content_to_scan}\n"
                                        + "\n".join(img_result.qr_texts)
                                    )
                        except Exception as e:
                            logging.warning(
                                f"Prompt image scanning error (fail-open): {e}"
                            )

                    # Strip base64 image data from content before unicode/injection scanning (Issue #1120)
                    content_to_scan = ImageDetector.strip_base64_images(content_to_scan)

            logging.info("Scanning user prompt for secrets...")
            secret_content_to_scan = None  # No annotation processing for prompts
            pii_content_to_scan = None
            annotations_config = None

        # Tracking variables for PreToolUse context saving (#1285)
        _pretool_pi_detected = False
        _pretool_cp_scanned = False
        _pretool_cp_detected = False

        # Check for prompt injection BEFORE scanning for secrets
        try:
            source_type = (
                "user_prompt" if hook_event == HookEvent.PROMPT else "file_content"
            )
            pi_result = run_prompt_injection_scan(
                content_to_scan,
                file_path=file_path,
                tool_name=tool_identifier,
                source_type=source_type,
                latency_timer=_latency_timer,
            )

            if pi_result is not None:
                injection_detected = pi_result.detected
                should_block = pi_result.should_block
                injection_error = pi_result.error_message

                if injection_detected:
                    _pretool_pi_detected = True
                    inj_hook_ctx = {
                        "hook_event": hook_event,
                        "tool_name": tool_name,
                    }
                    if hook_tool_use_id:
                        inj_hook_ctx["tool_use_id"] = hook_tool_use_id
                    if hook_session_id:
                        inj_hook_ctx["session_id"] = hook_session_id
                    _log_prompt_injection_violation(
                        filename,
                        context={
                            "ide_type": ide_type.value,
                            "hook_event": hook_event,
                            "file_path": file_path,
                        },
                        attack_type=pi_result.attack_type,
                        hook_context=inj_hook_ctx if inj_hook_ctx else None,
                        matched_pattern=pi_result.matched_pattern,
                        matched_text=pi_result.matched_text,
                        confidence=pi_result.confidence,
                        line_number=pi_result.line_number,
                        start_column=pi_result.start_column,
                        end_column=pi_result.end_column,
                    )

                if should_block:
                    pi_action = pi_result.extra.get("action", "block")
                    pi_ask_result = _handle_ask_mode_auto(
                        pi_action,
                        ViolationType.PROMPT_INJECTION,
                        config_section="prompt_injection",
                        error_msg=injection_error,
                        file_path=file_path,
                        matched_text=pi_result.matched_text,
                        line_number=pi_result.line_number,
                        matched_pattern=pi_result.matched_pattern,
                        latency_timer=_latency_timer,
                        hook_context={
                            "session_id": hook_session_id,
                            "project_path": get_project_dir(),
                            "hook_event": hook_event,
                            "tool_name": tool_name,
                        },
                        findings=pi_result.findings,
                    )
                    if pi_ask_result is not None:
                        from ai_guardian.tui.ask_dialog import AskDecision

                        if pi_ask_result.decision not in (
                            AskDecision.BLOCK,
                            AskDecision.BLOCK_ALL,
                        ):
                            pi_info_msg = _format_ask_info_message(
                                ViolationType.PROMPT_INJECTION,
                                pi_ask_result.decision,
                            )
                            warning_messages.append(pi_info_msg)
                            should_block = False
                            injection_error = pi_info_msg
                            _log_ask_decision(
                                ViolationType.PROMPT_INJECTION,
                                pi_ask_result.decision,
                                matched_text=pi_result.matched_text,
                                error_msg=injection_error,
                                file_path=file_path,
                                line_number=pi_result.line_number,
                                dialog_wait_ms=pi_ask_result.dialog_wait_ms,
                            )

                if should_block:
                    if ide_type != IDEType.CURSOR:
                        if file_path:
                            logging.info(
                                f"Blocking operation for {file_path} due to prompt injection detection"
                            )
                        else:
                            logging.info(
                                "Blocking operation due to prompt injection detection"
                            )

                    combined_warning = (
                        "\n\n".join(warning_messages) if warning_messages else None
                    )
                    result = _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=injection_error,
                        hook_event=hook_event,
                        warning_message=combined_warning,
                        violation_type=ViolationType.PROMPT_INJECTION,
                        security_message=security_message,
                    )
                    return result
                elif injection_detected and injection_error:
                    warning_messages.append(injection_error)

                if ide_type != IDEType.CURSOR:
                    if not injection_detected:
                        logging.info("✓ No prompt injection detected")
            elif HAS_PROMPT_INJECTION and ide_type != IDEType.CURSOR:
                logging.info("⚠️  Prompt injection detection temporarily disabled")
        except Exception as e:
            on_error = _get_on_scan_error_action()
            if on_error == ActionMode.BLOCK:
                logging.error(
                    f"Prompt injection check error (fail-closed, on_scan_error=block): {e}"
                )
                return _format_response(
                    adapter,
                    has_secrets=True,
                    hook_event=hook_event,
                    error_message=f"Prompt injection check failed (blocked by on_scan_error=block): {e}",
                    violation_type=ViolationType.PROMPT_INJECTION,
                    security_message=security_message,
                )
            logging.warning(f"Prompt injection check error (fail-open): {e}")

        # Check for context poisoning (LLM03) — on both user prompts and file reads
        try:
            cp_result = run_context_poisoning_scan(
                content_to_scan,
                file_path=file_path,
                tool_identifier=tool_identifier,
                latency_timer=_latency_timer,
            )

            if cp_result is not None:
                _pretool_cp_scanned = True
                cp_detected = cp_result.detected
                cp_should_block = cp_result.should_block
                cp_error_msg = cp_result.error_message

                if cp_detected:
                    _pretool_cp_detected = True
                    cp_hook_ctx = {
                        "hook_event": hook_event,
                        "tool_name": tool_name,
                    }
                    if hook_tool_use_id:
                        cp_hook_ctx["tool_use_id"] = hook_tool_use_id
                    if hook_session_id:
                        cp_hook_ctx["session_id"] = hook_session_id
                    _log_context_poisoning_violation(
                        filename,
                        context={
                            "ide_type": ide_type.value,
                            "hook_event": hook_event,
                            "file_path": file_path,
                        },
                        hook_context=cp_hook_ctx if cp_hook_ctx else None,
                        matched_pattern=cp_result.matched_pattern,
                        matched_text=cp_result.matched_text,
                        confidence=cp_result.confidence,
                        line_number=cp_result.line_number,
                        start_column=cp_result.start_column,
                        end_column=cp_result.end_column,
                    )

                if cp_should_block:
                    cp_action = cp_result.extra.get("action", "warn")
                    cp_ask_result = _handle_ask_mode_auto(
                        cp_action,
                        ViolationType.CONTEXT_POISONING,
                        config_section="context_poisoning",
                        error_msg=cp_error_msg,
                        file_path=file_path if "file_path" in dir() else None,
                        matched_text=cp_result.matched_text,
                        line_number=cp_result.line_number,
                        matched_pattern=cp_result.matched_pattern,
                        latency_timer=_latency_timer,
                        hook_context={
                            "session_id": hook_session_id,
                            "project_path": get_project_dir(),
                            "hook_event": hook_event,
                            "tool_name": tool_name,
                        },
                    )
                    if cp_ask_result is not None:
                        from ai_guardian.tui.ask_dialog import AskDecision

                        if cp_ask_result.decision not in (
                            AskDecision.BLOCK,
                            AskDecision.BLOCK_ALL,
                        ):
                            cp_info_msg = _format_ask_info_message(
                                ViolationType.CONTEXT_POISONING,
                                cp_ask_result.decision,
                            )
                            warning_messages.append(cp_info_msg)
                            cp_should_block = False
                            cp_error_msg = cp_info_msg
                            _log_ask_decision(
                                ViolationType.CONTEXT_POISONING,
                                cp_ask_result.decision,
                                matched_text=cp_result.matched_text,
                                error_msg=cp_error_msg,
                                file_path=(file_path if "file_path" in dir() else None),
                                line_number=cp_result.line_number,
                                dialog_wait_ms=cp_ask_result.dialog_wait_ms,
                            )

                if cp_should_block:
                    logging.info(
                        "Blocking operation due to context poisoning detection"
                    )
                    combined_warning = (
                        "\n\n".join(warning_messages) if warning_messages else None
                    )
                    result = _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=cp_error_msg,
                        hook_event=hook_event,
                        warning_message=combined_warning,
                        violation_type=ViolationType.CONTEXT_POISONING,
                        security_message=security_message,
                    )
                    return result
                elif cp_detected and cp_error_msg:
                    warning_messages.append(cp_error_msg)

        except Exception as e:
            logging.warning(f"Context poisoning check error (fail-open): {e}")

        # Check for supply chain threats in agent configuration files
        # Skip on UserPromptSubmit — users legitimately discuss curl install
        # commands, paste docs, and debug curl issues (see #1114)
        try:
            sc_file_path = file_path or filename or "user_prompt"
            sc_result = run_supply_chain_scan(
                content_to_scan,
                sc_file_path,
                hook_event=hook_event,
                latency_timer=_latency_timer,
            )

            if sc_result is not None and sc_result.detected:
                sc_hook_ctx = {"hook_event": hook_event, "tool_name": tool_name}
                if hook_tool_use_id:
                    sc_hook_ctx["tool_use_id"] = hook_tool_use_id
                if hook_session_id:
                    sc_hook_ctx["session_id"] = hook_session_id
                _log_supply_chain_violation(
                    filename,
                    context={
                        "ide_type": ide_type.value,
                        "hook_event": hook_event,
                        "file_path": sc_file_path,
                    },
                    hook_context=sc_hook_ctx if sc_hook_ctx else None,
                    matched_pattern=sc_result.matched_pattern,
                    matched_text=sc_result.matched_text,
                    category=sc_result.attack_type,
                    line_number=sc_result.line_number,
                    start_column=sc_result.start_column,
                    end_column=sc_result.end_column,
                )

                sc_should_block = sc_result.should_block
                sc_error_msg = sc_result.error_message
                sc_action = sc_result.extra.get("action", "block")
                sc_ask_result = _handle_ask_mode_auto(
                    sc_action,
                    ViolationType.SUPPLY_CHAIN,
                    config_section="supply_chain",
                    error_msg=sc_error_msg,
                    file_path=sc_file_path,
                    matched_text=sc_result.matched_text,
                    line_number=sc_result.line_number,
                    matched_pattern=sc_result.matched_pattern,
                    latency_timer=_latency_timer,
                    hook_context={
                        "session_id": hook_session_id,
                        "project_path": get_project_dir(),
                        "hook_event": hook_event,
                        "tool_name": tool_name,
                    },
                )
                if sc_ask_result is not None:
                    from ai_guardian.tui.ask_dialog import AskDecision

                    if sc_ask_result.decision not in (
                        AskDecision.BLOCK,
                        AskDecision.BLOCK_ALL,
                    ):
                        sc_should_block = False
                        warning_messages.append(
                            _format_ask_info_message(
                                ViolationType.SUPPLY_CHAIN,
                                sc_ask_result.decision,
                                detail=sc_file_path,
                            )
                        )
                        _log_ask_decision(
                            ViolationType.SUPPLY_CHAIN,
                            sc_ask_result.decision,
                            matched_text=sc_result.matched_text,
                            error_msg=sc_error_msg or "",
                            file_path=sc_file_path,
                            line_number=sc_result.line_number,
                            dialog_wait_ms=sc_ask_result.dialog_wait_ms,
                        )

                if sc_should_block:
                    logging.info(
                        "Blocking operation due to supply chain threat detection"
                    )
                    combined_warning = (
                        "\n\n".join(warning_messages) if warning_messages else None
                    )
                    result = _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=sc_error_msg,
                        hook_event=hook_event,
                        warning_message=combined_warning,
                        violation_type=ViolationType.SUPPLY_CHAIN,
                        security_message=security_message,
                    )
                    return result
                elif sc_error_msg:
                    warning_messages.append(sc_error_msg)

        except Exception as e:
            logging.warning(f"Supply chain check error (fail-open): {e}")

        # Check for offensive language (profanity, slurs, non-inclusive terms)
        try:
            ol_result = run_offensive_language_scan(
                content_to_scan,
                file_path=file_path,
                tool_identifier=tool_identifier,
                latency_timer=_latency_timer,
            )

            if ol_result is not None and ol_result.detected:
                _log_offensive_language_violation(
                    ol_result,
                    hook_name=hook_name if "hook_name" in dir() else "unknown",
                    hook_event=hook_event,
                    tool_identifier=tool_identifier,
                    hook_tool_use_id=hook_tool_use_id,
                    hook_session_id=hook_session_id,
                )

                ol_action = ol_result.extra.get("action", "log")
                ol_error_msg = ol_result.error_message
                ol_should_block = ol_result.should_block

                ol_ask_result = _handle_ask_mode_auto(
                    ol_action,
                    ViolationType.OFFENSIVE_LANGUAGE,
                    config_section="scan_offensive",
                    error_msg=ol_error_msg,
                    file_path=file_path,
                    matched_text=ol_result.matched_text,
                    line_number=ol_result.line_number,
                    matched_pattern=ol_result.matched_pattern,
                    latency_timer=_latency_timer,
                    hook_context={
                        "session_id": hook_session_id,
                        "project_path": get_project_dir(),
                        "hook_event": hook_event,
                        "tool_name": tool_name,
                    },
                )
                if ol_ask_result is not None:
                    from ai_guardian.tui.ask_dialog import AskDecision

                    if ol_ask_result.decision not in (
                        AskDecision.BLOCK,
                        AskDecision.BLOCK_ALL,
                    ):
                        ol_should_block = False
                        warning_messages.append(
                            _format_ask_info_message(
                                ViolationType.OFFENSIVE_LANGUAGE,
                                ol_ask_result.decision,
                            )
                        )
                        _log_ask_decision(
                            ViolationType.OFFENSIVE_LANGUAGE,
                            ol_ask_result.decision,
                            matched_text=ol_result.matched_text,
                            error_msg=ol_error_msg or "",
                            file_path=file_path,
                            line_number=ol_result.line_number,
                            dialog_wait_ms=ol_ask_result.dialog_wait_ms,
                        )

                if ol_should_block:
                    logging.info(
                        "Blocking operation due to offensive language detection"
                    )
                    combined_warning = (
                        "\n\n".join(warning_messages) if warning_messages else None
                    )
                    result = _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=ol_error_msg,
                        hook_event=hook_event,
                        warning_message=combined_warning,
                        violation_type=ViolationType.OFFENSIVE_LANGUAGE,
                        security_message=security_message,
                    )
                    return result
                elif ol_error_msg:
                    warning_messages.append(ol_error_msg)

        except Exception as e:
            logging.warning(f"Offensive language check error (fail-open): {e}")

        # Check for canary tokens (user-registered tripwire values detecting exfiltration)
        try:
            cd_source = file_path or filename or "content"
            cd_result = run_canary_detection_scan(
                content_to_scan,
                cd_source,
                latency_timer=_latency_timer,
            )

            if cd_result is not None and cd_result.detected:
                cd_hook_ctx = {"hook_event": hook_event, "tool_name": tool_name}
                if hook_tool_use_id:
                    cd_hook_ctx["tool_use_id"] = hook_tool_use_id
                if hook_session_id:
                    cd_hook_ctx["session_id"] = hook_session_id
                _log_canary_detection_violation(
                    cd_source,
                    matched_token=cd_result.matched_pattern,
                    matched_text=cd_result.matched_text,
                    description=cd_result.attack_type,
                    line_number=cd_result.line_number,
                    start_column=cd_result.start_column,
                    end_column=cd_result.end_column,
                    context={
                        "ide_type": ide_type.value,
                        "hook_event": hook_event,
                        "file_path": cd_source,
                    },
                    hook_context=cd_hook_ctx,
                )

                cd_should_block = cd_result.should_block
                cd_error_msg = cd_result.error_message
                cd_action = cd_result.extra.get("action", "block")
                cd_ask_result = _handle_ask_mode_auto(
                    cd_action,
                    ViolationType.CANARY_DETECTED,
                    config_section="canary_detection",
                    error_msg=cd_error_msg,
                    file_path=cd_source,
                    matched_text=cd_result.matched_text,
                    line_number=cd_result.line_number,
                    matched_pattern=cd_result.matched_pattern,
                    latency_timer=_latency_timer,
                    hook_context={
                        "session_id": hook_session_id,
                        "project_path": get_project_dir(),
                        "hook_event": hook_event,
                        "tool_name": tool_name,
                    },
                )
                if cd_ask_result is not None:
                    from ai_guardian.tui.ask_dialog import AskDecision

                    if cd_ask_result.decision not in (
                        AskDecision.BLOCK,
                        AskDecision.BLOCK_ALL,
                    ):
                        cd_should_block = False
                        warning_messages.append(
                            _format_ask_info_message(
                                ViolationType.CANARY_DETECTED,
                                cd_ask_result.decision,
                                detail=cd_source,
                            )
                        )
                        _log_ask_decision(
                            ViolationType.CANARY_DETECTED,
                            cd_ask_result.decision,
                            matched_text=cd_result.matched_text,
                            error_msg=cd_error_msg or "",
                            file_path=cd_source,
                            line_number=cd_result.line_number,
                            dialog_wait_ms=cd_ask_result.dialog_wait_ms,
                        )

                if cd_should_block:
                    logging.info("Blocking operation due to canary token detection")
                    combined_warning = (
                        "\n\n".join(warning_messages) if warning_messages else None
                    )
                    result = _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=cd_error_msg,
                        hook_event=hook_event,
                        warning_message=combined_warning,
                        violation_type=ViolationType.CANARY_DETECTED,
                        security_message=security_message,
                    )
                    return result
                elif cd_error_msg:
                    warning_messages.append(cd_error_msg)

        except Exception as e:
            logging.warning(f"Canary detection check error (fail-open): {e}")

        # Check for config file threats (credential exfiltration patterns in AI config files)
        if (
            hook_event in (HookEvent.PRE_TOOL_USE, HookEvent.BEFORE_READ_FILE)
            and file_path
            and content_to_scan
        ):
            try:
                cfs_result = run_config_file_scan(
                    file_path,
                    content_to_scan,
                    latency_timer=_latency_timer,
                )

                if cfs_result is not None:
                    config_details = cfs_result.extra.get("details")
                    config_error = cfs_result.error_message
                    should_block = cfs_result.should_block

                    if should_block:
                        cfs_action = cfs_result.extra.get("action", "block")
                        cfs_matched_pattern = (
                            config_details.get("pattern_name", "")
                            if config_details
                            else ""
                        )
                        cfs_ask_result = _handle_ask_mode_auto(
                            cfs_action,
                            ViolationType.CONFIG_FILE_EXFIL,
                            config_section="config_file_scanning",
                            error_msg=config_error or "",
                            file_path=file_path,
                            matched_text=file_path,
                            matched_pattern=cfs_matched_pattern,
                            latency_timer=_latency_timer,
                            hook_context={
                                "session_id": hook_session_id,
                                "project_path": get_project_dir(),
                                "hook_event": hook_event,
                                "tool_name": tool_name,
                            },
                        )
                        if cfs_ask_result is not None:
                            from ai_guardian.tui.ask_dialog import AskDecision

                            if cfs_ask_result.decision not in (
                                AskDecision.BLOCK,
                                AskDecision.BLOCK_ALL,
                            ):
                                should_block = False
                                warning_messages.append(
                                    _format_ask_info_message(
                                        ViolationType.CONFIG_FILE_EXFIL,
                                        cfs_ask_result.decision,
                                        detail=file_path,
                                    )
                                )
                                _log_ask_decision(
                                    ViolationType.CONFIG_FILE_EXFIL,
                                    cfs_ask_result.decision,
                                    matched_text=file_path or "",
                                    error_msg=config_error or "",
                                    file_path=file_path,
                                    dialog_wait_ms=cfs_ask_result.dialog_wait_ms,
                                )

                    if should_block:
                        if ide_type != IDEType.CURSOR:
                            logging.info(
                                f"Blocking operation for {file_path} due to config file threat"
                            )

                        if violation_logger:
                            try:
                                exfil_ctx = {
                                    "ide_type": (
                                        ide_type.value
                                        if hasattr(ide_type, "value")
                                        else str(ide_type)
                                    ),
                                    "hook_event": hook_event,
                                    "project_path": get_project_dir(),
                                }
                                if hook_tool_use_id:
                                    exfil_ctx["tool_use_id"] = hook_tool_use_id
                                if hook_session_id:
                                    exfil_ctx["session_id"] = hook_session_id
                                exfil_blocked = {
                                    "file_path": file_path,
                                    "line_number": (
                                        config_details.get("line_number")
                                        if config_details
                                        else None
                                    ),
                                    "reason": config_error,
                                    "details": config_details,
                                }
                                if (
                                    config_details
                                    and config_details.get("start_column") is not None
                                ):
                                    exfil_blocked["start_column"] = config_details[
                                        "start_column"
                                    ]
                                if (
                                    config_details
                                    and config_details.get("end_column") is not None
                                ):
                                    exfil_blocked["end_column"] = config_details[
                                        "end_column"
                                    ]
                                violation_logger.log_violation(
                                    violation_type=ViolationType.CONFIG_FILE_EXFIL,
                                    blocked=exfil_blocked,
                                    context=exfil_ctx,
                                    suggestion={
                                        "action": "review_config_file",
                                        "false_positive": (
                                            "Move to examples/ directory, or add to "
                                            "config_file_scanning.ignore_files"
                                        ),
                                    },
                                    severity="critical",
                                )
                            except Exception as e:
                                logging.error(
                                    f"Failed to log config file exfil violation: {e}"
                                )

                        combined_warning = (
                            "\n\n".join(warning_messages) if warning_messages else None
                        )
                        result = _format_response(
                            adapter,
                            has_secrets=True,
                            error_message=config_error,
                            hook_event=hook_event,
                            warning_message=combined_warning,
                            violation_type=ViolationType.CONFIG_FILE_EXFIL,
                            security_message=security_message,
                        )
                        return result
                    elif config_details and config_error:
                        warning_messages.append(config_error)

                    if ide_type != IDEType.CURSOR:
                        if not config_details:
                            logging.debug("✓ No config file threats detected")
                elif HAS_CONFIG_SCANNER and ide_type != IDEType.CURSOR:
                    logging.info("⚠️  Config file scanning temporarily disabled")
            except Exception as e:
                on_error = _get_on_scan_error_action()
                if on_error == ActionMode.BLOCK:
                    logging.error(
                        f"Config file scanning error (fail-closed, on_scan_error=block): {e}"
                    )
                    return _format_response(
                        adapter,
                        has_secrets=True,
                        hook_event=hook_event,
                        error_message=f"Config file scanning failed (blocked by on_scan_error=block): {e}",
                        violation_type=ViolationType.CONFIG_FILE_EXFIL,
                        security_message=security_message,
                    )
                logging.warning(f"Config file scanning error (fail-open): {e}")

        # Check for secrets in the content
        secret_config, config_error = _load_secret_scanning_config()
        if config_error:
            warning_messages.append(config_error)

        # Check if secret scanning is enabled (supports time-based disabling)
        if is_feature_enabled(
            secret_config.get("enabled") if secret_config else None, now, default=True
        ):
            # Extract ignore lists and allowlist from config
            ignore_files = (
                secret_config.get("ignore_files", []) if secret_config else []
            )
            ignore_tools = (
                secret_config.get("ignore_tools", []) if secret_config else []
            )
            secret_allowlist = (
                secret_config.get("allowlist_patterns", []) if secret_config else []
            )

            pre_secret_ctx = {"ide_type": ide_type.value, "hook_event": hook_event}
            if hook_tool_use_id:
                pre_secret_ctx["tool_use_id"] = hook_tool_use_id
            if hook_session_id:
                pre_secret_ctx["session_id"] = hook_session_id
            secret_scan_content = (
                secret_content_to_scan
                if secret_content_to_scan is not None
                else content_to_scan
            )
            pre_secret_result = run_secret_scan(
                secret_scan_content,
                filename,
                config=secret_config,
                context=pre_secret_ctx,
                file_path=file_path,
                tool_name=tool_identifier,
                ignore_files=ignore_files,
                ignore_tools=ignore_tools,
                allowlist_patterns=secret_allowlist,
                latency_timer=_latency_timer,
            )

            has_secrets = pre_secret_result.detected if pre_secret_result else False
            error_message = (
                pre_secret_result.error_message if pre_secret_result else None
            )

            if not has_secrets and error_message:
                warning_messages.append(error_message)

            if has_secrets:
                secret_action_pre = pre_secret_result.extra.get("action", "block")
                ask_result_pre = _handle_ask_mode_auto(
                    secret_action_pre,
                    ViolationType.SECRET_DETECTED,
                    config_section="secret_scanning",
                    error_msg=error_message,
                    file_path=file_path,
                    matched_text=pre_secret_result.matched_text,
                    start_column=pre_secret_result.start_column,
                    latency_timer=_latency_timer,
                    hook_context={
                        "session_id": hook_session_id,
                        "project_path": get_project_dir(),
                        "hook_event": hook_event,
                        "tool_name": tool_name,
                    },
                    findings=pre_secret_result.findings,
                )
                if ask_result_pre is not None:
                    from ai_guardian.tui.ask_dialog import AskDecision

                    if ask_result_pre.decision not in (
                        AskDecision.BLOCK,
                        AskDecision.BLOCK_ALL,
                    ):
                        info_msg = _format_ask_info_message(
                            ViolationType.SECRET_DETECTED, ask_result_pre.decision
                        )
                        warning_messages.append(info_msg)
                        has_secrets = False
                        _log_ask_decision(
                            ViolationType.SECRET_DETECTED,
                            ask_result_pre.decision,
                            matched_text=pre_secret_result.matched_text,
                            error_msg=error_message or "",
                            file_path=file_path,
                            line_number=pre_secret_result.line_number,
                            dialog_wait_ms=ask_result_pre.dialog_wait_ms,
                            invocation_allowed_findings=_invocation_allowed,
                        )
                    else:
                        _log_ask_decision(
                            ViolationType.SECRET_DETECTED,
                            ask_result_pre.decision,
                            matched_text=pre_secret_result.matched_text,
                            error_msg=error_message or "",
                            file_path=file_path,
                            line_number=pre_secret_result.line_number,
                            dialog_wait_ms=ask_result_pre.dialog_wait_ms,
                        )

            if has_secrets:
                combined_warning = (
                    "\n\n".join(warning_messages) if warning_messages else None
                )
                result = _format_response(
                    adapter,
                    has_secrets=True,
                    error_message=error_message,
                    hook_event=hook_event,
                    warning_message=combined_warning,
                    violation_type=ViolationType.SECRET_DETECTED,
                    security_message=security_message,
                )
                return result

            # No secrets found, allow operation
            if hook_event == HookEvent.PRE_TOOL_USE:
                if file_path:
                    logging.info(
                        f"✓ No secrets detected in file '{filename}' ({file_path})"
                    )
                else:
                    logging.info(f"✓ No secrets detected in file '{filename}'")
            else:
                logging.info("✓ No secrets detected in prompt")
        elif secret_config and ide_type != IDEType.CURSOR:
            # Secret scanning is temporarily disabled
            logging.info("⚠️  Secret scanning temporarily disabled")

        # PII scanning for UserPromptSubmit and PreToolUse (Issue #262)
        pii_was_skipped = False
        if content_to_scan:
            pii_scan_content = (
                pii_content_to_scan
                if pii_content_to_scan is not None
                else content_to_scan
            )
            logging.info(
                f"Scanning {'prompt' if hook_event == HookEvent.PROMPT else filename} for PII..."
            )
            pii_result = run_pii_scan(
                pii_scan_content,
                file_path=file_path,
                tool_identifier=tool_identifier,
                latency_timer=_latency_timer,
            )

            if pii_result is not None and pii_result.extra.get("skipped"):
                pii_was_skipped = True
            elif pii_result is not None and pii_result.detected:
                has_pii = True
                pii_redactions = pii_result.redactions
                pii_warning = pii_result.error_message
                pii_action = pii_result.extra.get("action", "block")

                if has_pii and not pii_redactions:
                    result = _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=pii_warning,
                        hook_event=hook_event,
                        violation_type=ViolationType.PII_DETECTED,
                        security_message=security_message,
                    )
                    return result

                if has_pii and pii_redactions:
                    hook_name = (
                        "UserPromptSubmit"
                        if hook_event == HookEvent.PROMPT
                        else "PreToolUse"
                    )
                    pii_config_for_log, _ = _load_pii_config()
                    pii_action, pii_types = _log_pii_violation(
                        violation_logger,
                        pii_config_for_log or {"action": pii_action},
                        pii_redactions,
                        tool_identifier or filename,
                        hook_name,
                        file_path,
                        content_to_scan,
                        hook_event,
                        hook_tool_use_id=hook_tool_use_id,
                        hook_session_id=hook_session_id,
                    )
                    logging.warning(f"PII detected: {pii_types}")

                    pii_matched_text = _extract_pii_matched_text(
                        pii_redactions, pii_scan_content
                    )
                    pii_findings = _pii_redactions_to_findings(
                        pii_redactions, pii_scan_content, pii_warning
                    )

                    pii_line_number2 = (
                        pii_redactions[0].get("line_number") if pii_redactions else None
                    )
                    pii_file_path2 = file_path
                    if not pii_file_path2:
                        pii_file_path2 = _extract_file_path_from_pii_warning(
                            pii_warning
                        )
                    pii_ask_result2 = _handle_ask_mode_auto(
                        pii_action,
                        ViolationType.PII_DETECTED,
                        config_section="scan_pii",
                        error_msg=pii_warning,
                        file_path=pii_file_path2,
                        matched_text=pii_matched_text,
                        line_number=pii_line_number2,
                        latency_timer=_latency_timer,
                        hook_context={
                            "session_id": hook_session_id,
                            "project_path": get_project_dir(),
                            "hook_event": hook_event,
                            "tool_name": tool_name,
                        },
                        findings=pii_findings,
                    )
                    if pii_ask_result2 is not None:
                        from ai_guardian.tui.ask_dialog import AskDecision

                        if pii_ask_result2.decision not in (
                            AskDecision.BLOCK,
                            AskDecision.BLOCK_ALL,
                        ):
                            pii_action = "warn"
                            _log_ask_decision(
                                ViolationType.PII_DETECTED,
                                pii_ask_result2.decision,
                                matched_text=pii_matched_text,
                                error_msg=pii_warning or "",
                                file_path=pii_file_path2,
                                line_number=pii_line_number2,
                                dialog_wait_ms=pii_ask_result2.dialog_wait_ms,
                                invocation_allowed_findings=_invocation_allowed,
                                finding_fingerprints=_compute_pii_transcript_fingerprints(
                                    pii_redactions, pii_scan_content
                                ),
                            )
                        else:
                            pii_action = "block"
                            _log_ask_decision(
                                ViolationType.PII_DETECTED,
                                pii_ask_result2.decision,
                                matched_text=pii_matched_text,
                                error_msg=pii_warning or "",
                                file_path=pii_file_path2,
                                line_number=pii_line_number2,
                                dialog_wait_ms=pii_ask_result2.dialog_wait_ms,
                            )

                    if pii_action in ("block", "redact"):
                        combined_warning = (
                            "\n\n".join(warning_messages) if warning_messages else None
                        )
                        final_error = pii_warning
                        if combined_warning:
                            final_error = f"{combined_warning}\n\n{final_error}"
                        result = _format_response(
                            adapter,
                            has_secrets=True,
                            error_message=final_error,
                            hook_event=hook_event,
                            violation_type=ViolationType.PII_DETECTED,
                            security_message=security_message,
                        )
                        return result
                    elif pii_action == "warn":
                        warning_messages.append(pii_warning)
                    elif pii_action == "log-only":
                        log_only_count += 1
                    else:
                        logging.warning(
                            f"Unknown PII action '{pii_action}', allowing through"
                        )

        # Transcript scanning for secrets and PII (Issue #430, #442, #935)
        # Detects threats that entered the transcript via ! shell commands (which bypass hooks)
        # Prompt injection scanning intentionally excluded — too many false positives in conversation context
        #
        # transcript_path may already be injected into hook_data by adapter defaults
        # resolution above (Issue #935). Build the list of paths to scan:
        # - IDE-provided path (from hook_data), OR
        # - All adapter-default paths (Codex may have multiple session files)
        transcript_path = _get_transcript_path(hook_data)
        transcript_paths_to_scan = [transcript_path] if transcript_path else []
        if not transcript_paths_to_scan and adapter:
            transcript_paths_to_scan = adapter.get_default_transcript_paths()

        if transcript_paths_to_scan and hook_event == HookEvent.PROMPT:
            try:
                ts_config, ts_error = _load_transcript_scanning_config()
                if ts_error:
                    logging.warning(f"Transcript scanning config error: {ts_error}")

                if ts_config and is_feature_enabled(
                    ts_config.get("enabled"), now, default=True
                ):
                    logging.info("Scanning transcript for secrets/PII...")

                    # Reuse already-loaded configs; load fresh if not yet available
                    try:
                        ts_secret_config = secret_config
                    except NameError:
                        ts_secret_config, _ = _load_secret_scanning_config()
                    try:
                        ts_pii_config = pii_config
                    except NameError:
                        ts_pii_config, _ = _load_pii_config()

                    ts_allowed = _invocation_allowed or None
                    for ts_path in transcript_paths_to_scan:
                        with _latency_timer.check("transcript_scanning"):
                            transcript_warnings = scan_transcript_incremental(
                                ts_path,
                                secret_config=ts_secret_config,
                                pii_config=ts_pii_config,
                                hook_context=(
                                    {"session_id": hook_session_id}
                                    if hook_session_id
                                    else None
                                ),
                                allowed_findings=ts_allowed,
                            )
                        if transcript_warnings:
                            warning_messages.extend(transcript_warnings)
                            logging.warning(
                                f"Transcript scanning found {len(transcript_warnings)} issue(s) in {ts_path}"
                            )
                        else:
                            logging.info(
                                f"✓ No threats detected in transcript: {ts_path}"
                            )
                elif ts_config and ide_type != IDEType.CURSOR:
                    logging.info("⚠️  Transcript scanning temporarily disabled")
            except Exception as e:
                on_error = _get_on_scan_error_action()
                if on_error == ActionMode.BLOCK:
                    logging.error(
                        f"Transcript scanning error (fail-closed, on_scan_error=block): {e}"
                    )
                    return _format_response(
                        adapter,
                        has_secrets=True,
                        hook_event=hook_event,
                        error_message=f"Transcript scanning failed (blocked by on_scan_error=block): {e}",
                        violation_type=ViolationType.SECRET_DETECTED,
                        security_message=security_message,
                    )
                logging.warning(f"Transcript scanning error (fail-open): {e}")

        # OpenCode transcript scanning via SQLite (Issue #934)
        # When no transcript_path is available and adapter is OpenCode,
        # read conversation text from OpenCode's SQLite session DB.
        if (
            not transcript_path
            and hook_event == HookEvent.PROMPT
            and adapter
            and adapter.name == "OpenCode"
        ):
            try:
                from ai_guardian.opencode_transcript import get_opencode_db_path

                ts_config, ts_error = _load_transcript_scanning_config()
                if ts_error:
                    logging.warning(f"Transcript scanning config error: {ts_error}")

                if ts_config and is_feature_enabled(
                    ts_config.get("enabled"), now, default=True
                ):
                    oc_db_path = get_opencode_db_path()
                    oc_session_id = hook_data.get("session_id")
                    if oc_db_path and oc_session_id:
                        logging.info(
                            "Scanning OpenCode transcript (SQLite) for secrets/PII..."
                        )

                        try:
                            ts_secret_config = secret_config
                        except NameError:
                            ts_secret_config, _ = _load_secret_scanning_config()
                        try:
                            ts_pii_config = pii_config
                        except NameError:
                            ts_pii_config, _ = _load_pii_config()

                        oc_allowed = _invocation_allowed or None
                        transcript_warnings = scan_opencode_transcript_incremental(
                            oc_db_path,
                            oc_session_id,
                            secret_config=ts_secret_config,
                            pii_config=ts_pii_config,
                            hook_context=(
                                {"session_id": hook_session_id}
                                if hook_session_id
                                else None
                            ),
                            allowed_findings=oc_allowed,
                        )
                        if transcript_warnings:
                            warning_messages.extend(transcript_warnings)
                            logging.warning(
                                f"OpenCode transcript scanning found {len(transcript_warnings)} issue(s)"
                            )
                        else:
                            logging.info("✓ No threats detected in OpenCode transcript")
                    elif not oc_db_path:
                        logging.debug(
                            "OpenCode DB not found, skipping transcript scanning"
                        )
                    elif not oc_session_id:
                        logging.debug(
                            "No session_id in hook data, skipping OpenCode transcript scanning"
                        )
            except Exception as e:
                on_error = _get_on_scan_error_action()
                if on_error == ActionMode.BLOCK:
                    logging.error(
                        f"OpenCode transcript scanning error (fail-closed): {e}"
                    )
                    return _format_response(
                        adapter,
                        has_secrets=True,
                        hook_event=hook_event,
                        error_message=f"OpenCode transcript scanning failed (blocked): {e}",
                        violation_type=ViolationType.SECRET_DETECTED,
                        security_message=security_message,
                    )
                logging.warning(f"OpenCode transcript scanning error (fail-open): {e}")

        # Save PreToolUse context for PostToolUse correlation (#366)
        if (
            hook_event in (HookEvent.PRE_TOOL_USE, HookEvent.BEFORE_READ_FILE)
            and context_mgr
            and hook_tool_use_id
        ):
            try:
                # Determine if PII scan was skipped and why
                pii_scanned = False
                pii_skip_reason = None
                if content_to_scan:
                    if pii_was_skipped:
                        pii_skip_reason = "ignore_files match"
                    else:
                        pii_scanned = True

                # Determine if file matched ignore_files
                ignore_files_matched = bool(
                    file_path
                    and secret_config
                    and _matches_ignore_files(
                        file_path, secret_config.get("ignore_files", [])
                    )
                )

                pretool_context = {
                    "file_path": file_path,
                    "tool_name": tool_identifier or tool_name,
                    "scan_results": {
                        "secrets_scanned": content_to_scan is not None,
                        "secrets_found": False,  # if we got here, no secrets blocked
                        "pii_scanned": pii_scanned,
                        "pii_skipped_reason": pii_skip_reason,
                        "prompt_injection_scanned": content_to_scan is not None,
                        "prompt_injection_found": _pretool_pi_detected,
                        "context_poisoning_scanned": _pretool_cp_scanned,
                        "context_poisoning_found": _pretool_cp_detected,
                    },
                    "ignore_files_matched": ignore_files_matched,
                }
                context_mgr.save_pretool_context(hook_tool_use_id, pretool_context)
                logging.info(
                    f"PreToolUse: saved context for tool_use_id={hook_tool_use_id}"
                )
            except Exception as e:
                logging.debug(f"Failed to save PreToolUse context (non-fatal): {e}")

        # Combine all warning messages if any exist
        combined_warning = "\n\n".join(warning_messages) if warning_messages else None

        result = _format_response(
            adapter,
            has_secrets=False,
            hook_event=hook_event,
            warning_message=combined_warning,
            security_message=security_message,
        )
        if combined_warning:
            result["_warning"] = True
            result["_violation_type"] = "mixed"
        if log_only_count > 0:
            result["_log_only"] = log_only_count
            result["_violation_type"] = "mixed"
        return result

    except Exception as e:
        logging.error(f"Unexpected error processing hook data: {e}")
        import traceback

        logging.error(traceback.format_exc())
        # Best-effort position advance so PostToolUse exceptions don't leave
        # the transcript position stale for the next session.
        try:
            if hook_event == HookEvent.POST_TOOL_USE:
                _advance_transcript_position(hook_data)
        except Exception:
            pass  # intentionally silent — best-effort operation
        # Fail-open: allow operation on errors
        return {"output": None, "exit_code": 0}
    finally:
        logging.disable(logging.NOTSET)
        _finalize_latency(_latency_timer, _latency_event, _latency_tool)
        if (
            _latency_timer is not None
            and _latency_timer.ask_wait_total_ms > 0
            and daemon_state is not None
        ):
            try:
                daemon_state.record_ask_dialog(_latency_timer.ask_wait_total_ms)
            except Exception:
                pass  # intentionally silent — metrics recording best-effort


def process_hook_input():
    """
    Process hook input from stdin and check for secrets.

    Thin wrapper around process_hook_data() that reads JSON from stdin.

    Returns:
        dict: Response with 'output' (str or None) and 'exit_code' (int)
              - For Claude Code: output=None, exit_code=0 (allow) or 2 (block)
              - For Cursor: output=JSON string, exit_code=0
    """
    try:
        stdin_content = sys.stdin.read()
        hook_data = json.loads(stdin_content)
        result = process_hook_data(hook_data)

        # Mark session for security re-injection after blocks (#584)
        if result.get("_blocked"):
            try:
                from ai_guardian.session_state import (
                    SessionStateManager,
                    derive_session_key,
                )

                key = derive_session_key(hook_data)
                SessionStateManager().mark_security_reinject(key)
            except Exception:
                pass  # intentionally silent — session state best-effort

        return result
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse hook input: {e}")
        return {"output": None, "exit_code": 0}
    except Exception as e:
        logging.error(f"Unexpected error in hook: {e}")
        import traceback

        logging.error(traceback.format_exc())
        return {"output": None, "exit_code": 0}
