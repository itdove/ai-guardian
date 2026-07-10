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


# --- Re-exports from secret_scanning.py for backward compatibility ---
from ai_guardian.secret_scanning import (  # noqa: F401
    DEFAULT_ENGINES,
    _AUTH_ERROR_KEYWORDS,
    _NETWORK_ERROR_KEYWORDS,
    _build_violation_context,
    _enrich_blocked_from_details,
    _log_secret_detection_violation,
    _CATEGORY_VIOLATION_MAP,
    _log_finding_violation,
    _count_gitleaks_patterns,
    _CATEGORY_BANNER,
    _build_secret_detected_message,
    _describe_patterns,
    _apply_secret_validation,
    _run_secret_validation,
    _extract_matched_text_for_ask,
    check_secrets_with_gitleaks,
)
import ai_guardian.secret_scanning as _secret_scanning_mod

# --- Re-exports from transcript_scanning.py for backward compatibility ---
from ai_guardian.transcript_scanning import (  # noqa: F401
    _get_transcript_path,
    _load_transcript_positions,
    _save_transcript_positions,
    _advance_transcript_position,
    _load_seen_findings,
    _save_seen_findings,
    _finding_fingerprint,
    _extract_secret_type_from_error,
    _extract_text_from_transcript_line,
    scan_transcript_incremental,
    _scan_transcript_text,
    scan_opencode_transcript_incremental,
    _log_transcript_violation,
)

# --- Re-exports from ask_mode.py for backward compatibility ---
from ai_guardian.ask_mode import (  # noqa: F401
    _get_directory_action_from_config,
    _build_permission_matched_text,
    _handle_ask_mode,
    _handle_ask_mode_multi,
    _handle_ask_mode_auto,
    _ASK_VIOLATION_LABELS,
    _format_ask_info_message,
    _log_ask_decision,
    _record_allowed_for_transcript,
    _compute_pii_transcript_fingerprints,
)

# --- Re-exports from hook_events/session_events.py for backward compatibility ---
from ai_guardian.hook_events.session_events import (  # noqa: F401
    _handle_session_end,
    _handle_bootstrap_scan,
    _run_bootstrap_scan,
)

# --- Re-exports from hook_events/scanners.py for backward compatibility ---
from ai_guardian.hook_events.scanners import (  # noqa: F401
    run_prompt_injection_scan,
    run_context_poisoning_scan,
    run_supply_chain_scan,
    _should_skip_offensive_language_scan,
    run_offensive_language_scan,
    run_canary_detection_scan,
    run_code_security_scan,
    run_config_file_scan,
    run_bash_exfil_scan,
    run_exfil_detection_scan,
    run_image_scan,
    run_pii_scan,
    run_secret_scan,
    run_directory_check,
)

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

        # SESSION_START: agents that fire a dedicated session-open event (e.g. Gemini CLI
        # SessionStart). Run bootstrap scan immediately — no other processing needed.
        if hook_event == HookEvent.SESSION_START:
            bs_response = _handle_bootstrap_scan(
                daemon_state,
                hook_session_id,
                adapter,
                ide_type,
                hook_event,
                violation_logger,
            )
            if bs_response:
                return bs_response
            return {"output": None, "exit_code": 0}

        _latency_timer = _CheckTimer(enabled=_is_latency_enabled())
        _latency_event = hook_event

        # Bootstrap scan: scan agent config files on first hook of a new session (#1394).
        # Agents with SESSION_START (e.g. Gemini CLI) already ran bootstrap above and
        # marked the session seen — is_new_session() returns False here for them.
        _bs_response = _handle_bootstrap_scan(
            daemon_state,
            hook_session_id,
            adapter,
            ide_type,
            hook_event,
            violation_logger,
        )
        if _bs_response:
            return _bs_response

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

                        inject_trigger = (
                            si_config.get("inject_trigger", "first_per_session")
                            if si_config
                            else "first_per_session"
                        )
                        custom_rules = (
                            si_config.get("custom_rules", []) if si_config else []
                        )
                        replace_defaults = (
                            si_config.get("replace_defaults", False)
                            if si_config
                            else False
                        )

                        session_key = derive_session_key(hook_data)
                        state_mgr = SessionStateManager(daemon_state=daemon_state)

                        if inject_trigger == "every_prompt":
                            should_inject = True
                        elif inject_trigger == "after_block_only":
                            should_inject = state_mgr.has_reinject_pending(session_key)
                            if should_inject:
                                state_mgr.mark_security_injected(session_key)
                        else:
                            should_inject = state_mgr.should_inject_security(
                                session_key
                            )
                            if should_inject:
                                state_mgr.mark_security_injected(session_key)

                        if should_inject:
                            if replace_defaults:
                                raw = "\n".join(custom_rules) if custom_rules else None
                            else:
                                if custom_rules:
                                    raw = (
                                        _SECURITY_SYSTEM_MESSAGE
                                        + "\n"
                                        + "\n".join(custom_rules)
                                    )
                                else:
                                    raw = _SECURITY_SYSTEM_MESSAGE
                            security_message = raw
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
                            HookEvent.POST_TOOL_USE.display_name,
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
                        hook_name=HookEvent.POST_TOOL_USE.display_name,
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

        # Build registry + PostScanContext early so command-based scanners
        # (BASH_EXFIL, EXFIL_DETECTION) can use apply_post_scan_pipeline().
        # _pipeline_names is deferred until content_to_scan is known.
        from ai_guardian.scanner_registry import ScannerName, get_default_registry
        from ai_guardian.post_scan_filters import (
            PostScanContext,
            apply_post_scan_pipeline,
            log_scan_violations_per_finding,
        )

        _registry = get_default_registry()
        _post_scan_ctx = PostScanContext(
            handle_ask_mode_auto=_handle_ask_mode_auto,
            log_ask_decision=_log_ask_decision,
            format_ask_info_message=_format_ask_info_message,
            hook_event=hook_event,
            hook_session_id=hook_session_id,
            hook_tool_use_id=hook_tool_use_id,
            tool_name=tool_name,
            ide_type_value=(
                ide_type.value if hasattr(ide_type, "value") else str(ide_type)
            ),
            violation_logger=violation_logger,
            latency_timer=_latency_timer,
            invocation_allowed_findings=_invocation_allowed,
        )

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

                    if bash_exfil_result is not None and bash_exfil_result.detected:
                        logging.warning(
                            "🚨 BLOCKED: Credential exfiltration detected in Bash command"
                        )
                        be_decision = apply_post_scan_pipeline(
                            _registry.get(ScannerName.BASH_EXFIL),
                            bash_exfil_result,
                            _post_scan_ctx,
                            blocked_overrides={
                                "command": bash_command[:500],
                            },
                        )
                        warning_messages.extend(be_decision.warnings)
                        if be_decision.should_block:
                            combined_warning = (
                                "\n\n".join(warning_messages)
                                if warning_messages
                                else None
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
                        and exfil_detection_result.detected
                    ):
                        logging.warning(
                            "🚨 BLOCKED: Credential exfiltration behavior detected"
                        )
                        ed_decision = apply_post_scan_pipeline(
                            _registry.get(ScannerName.EXFIL_DETECTION),
                            exfil_detection_result,
                            _post_scan_ctx,
                            blocked_overrides={
                                "command": bash_command[:500],
                            },
                        )
                        warning_messages.extend(ed_decision.warnings)
                        if ed_decision.should_block:
                            combined_warning = (
                                "\n\n".join(warning_messages)
                                if warning_messages
                                else None
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
                                    log_scan_violations_per_finding(
                                        _registry.get(ScannerName.CODE_SECURITY),
                                        all_findings,
                                        _post_scan_ctx,
                                        file_path=cs_file_path,
                                    )
                                    cs_decision = apply_post_scan_pipeline(
                                        _registry.get(ScannerName.CODE_SECURITY),
                                        cs_result,
                                        _post_scan_ctx,
                                        file_path=cs_file_path,
                                        filename=filename,
                                        skip_violation_log=True,
                                    )
                                    warning_messages.extend(cs_decision.warnings)
                                    cs_action = cs_result.extra.get("action", "warn")
                                    if (
                                        cs_decision.should_block
                                        and cs_action == "block"
                                    ):
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
                                    elif cs_action in ("warn",):
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

        # Build content-scanning pipeline names from the registry (#1253 Phase 3)
        # _registry and _post_scan_ctx already constructed above (before BASH_EXFIL).
        _content_pipeline = _registry.get_pipeline(
            hook_event,
            has_content=content_to_scan is not None,
            has_file_path=file_path is not None,
        )
        _pipeline_names = {e.name for e in _content_pipeline}

        # Check for prompt injection BEFORE scanning for secrets
        try:
            pi_result = None
            if ScannerName.PROMPT_INJECTION in _pipeline_names:
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
                if pi_result.detected:
                    _pretool_pi_detected = True
                    pi_decision = apply_post_scan_pipeline(
                        _registry.get(ScannerName.PROMPT_INJECTION),
                        pi_result,
                        _post_scan_ctx,
                        file_path=file_path,
                        filename=filename,
                    )
                    warning_messages.extend(pi_decision.warnings)
                    if pi_decision.should_block:
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
                        return _format_response(
                            adapter,
                            has_secrets=True,
                            error_message=pi_decision.error_message,
                            hook_event=hook_event,
                            warning_message=combined_warning,
                            violation_type=ViolationType.PROMPT_INJECTION,
                            security_message=security_message,
                        )
                else:
                    if ide_type != IDEType.CURSOR:
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
            cp_result = None
            if ScannerName.CONTEXT_POISONING in _pipeline_names:
                cp_result = run_context_poisoning_scan(
                    content_to_scan,
                    file_path=file_path,
                    tool_identifier=tool_identifier,
                    latency_timer=_latency_timer,
                )

            if cp_result is not None:
                _pretool_cp_scanned = True
                if cp_result.detected:
                    _pretool_cp_detected = True
                    cp_decision = apply_post_scan_pipeline(
                        _registry.get(ScannerName.CONTEXT_POISONING),
                        cp_result,
                        _post_scan_ctx,
                        file_path=file_path,
                        filename=filename,
                    )
                    warning_messages.extend(cp_decision.warnings)
                    if cp_decision.should_block:
                        logging.info(
                            "Blocking operation due to context poisoning detection"
                        )
                        combined_warning = (
                            "\n\n".join(warning_messages) if warning_messages else None
                        )
                        return _format_response(
                            adapter,
                            has_secrets=True,
                            error_message=cp_decision.error_message,
                            hook_event=hook_event,
                            warning_message=combined_warning,
                            violation_type=ViolationType.CONTEXT_POISONING,
                            security_message=security_message,
                        )

        except Exception as e:
            logging.warning(f"Context poisoning check error (fail-open): {e}")

        # Check for supply chain threats in agent configuration files
        try:
            sc_result = None
            if ScannerName.SUPPLY_CHAIN in _pipeline_names:
                sc_file_path = file_path or filename or "user_prompt"
                sc_result = run_supply_chain_scan(
                    content_to_scan,
                    sc_file_path,
                    hook_event=hook_event,
                    latency_timer=_latency_timer,
                )

            if sc_result is not None and sc_result.detected:
                sc_decision = apply_post_scan_pipeline(
                    _registry.get(ScannerName.SUPPLY_CHAIN),
                    sc_result,
                    _post_scan_ctx,
                    file_path=sc_file_path,
                    filename=filename,
                )
                warning_messages.extend(sc_decision.warnings)
                if sc_decision.should_block:
                    logging.info(
                        "Blocking operation due to supply chain threat detection"
                    )
                    combined_warning = (
                        "\n\n".join(warning_messages) if warning_messages else None
                    )
                    return _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=sc_decision.error_message,
                        hook_event=hook_event,
                        warning_message=combined_warning,
                        violation_type=ViolationType.SUPPLY_CHAIN,
                        security_message=security_message,
                    )
            elif sc_result is not None and sc_result.error_message:
                warning_messages.append(sc_result.error_message)

        except Exception as e:
            logging.warning(f"Supply chain check error (fail-open): {e}")

        # Check for offensive language (profanity, slurs, non-inclusive terms)
        try:
            ol_result = None
            if ScannerName.OFFENSIVE_LANGUAGE in _pipeline_names:
                ol_result = run_offensive_language_scan(
                    content_to_scan,
                    file_path=file_path,
                    tool_identifier=tool_identifier,
                    latency_timer=_latency_timer,
                )

            if ol_result is not None and ol_result.detected:
                ol_decision = apply_post_scan_pipeline(
                    _registry.get(ScannerName.OFFENSIVE_LANGUAGE),
                    ol_result,
                    _post_scan_ctx,
                    file_path=file_path,
                    filename=filename,
                )
                warning_messages.extend(ol_decision.warnings)
                if ol_decision.should_block:
                    logging.info(
                        "Blocking operation due to offensive language detection"
                    )
                    combined_warning = (
                        "\n\n".join(warning_messages) if warning_messages else None
                    )
                    return _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=ol_decision.error_message,
                        hook_event=hook_event,
                        warning_message=combined_warning,
                        violation_type=ViolationType.OFFENSIVE_LANGUAGE,
                        security_message=security_message,
                    )
            elif ol_result is not None and ol_result.error_message:
                warning_messages.append(ol_result.error_message)

        except Exception as e:
            logging.warning(f"Offensive language check error (fail-open): {e}")

        # Check for canary tokens (user-registered tripwire values detecting exfiltration)
        try:
            cd_result = None
            if ScannerName.CANARY_DETECTION in _pipeline_names:
                cd_source = file_path or filename or "content"
                cd_result = run_canary_detection_scan(
                    content_to_scan,
                    cd_source,
                    latency_timer=_latency_timer,
                )

            if cd_result is not None and cd_result.detected:
                cd_decision = apply_post_scan_pipeline(
                    _registry.get(ScannerName.CANARY_DETECTION),
                    cd_result,
                    _post_scan_ctx,
                    file_path=cd_source,
                    filename=filename,
                )
                warning_messages.extend(cd_decision.warnings)
                if cd_decision.should_block:
                    logging.info("Blocking operation due to canary token detection")
                    combined_warning = (
                        "\n\n".join(warning_messages) if warning_messages else None
                    )
                    return _format_response(
                        adapter,
                        has_secrets=True,
                        error_message=cd_decision.error_message,
                        hook_event=hook_event,
                        warning_message=combined_warning,
                        violation_type=ViolationType.CANARY_DETECTED,
                        security_message=security_message,
                    )
            elif cd_result is not None and cd_result.error_message:
                warning_messages.append(cd_result.error_message)

        except Exception as e:
            logging.warning(f"Canary detection check error (fail-open): {e}")

        # Check for config file threats (credential exfiltration patterns in AI config files)
        if ScannerName.CONFIG_FILE in _pipeline_names:
            try:
                cfs_result = run_config_file_scan(
                    file_path,
                    content_to_scan,
                    latency_timer=_latency_timer,
                )

                if cfs_result is not None:
                    if cfs_result.detected:
                        cfs_decision = apply_post_scan_pipeline(
                            _registry.get(ScannerName.CONFIG_FILE),
                            cfs_result,
                            _post_scan_ctx,
                            file_path=file_path,
                            filename=filename,
                            blocked_overrides={
                                "details": cfs_result.extra.get("details"),
                            },
                        )
                        warning_messages.extend(cfs_decision.warnings)
                        if cfs_decision.should_block:
                            if ide_type != IDEType.CURSOR:
                                logging.info(
                                    f"Blocking operation for {file_path} due to config file threat"
                                )
                            combined_warning = (
                                "\n\n".join(warning_messages)
                                if warning_messages
                                else None
                            )
                            result = _format_response(
                                adapter,
                                has_secrets=True,
                                error_message=cfs_result.error_message,
                                hook_event=hook_event,
                                warning_message=combined_warning,
                                violation_type=ViolationType.CONFIG_FILE_EXFIL,
                                security_message=security_message,
                            )
                            return result
                        elif cfs_result.error_message:
                            warning_messages.append(cfs_result.error_message)
                    else:
                        if ide_type != IDEType.CURSOR:
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

        if ScannerName.SECRET in _pipeline_names and is_feature_enabled(
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
                secret_decision = apply_post_scan_pipeline(
                    _registry.get(ScannerName.SECRET),
                    pre_secret_result,
                    _post_scan_ctx,
                    file_path=file_path,
                    filename=filename,
                    skip_violation_log=True,
                )
                warning_messages.extend(secret_decision.warnings)
                has_secrets = secret_decision.should_block

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
        if ScannerName.PII in _pipeline_names and content_to_scan:
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
                    pii_config_for_log, _ = _load_pii_config()
                    pii_action = (pii_config_for_log or {}).get("action", pii_action)
                    pii_types = list(
                        set(r.get("type", "unknown") for r in pii_redactions)
                    )
                    logging.warning(f"PII detected: {pii_types}")

                    pii_result.extra["action"] = pii_action
                    if (
                        pii_redactions
                        and pii_redactions[0].get("line_number") is not None
                    ):
                        pii_result.line_number = pii_redactions[0]["line_number"]
                    pii_result.matched_text = _extract_pii_matched_text(
                        pii_redactions, pii_scan_content
                    )
                    pii_result.findings = _pii_redactions_to_findings(
                        pii_redactions, pii_scan_content, pii_warning
                    )

                    pii_file_path2 = file_path
                    if not pii_file_path2:
                        pii_file_path2 = _extract_file_path_from_pii_warning(
                            pii_warning
                        )
                    pii_fps = _compute_pii_transcript_fingerprints(
                        pii_redactions, pii_scan_content
                    )

                    pii_line_number = (
                        pii_redactions[0].get("line_number") if pii_redactions else None
                    )
                    pii_blocked_ov = {
                        "pii_count": len(pii_redactions),
                        "pii_types": pii_types,
                    }
                    if pii_line_number is not None:
                        pii_blocked_ov["line_number"] = pii_line_number

                    pii_decision = apply_post_scan_pipeline(
                        _registry.get(ScannerName.PII),
                        pii_result,
                        _post_scan_ctx,
                        file_path=pii_file_path2,
                        filename=filename,
                        blocked_overrides=pii_blocked_ov,
                        finding_fingerprints=pii_fps,
                    )
                    warning_messages.extend(pii_decision.warnings)

                    if not pii_decision.should_block:
                        pii_action = "warn"

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
                        "secrets_scanned": ScannerName.SECRET in _pipeline_names,
                        "secrets_found": False,  # if we got here, no secrets blocked
                        "pii_scanned": pii_scanned,
                        "pii_skipped_reason": pii_skip_reason,
                        "prompt_injection_scanned": (
                            ScannerName.PROMPT_INJECTION in _pipeline_names
                        ),
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
