"""Shared transcript scanning utilities.

Position tracking, dedup, fingerprinting, core scanning, and violation logging
used by all TranscriptAdapter implementations.
"""

try:
    import fcntl

    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Callable, Dict, Optional

from ai_guardian.config.utils import get_project_dir, get_state_dir, is_feature_enabled
from ai_guardian.constants import HookEvent, ViolationType
from ai_guardian.scanners.secret_scanning import check_secrets_with_gitleaks

import ai_guardian.scanners.secret_scanning as _secret_scanning_mod

try:
    from ai_guardian.violations.logger import ViolationLogger

    HAS_VIOLATION_LOGGER = True
except ImportError:
    HAS_VIOLATION_LOGGER = False


# ---------------------------------------------------------------------------
# Hook data extraction
# ---------------------------------------------------------------------------


def _get_transcript_path(hook_data: dict):
    """Extract transcript path from hook data across IDE types."""
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


# ---------------------------------------------------------------------------
# Position tracking
# ---------------------------------------------------------------------------


def _load_transcript_positions() -> Dict[str, object]:
    """Load transcript scanning positions from state dir.

    Values are ints (byte offsets / timestamps) for JSONL and OpenCode,
    or lists of bubble-ID strings for Cursor.
    """
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


def _save_transcript_positions(positions: Dict[str, object]) -> None:
    """Save transcript scanning positions to state dir.

    Prunes entries for files that no longer exist, but keeps prefixed
    keys (opencode:, cursor:) unconditionally.
    """
    state_dir = get_state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    pos_file = state_dir / "transcript_positions.json"
    try:
        pruned = {k: v for k, v in positions.items() if ":" in k or os.path.exists(k)}
        with open(pos_file, "w", encoding="utf-8") as f:
            json.dump(pruned, f)
    except Exception as e:
        logging.debug(f"Failed to save transcript positions: {e}")


def _scan_with_position_tracking(
    pos_key: str,
    reader_fn: Callable,
    default_position: object = 0,
    init_position_fn: Optional[Callable] = None,
    label: str = "Transcript",
) -> str:
    """Handle position loading/saving for incremental transcript scanning.

    Args:
        pos_key: Key for position tracking (e.g., ``"cline:<task_id>"``).
        reader_fn: ``(last_position) -> (combined_text, new_position)``.
        default_position: Initial position passed to *reader_fn* on first
            scan when *init_position_fn* is not provided.
        init_position_fn: Optional ``() -> initial_position``.  When given,
            called on first scan instead of *reader_fn* to seed the position
            without reading content.
        label: Human-readable adapter name for debug logging.

    Returns:
        Combined text from new content, or ``""`` when there is nothing to
        scan (first scan or no new data).  Position is persisted
        automatically whenever it changes.
    """
    positions = _load_transcript_positions()

    if pos_key not in positions:
        if init_position_fn is not None:
            positions[pos_key] = init_position_fn()
        else:
            _, new_pos = reader_fn(default_position)
            positions[pos_key] = new_pos
        _save_transcript_positions(positions)
        logging.debug(f"{label} transcript first seen, initialized position")
        return ""

    last_pos = positions[pos_key]
    combined_text, new_pos = reader_fn(last_pos)

    if new_pos != last_pos:
        positions[pos_key] = new_pos
        _save_transcript_positions(positions)

    return combined_text


# ---------------------------------------------------------------------------
# Path discovery
# ---------------------------------------------------------------------------


def _discover_path(
    env_var: str,
    default: str,
    check: Callable[[str], bool] = os.path.isdir,
    env_suffix: str = "",
) -> Optional[str]:
    """Discover a storage path via environment variable or platform default.

    Args:
        env_var: Environment variable to check first.
        default: Default path (expanded with :func:`os.path.expanduser`).
        check: Validation function (e.g., :func:`os.path.isdir`).
        env_suffix: Filename appended to the env-var value via
            :func:`os.path.join`.
    """
    custom = os.environ.get(env_var)
    if custom:
        path = os.path.join(custom, env_suffix) if env_suffix else custom
        if check(path):
            return path

    expanded = os.path.expanduser(default)
    if check(expanded):
        return expanded

    return None


# ---------------------------------------------------------------------------
# Seen-findings dedup
# ---------------------------------------------------------------------------


def _load_seen_findings() -> Dict[str, Dict[str, str]]:
    """Load seen transcript findings from state dir.

    Returns:
        Dict mapping transcript keys to dicts of {fingerprint: iso_timestamp}.
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

    Prunes entries for files that no longer exist, but keeps prefixed keys.
    """
    state_dir = get_state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    sf_file = state_dir / "transcript_seen_findings.json"
    try:
        pruned = {k: v for k, v in seen.items() if ":" in k or os.path.exists(k)}
        with open(sf_file, "w", encoding="utf-8") as f:
            json.dump(pruned, f)
    except Exception as e:
        logging.debug(f"Failed to save seen findings: {e}")


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------


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
    """Extract the secret type (rule_id) from a scanner error message."""
    match = re.search(r"Secret Type:\s*(.+)", error_msg)
    if match:
        return match.group(1).strip()
    return "unknown"


# ---------------------------------------------------------------------------
# Core scanning
# ---------------------------------------------------------------------------


def _scan_transcript_text(
    combined_text: str,
    transcript_key: str,
    secret_config: Optional[Dict] = None,
    pii_config: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    allowed_findings: Optional[set] = None,
) -> list:
    """Scan combined text for secrets and PII with deduplication.

    Shared by all transcript adapter implementations.

    Args:
        combined_text: Concatenated transcript text to scan.
        transcript_key: Key for dedup tracking (file path or prefixed ID).
        secret_config: Secret scanning config.
        pii_config: PII scanning config.
        hook_context: Optional context with session_id for correlation.
        allowed_findings: Optional set of fingerprints to skip.

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
                per_findings = _secret_scanning_mod._last_secret_findings or []
                if per_findings:
                    new_findings = []
                    for finding in per_findings:
                        rule_id = getattr(
                            finding, "rule_id", ""
                        ) or _extract_secret_type_from_error(secret_error)
                        fp = _finding_fingerprint("secret", rule_id)
                        if fp not in seen and fp not in (allowed_findings or ()):
                            new_findings.append((fp, rule_id))
                            seen[fp] = now_iso
                    if new_findings:
                        count = len(new_findings)
                        types = list(dict.fromkeys(r for _, r in new_findings))
                        noun = "SECRET" if count == 1 else "SECRETS"
                        verb = "was" if count == 1 else "were"
                        type_line = (
                            f"Type{'s' if count > 1 else ''}: {', '.join(types)}\n"
                            if types
                            else ""
                        )
                        warning_msg = (
                            f"\n{'='*70}\n"
                            f"🔍 {count} {noun} DETECTED IN CONVERSATION TRANSCRIPT\n"
                            f"{'='*70}\n"
                            f"{count} secret(s) {verb} found in your conversation history\n"
                            f"{type_line}"
                            f"(possibly from a ! shell command).\n"
                            f"The secret(s) have already been sent to the AI model.\n"
                            f"Recommended actions:\n"
                            f"  1. Rotate the exposed credential(s) immediately\n"
                            f"  2. Start a new session to limit further exposure\n"
                            f"  3. Review your shell history for other leaked secrets\n"
                            f"{'='*70}\n"
                        )
                        warnings.append(warning_msg)
                        _log_transcript_violation(
                            ViolationType.SECRET_IN_TRANSCRIPT,
                            transcript_key,
                            details={
                                "reason": secret_error,
                                "count": count,
                                "types": types,
                            },
                            hook_context=hook_context,
                        )
                else:
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
            from ai_guardian.hook_processing import _scan_for_pii

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


# ---------------------------------------------------------------------------
# Violation logging
# ---------------------------------------------------------------------------


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
