"""Transcript scanning functions extracted from hook_processing.py (Phase 5b, #1491)."""

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
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from ai_guardian.config_utils import get_project_dir, get_state_dir, is_feature_enabled
from ai_guardian.constants import HookEvent, ViolationType
from ai_guardian.secret_scanning import check_secrets_with_gitleaks

import ai_guardian.secret_scanning as _secret_scanning_mod

try:
    from ai_guardian.violation_logger import ViolationLogger

    HAS_VIOLATION_LOGGER = True
except ImportError:
    HAS_VIOLATION_LOGGER = False


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
