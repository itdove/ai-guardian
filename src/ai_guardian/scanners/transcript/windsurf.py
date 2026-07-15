"""Windsurf (Devin Desktop) transcript adapter — JSONL step files.

Windsurf stores Cascade conversation transcripts as JSONL files at
``~/.windsurf/transcripts/{trajectory_id}.jsonl``.  Each line is a JSON
object with ``type``, ``status``, and type-specific data fields.
"""

import json
import logging
import os
from typing import Dict, List, Optional, Tuple

from ai_guardian.scanners.transcript.base import TranscriptAdapter
from ai_guardian.scanners.transcript.common import (
    _get_transcript_path,
    _load_transcript_positions,
    _save_transcript_positions,
    _scan_transcript_text,
)


def get_windsurf_transcripts_dir() -> Optional[str]:
    """Find the Windsurf transcripts directory.

    Checks ``WINDSURF_TRANSCRIPTS_DIR`` env var first, then the default
    ``~/.windsurf/transcripts`` path (same across platforms per Windsurf docs).
    """
    custom = os.environ.get("WINDSURF_TRANSCRIPTS_DIR")
    if custom and os.path.isdir(custom):
        return custom

    default = os.path.expanduser("~/.windsurf/transcripts")
    if os.path.isdir(default):
        return default

    return None


_KNOWN_STEP_FIELDS = {
    "user_input": "user_response",
    "planner_response": "response",
    "code_action": "new_content",
}


def _extract_text_from_windsurf_step(step: dict) -> str:
    """Extract scannable text from a single Windsurf JSONL step object.

    Handles known step types via ``_KNOWN_STEP_FIELDS`` mapping and falls
    back to walking the type-named sub-dict for string values.
    """
    step_type = step.get("type")
    if not isinstance(step_type, str):
        return ""

    type_data = step.get(step_type)
    if not isinstance(type_data, dict):
        return ""

    field = _KNOWN_STEP_FIELDS.get(step_type)
    if field is not None:
        text = type_data.get(field)
        return text if isinstance(text, str) else ""

    texts: List[str] = []
    for val in type_data.values():
        if isinstance(val, str) and val:
            texts.append(val)
    return "\n".join(texts)


def read_windsurf_transcript(
    transcript_path: str,
    seen_count: int = 0,
) -> Tuple[str, int]:
    """Read conversation text from a Windsurf JSONL transcript incrementally.

    Uses line count as the position cursor.  Lines at indices
    0..seen_count-1 are skipped.

    Returns:
        Tuple of (combined_new_text, total_line_count).
    """
    try:
        with open(transcript_path, encoding="utf-8") as f:
            skipped = 0
            for _ in range(seen_count):
                if not f.readline():
                    break
                skipped += 1

            truncated = skipped < seen_count
            if truncated:
                f.seek(0)

            texts = []
            total = 0 if truncated else skipped
            for raw_line in f:
                total += 1
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    step = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(step, dict):
                    continue
                extracted = _extract_text_from_windsurf_step(step)
                if extracted:
                    texts.append(extracted)
    except OSError as e:
        logging.debug(f"Windsurf transcript read error: {e}")
        return "", 0

    return "\n".join(texts), total


def scan_windsurf_transcript_incremental(
    transcript_path: str,
    trajectory_id: str,
    secret_config: Optional[Dict] = None,
    pii_config: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    allowed_findings: Optional[set] = None,
) -> list:
    """Incrementally scan a Windsurf transcript JSONL file."""
    warnings: List[str] = []
    pos_key = f"windsurf:{trajectory_id}"

    positions = _load_transcript_positions()
    is_first_scan = pos_key not in positions

    seen_count = (
        positions[pos_key]
        if not is_first_scan and isinstance(positions[pos_key], int)
        else 0
    )
    combined_text, new_count = read_windsurf_transcript(transcript_path, seen_count)

    if is_first_scan:
        logging.debug(
            f"Windsurf transcript first seen, initialized with {new_count} lines"
        )
    elif combined_text:
        warnings = _scan_transcript_text(
            combined_text,
            pos_key,
            secret_config,
            pii_config,
            hook_context,
            allowed_findings=allowed_findings,
        )

    if new_count != seen_count or is_first_scan:
        positions[pos_key] = new_count
        _save_transcript_positions(positions)

    return warnings


class WindsurfTranscriptAdapter(TranscriptAdapter):
    """Transcript adapter for Windsurf JSONL step files."""

    @property
    def name(self) -> str:
        return "Windsurf"

    def can_scan(self, hook_data: Dict, adapter=None) -> bool:
        if adapter and adapter.name == "Windsurf":
            return not _get_transcript_path(hook_data)
        return False

    def scan_incremental(
        self,
        hook_data: Dict,
        secret_config: Optional[Dict] = None,
        pii_config: Optional[Dict] = None,
        hook_context: Optional[Dict] = None,
        allowed_findings: Optional[set] = None,
    ) -> List[str]:
        transcripts_dir = get_windsurf_transcripts_dir()
        if not transcripts_dir:
            logging.debug("Windsurf transcript: no transcripts directory found")
            return []

        trajectory_id = hook_data.get("trajectory_id") or hook_data.get("session_id")
        if not trajectory_id:
            logging.debug("Windsurf transcript: no trajectory_id in hook data")
            return []

        transcript_path = os.path.join(transcripts_dir, f"{trajectory_id}.jsonl")
        if not os.path.isfile(transcript_path):
            logging.debug(f"Windsurf transcript file not found: {transcript_path}")
            return []

        return scan_windsurf_transcript_incremental(
            transcript_path,
            trajectory_id,
            secret_config=secret_config,
            pii_config=pii_config,
            hook_context=hook_context,
            allowed_findings=allowed_findings,
        )
