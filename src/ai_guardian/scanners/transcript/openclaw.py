"""OpenClaw transcript adapter — JSONL transcript files.

OpenClaw stores conversation transcripts as JSONL files at
``~/.openclaw/transcripts/YYYY-MM-DD/<session>/transcript.jsonl``.
Each line is a JSON object with a ``role`` field (user/assistant/tool)
and ``content`` (string or structured).
"""

import json
import logging
import os
from typing import Dict, List, Optional, Tuple

from ai_guardian.scanners.transcript.base import TranscriptAdapter
from ai_guardian.scanners.transcript.common import (
    _discover_path,
    _get_transcript_path,
    _scan_transcript_text,
    _scan_with_position_tracking,
)


def get_openclaw_transcripts_dir() -> Optional[str]:
    """Find the OpenClaw transcripts directory.

    Checks ``OPENCLAW_STATE_DIR`` env var first, then the default
    ``~/.openclaw/transcripts`` path.
    """
    return _discover_path("OPENCLAW_STATE_DIR", "~/.openclaw/transcripts")


def _extract_text_from_openclaw_entry(entry: dict) -> str:
    """Extract scannable text from a single OpenClaw JSONL entry.

    Handles ``content`` as string or structured object, plus ``output``
    and ``arguments`` fields for tool entries.
    """
    texts: List[str] = []

    content = entry.get("content")
    if isinstance(content, str) and content:
        texts.append(content)
    elif isinstance(content, dict):
        for field in ("text", "content", "value", "message"):
            val = content.get(field)
            if isinstance(val, str) and val:
                texts.append(val)
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                text = block.get("text") or block.get("content", "")
                if isinstance(text, str) and text:
                    texts.append(text)

    output = entry.get("output")
    if isinstance(output, str) and output:
        texts.append(output)

    args = entry.get("arguments")
    if isinstance(args, dict):
        for field in ("command", "content", "text", "path"):
            val = args.get(field)
            if isinstance(val, str) and val:
                texts.append(val)
    elif isinstance(args, str) and args:
        texts.append(args)

    return "\n".join(texts)


def get_most_recent_transcript(transcripts_dir: str) -> Optional[str]:
    """Find the most recently modified ``transcript.jsonl`` file.

    Walks date directories (``YYYY-MM-DD/``) and session subdirectories
    to find the newest transcript.
    """
    best_mtime = -1.0
    best_path: Optional[str] = None
    try:
        for date_dir in sorted(os.listdir(transcripts_dir), reverse=True):
            date_path = os.path.join(transcripts_dir, date_dir)
            if not os.path.isdir(date_path):
                continue
            try:
                for session_dir in os.listdir(date_path):
                    candidate = os.path.join(date_path, session_dir, "transcript.jsonl")
                    if not os.path.isfile(candidate):
                        continue
                    mtime = os.path.getmtime(candidate)
                    if mtime > best_mtime:
                        best_mtime = mtime
                        best_path = candidate
            except OSError:
                continue
            if best_path:
                break
    except OSError as e:
        logging.debug(f"OpenClaw transcripts listing error: {e}")
        return None
    return best_path


def read_openclaw_transcript(
    transcript_path: str,
    seen_count: int = 0,
) -> Tuple[str, int]:
    """Read conversation text from an OpenClaw JSONL transcript incrementally.

    Uses line count as the position cursor.

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
                    entry = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict):
                    continue
                extracted = _extract_text_from_openclaw_entry(entry)
                if extracted:
                    texts.append(extracted)
    except OSError as e:
        logging.debug(f"OpenClaw transcript read error: {e}")
        return "", 0

    return "\n".join(texts), total


def scan_openclaw_transcript_incremental(
    transcript_path: str,
    session_id: str,
    secret_config: Optional[Dict] = None,
    pii_config: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    allowed_findings: Optional[set] = None,
) -> list:
    """Incrementally scan an OpenClaw transcript JSONL file."""
    pos_key = f"openclaw:{session_id}"

    combined_text = _scan_with_position_tracking(
        pos_key,
        reader_fn=lambda seen: read_openclaw_transcript(transcript_path, seen),
        label="OpenClaw",
    )

    if not combined_text:
        return []

    return _scan_transcript_text(
        combined_text,
        pos_key,
        secret_config,
        pii_config,
        hook_context,
        allowed_findings=allowed_findings,
    )


class OpenClawTranscriptAdapter(TranscriptAdapter):
    """Transcript adapter for OpenClaw JSONL transcript files."""

    @property
    def name(self) -> str:
        return "OpenClaw"

    def can_scan(
        self,
        hook_data: Dict,
        adapter=None,
    ) -> bool:
        # OpenClaw shares KiroAdapter (no dedicated hook adapter), so the
        # base class adapter.name matching won't work. Use the env var instead.
        ide_type = os.environ.get("AI_GUARDIAN_IDE_TYPE", "").lower()
        if ide_type != "openclaw":
            return False
        return not _get_transcript_path(hook_data)

    def scan_incremental(
        self,
        hook_data: Dict,
        secret_config: Optional[Dict] = None,
        pii_config: Optional[Dict] = None,
        hook_context: Optional[Dict] = None,
        allowed_findings: Optional[set] = None,
    ) -> List[str]:
        transcripts_dir = get_openclaw_transcripts_dir()
        if not transcripts_dir:
            logging.debug("OpenClaw transcript: no transcripts directory found")
            return []

        session_id = hook_data.get("session_id")
        transcript_path = None

        if session_id:
            try:
                for date_dir in sorted(os.listdir(transcripts_dir), reverse=True):
                    candidate = os.path.join(
                        transcripts_dir, date_dir, session_id, "transcript.jsonl"
                    )
                    if os.path.isfile(candidate):
                        transcript_path = candidate
                        break
            except OSError:
                pass

        if not transcript_path:
            transcript_path = get_most_recent_transcript(transcripts_dir)

        if not transcript_path:
            logging.debug("OpenClaw transcript: no transcript file found")
            return []

        if not session_id:
            parts = transcript_path.split(os.sep)
            session_id = parts[-2] if len(parts) >= 2 else "unknown"

        return scan_openclaw_transcript_incremental(
            transcript_path,
            session_id,
            secret_config=secret_config,
            pii_config=pii_config,
            hook_context=hook_context,
            allowed_findings=allowed_findings,
        )
