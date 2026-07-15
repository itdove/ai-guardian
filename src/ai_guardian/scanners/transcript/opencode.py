"""OpenCode transcript adapter — SQLite session database.

OpenCode stores conversation sessions in a SQLite database at
~/.local/share/opencode/opencode.db (or OPENCODE_HOME). This module
reads message parts to extract text for transcript scanning.
"""

import json
import logging
import os
import sqlite3
from typing import Dict, List, Optional, Tuple

from ai_guardian.scanners.transcript.base import TranscriptAdapter
from ai_guardian.scanners.transcript.common import (
    _load_transcript_positions,
    _save_transcript_positions,
    _scan_transcript_text,
)


def get_opencode_db_path() -> Optional[str]:
    """Find OpenCode SQLite database path.

    Checks OPENCODE_HOME env var first, then default XDG location.
    """
    home = os.environ.get("OPENCODE_HOME")
    if home:
        db_path = os.path.join(home, "opencode.db")
        if os.path.exists(db_path):
            return db_path

    default = os.path.expanduser("~/.local/share/opencode/opencode.db")
    if os.path.exists(default):
        return default

    return None


def _extract_text_from_part(data: dict) -> str:
    """Extract scannable text from an OpenCode part data dict."""
    part_type = data.get("type")
    texts = []

    if part_type == "text":
        text = data.get("text", "")
        if text:
            texts.append(text)

    elif part_type == "tool":
        state = data.get("state")
        if isinstance(state, str):
            try:
                state = json.loads(state)
            except (json.JSONDecodeError, TypeError):
                state = None
        if isinstance(state, dict):
            output = state.get("output", "")
            if output:
                texts.append(output)
            input_data = state.get("input")
            if isinstance(input_data, dict):
                command = input_data.get("command", "")
                if command:
                    texts.append(command)

    return "\n".join(texts)


def read_opencode_transcript(
    db_path: str,
    session_id: str,
    since_timestamp: int = 0,
) -> Tuple[str, int]:
    """Read conversation text from OpenCode SQLite DB incrementally.

    Queries the ``part`` table for text and tool parts created after
    the given timestamp cursor.
    """
    texts = []
    latest_ts = since_timestamp

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cursor = conn.execute(
                "SELECT data, time_created FROM part "
                "WHERE session_id = ? AND time_created > ? "
                "ORDER BY time_created ASC",
                (session_id, since_timestamp),
            )

            for data_str, ts in cursor:
                if ts > latest_ts:
                    latest_ts = ts

                try:
                    data = json.loads(data_str)
                except (json.JSONDecodeError, TypeError):
                    continue

                if not isinstance(data, dict):
                    continue

                extracted = _extract_text_from_part(data)
                if extracted:
                    texts.append(extracted)
        finally:
            conn.close()
    except sqlite3.Error as e:
        logging.debug(f"OpenCode DB read error: {e}")

    return "\n".join(texts), latest_ts


def get_opencode_latest_timestamp(db_path: str, session_id: str) -> int:
    """Get the latest part timestamp for a session (for first-scan skip)."""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            row = conn.execute(
                "SELECT MAX(time_created) FROM part WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if row and row[0] is not None:
                return row[0]
        finally:
            conn.close()
    except sqlite3.Error as e:
        logging.debug(f"OpenCode DB timestamp query error: {e}")
    return 0


def scan_opencode_transcript_incremental(
    db_path: str,
    session_id: str,
    secret_config: Optional[Dict] = None,
    pii_config: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    allowed_findings: Optional[set] = None,
) -> list:
    """Incrementally scan OpenCode session transcript via SQLite."""
    warnings = []
    pos_key = f"opencode:{session_id}"

    positions = _load_transcript_positions()

    if pos_key not in positions:
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

    positions[pos_key] = new_ts
    _save_transcript_positions(positions)

    return warnings


class OpenCodeTranscriptAdapter(TranscriptAdapter):
    """Transcript adapter for OpenCode SQLite session database."""

    @property
    def name(self) -> str:
        return "OpenCode"

    def can_scan(self, hook_data: Dict, adapter=None) -> bool:
        if adapter and adapter.name == "OpenCode":
            from ai_guardian.scanners.transcript.common import _get_transcript_path

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
        db_path = get_opencode_db_path()
        session_id = hook_data.get("session_id")
        if not db_path or not session_id:
            logging.debug("OpenCode transcript: no DB path or session_id available")
            return []

        return scan_opencode_transcript_incremental(
            db_path,
            session_id,
            secret_config=secret_config,
            pii_config=pii_config,
            hook_context=hook_context,
            allowed_findings=allowed_findings,
        )
