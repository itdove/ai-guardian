"""OpenCode transcript reading via SQLite session DB.

OpenCode stores conversation sessions in a SQLite database at
~/.local/share/opencode/opencode.db (or OPENCODE_HOME). This module
reads message parts to extract text for transcript scanning.
"""

import json
import logging
import os
import sqlite3
from typing import Optional, Tuple


def get_opencode_db_path() -> Optional[str]:
    """Find OpenCode SQLite database path.

    Checks OPENCODE_HOME env var first, then default XDG location.

    Returns:
        Absolute path to opencode.db, or None if not found.
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
    """Extract scannable text from an OpenCode part data dict.

    Args:
        data: Parsed JSON from part.data column.

    Returns:
        Extracted text, or empty string.
    """
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
    the given timestamp cursor.  Returns combined text and the latest
    timestamp seen so the caller can advance the cursor.

    Args:
        db_path: Absolute path to opencode.db.
        session_id: OpenCode session ID to scan.
        since_timestamp: Only read parts with time_created > this value
            (epoch milliseconds).

    Returns:
        Tuple of (combined_text, latest_timestamp).  If nothing new,
        combined_text is empty and latest_timestamp equals since_timestamp.
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
    """Get the latest part timestamp for a session (for first-scan skip).

    Args:
        db_path: Absolute path to opencode.db.
        session_id: OpenCode session ID.

    Returns:
        Latest time_created value, or 0 if session has no parts.
    """
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
