"""Cline / ZooCode transcript adapter — JSON array task files.

Cline stores conversation data as JSON array files at
``globalStorage/saoudrizwan.claude-dev/tasks/<task_id>/api_conversation_history.json``
under the VS Code user data directory.  Each file is a JSON array of
message objects with ``role`` and ``content`` fields.
"""

import json
import logging
import os
import sys
from typing import Dict, List, Optional, Tuple

from ai_guardian.scanners.transcript.base import TranscriptAdapter
from ai_guardian.scanners.transcript.common import (
    _get_transcript_path,
    _load_transcript_positions,
    _save_transcript_positions,
    _scan_transcript_text,
)

HISTORY_FILENAME = "api_conversation_history.json"


def get_cline_storage_dir() -> Optional[str]:
    """Find the Cline tasks directory.

    Checks ``CLINE_STORAGE_DIR`` env var first, then platform-specific defaults.
    """
    custom = os.environ.get("CLINE_STORAGE_DIR")
    if custom:
        tasks = (
            custom
            if os.path.basename(custom) == "tasks"
            else os.path.join(custom, "tasks")
        )
        if os.path.isdir(tasks):
            return tasks

    ext_id = "saoudrizwan.claude-dev"
    if sys.platform == "darwin":
        default = os.path.expanduser(
            f"~/Library/Application Support/Code/User/globalStorage/{ext_id}/tasks"
        )
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        default = os.path.join(
            appdata, "Code", "User", "globalStorage", ext_id, "tasks"
        )
    else:
        default = os.path.expanduser(
            f"~/.config/Code/User/globalStorage/{ext_id}/tasks"
        )

    if os.path.isdir(default):
        return default

    return None


def _extract_text_from_cline_message(message: dict) -> str:
    """Extract scannable text from a single Cline message object."""
    content = message.get("content")
    if content is None:
        return ""
    if isinstance(content, str):
        return content

    if not isinstance(content, list):
        return ""

    texts: List[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        block_type = block.get("type", "")

        if block_type == "text":
            text = block.get("text")
            if isinstance(text, str) and text:
                texts.append(text)

        elif block_type == "tool_result":
            result_content = block.get("content")
            if isinstance(result_content, str) and result_content:
                texts.append(result_content)
            elif isinstance(result_content, list):
                for inner in result_content:
                    if isinstance(inner, dict):
                        inner_text = inner.get("text")
                        if isinstance(inner_text, str) and inner_text:
                            texts.append(inner_text)

        elif block_type == "tool_use":
            inp = block.get("input")
            if isinstance(inp, dict):
                for field in ("command", "content", "text"):
                    val = inp.get(field)
                    if isinstance(val, str) and val:
                        texts.append(val)

    return "\n".join(texts)


def get_most_recent_task_dir(storage_dir: str) -> Optional[str]:
    """Find the most recently modified task directory."""
    best_mtime = -1.0
    best_path: Optional[str] = None
    try:
        with os.scandir(storage_dir) as it:
            for entry in it:
                if not entry.is_dir():
                    continue
                history = os.path.join(entry.path, HISTORY_FILENAME)
                if os.path.isfile(history):
                    mtime = os.path.getmtime(history)
                    if mtime > best_mtime:
                        best_mtime = mtime
                        best_path = entry.path
    except OSError as e:
        logging.debug(f"Cline storage listing error: {e}")
        return None

    return best_path


def read_cline_task_transcript(
    task_dir: str,
    seen_count: int = 0,
) -> Tuple[str, int]:
    """Read conversation text from a Cline task JSON file incrementally.

    Uses message count as the position cursor.  Messages at indices
    0..seen_count-1 are skipped.

    Returns:
        Tuple of (combined_new_text, total_message_count).
    """
    history = os.path.join(task_dir, HISTORY_FILENAME)
    try:
        with open(history, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logging.debug(f"Cline transcript read error: {e}")
        return "", 0

    if not isinstance(data, list):
        logging.debug("Cline transcript: expected JSON array")
        return "", 0

    total = len(data)
    if seen_count > total:
        seen_count = 0

    new_messages = data[seen_count:]
    if not new_messages:
        return "", total

    texts = []
    for msg in new_messages:
        if not isinstance(msg, dict):
            continue
        extracted = _extract_text_from_cline_message(msg)
        if extracted:
            texts.append(extracted)

    return "\n".join(texts), total


def scan_cline_transcript_incremental(
    task_dir: str,
    secret_config: Optional[Dict] = None,
    pii_config: Optional[Dict] = None,
    hook_context: Optional[Dict] = None,
    allowed_findings: Optional[set] = None,
) -> list:
    """Incrementally scan a Cline task transcript."""
    warnings: List[str] = []
    task_id = os.path.basename(task_dir)
    pos_key = f"cline:{task_id}"

    positions = _load_transcript_positions()
    is_first_scan = pos_key not in positions

    seen_count = (
        positions[pos_key]
        if not is_first_scan and isinstance(positions[pos_key], int)
        else 0
    )
    combined_text, new_count = read_cline_task_transcript(task_dir, seen_count)

    if is_first_scan:
        logging.debug(
            f"Cline transcript first seen, initialized with {new_count} messages"
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


class ClineTranscriptAdapter(TranscriptAdapter):
    """Transcript adapter for Cline / ZooCode JSON array files."""

    @property
    def name(self) -> str:
        return "Cline"

    def can_scan(self, hook_data: Dict, adapter=None) -> bool:
        if adapter and adapter.name == "Cline":
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
        storage_dir = get_cline_storage_dir()
        if not storage_dir:
            logging.debug("Cline transcript: no storage directory found")
            return []

        task_id = hook_data.get("session_id") or hook_data.get("task_id")
        task_dir = None
        if task_id:
            candidate = os.path.join(storage_dir, task_id)
            if os.path.isdir(candidate):
                task_dir = candidate

        if not task_dir:
            task_dir = get_most_recent_task_dir(storage_dir)

        if not task_dir:
            logging.debug("Cline transcript: no task directory found")
            return []

        return scan_cline_transcript_incremental(
            task_dir,
            secret_config=secret_config,
            pii_config=pii_config,
            hook_context=hook_context,
            allowed_findings=allowed_findings,
        )
