"""
Cross-hook context passing between PreToolUse and PostToolUse.

Provides a unified interface for storing PreToolUse scan results
and retrieving them during PostToolUse processing, enabling:
- Skip double-scanning (performance)
- File path inheritance for PostToolUse violations
- ignore_files consistency across hooks
- Audit trail correlation via tool_use_id
"""

import json
import logging
import os
import stat
import time
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_CONTEXT_TTL = 300  # 5 minutes


class HookContextManager:
    """Manage shared context between PreToolUse and PostToolUse hooks.

    Operates in two modes:
    - Daemon mode: delegates to DaemonState in-memory store (zero I/O)
    - Local mode: uses session-scoped temp file with secure permissions
    """

    def __init__(self, session_id: Optional[str] = None, daemon_state=None):
        self._session_id = session_id
        self._daemon_state = daemon_state
        self._context_file = None

        if not daemon_state and session_id:
            safe_id = self._sanitize_session_id(session_id)
            self._context_file = Path(f"/tmp/ai-guardian-{safe_id}.json")

    @staticmethod
    def _sanitize_session_id(session_id: str) -> str:
        """Sanitize session ID for use in file path."""
        return "".join(c for c in session_id if c.isalnum() or c in "-_")

    def save_pretool_context(self, tool_use_id: str, context: Dict) -> bool:
        """Save PreToolUse context for later PostToolUse correlation.

        Args:
            tool_use_id: Tool use identifier from IDE
            context: Dict with scan results and metadata

        Returns:
            True if saved successfully
        """
        if not tool_use_id:
            return False

        try:
            if self._daemon_state:
                self._daemon_state.store_pretooluse_context(
                    self._session_id, tool_use_id, context
                )
                return True

            return self._save_to_file(tool_use_id, context)
        except Exception as e:
            logger.debug(f"Failed to save pretool context: {e}")
            return False

    def get_pretool_context(self, tool_use_id: str) -> Optional[Dict]:
        """Retrieve PreToolUse context for PostToolUse correlation.

        Args:
            tool_use_id: Tool use identifier from IDE

        Returns:
            PreToolUse context dict, or None if not found/expired
        """
        if not tool_use_id:
            return None

        try:
            if self._daemon_state:
                return self._daemon_state.get_pretooluse_context(
                    self._session_id, tool_use_id
                )

            return self._load_from_file(tool_use_id)
        except Exception as e:
            logger.debug(f"Failed to load pretool context: {e}")
            return None

    def cleanup(self, max_age_seconds: int = DEFAULT_CONTEXT_TTL):
        """Remove expired entries to prevent accumulation.

        Only applies to temp file mode; daemon mode handles its own cleanup.
        """
        if self._daemon_state:
            self._daemon_state.cleanup_expired_contexts()
            return

        if not self._context_file or not self._context_file.exists():
            return

        try:
            data = self._read_file()
            if not data:
                return

            now = time.time()
            expired = [
                k for k, v in data.items()
                if now - v.get("timestamp", 0) > max_age_seconds
            ]

            if expired:
                for key in expired:
                    del data[key]
                self._write_file(data)
                logger.debug(f"Cleaned up {len(expired)} expired hook contexts")
        except Exception as e:
            logger.debug(f"Context cleanup error: {e}")

    def _save_to_file(self, tool_use_id: str, context: Dict) -> bool:
        """Save context entry to temp file."""
        if not self._context_file:
            return False

        data = self._read_file() or {}

        data[tool_use_id] = {
            "context": context,
            "timestamp": time.time(),
        }

        return self._write_file(data)

    def _load_from_file(self, tool_use_id: str) -> Optional[Dict]:
        """Load context entry from temp file."""
        if not self._context_file:
            return None

        data = self._read_file()
        if not data:
            return None

        entry = data.get(tool_use_id)
        if entry is None:
            return None

        age = time.time() - entry.get("timestamp", 0)
        if age > DEFAULT_CONTEXT_TTL:
            return None

        return entry.get("context")

    def _read_file(self) -> Optional[Dict]:
        """Read and parse the context file."""
        if not self._context_file or not self._context_file.exists():
            return None
        try:
            content = self._context_file.read_text(encoding="utf-8")
            if not content.strip():
                return None
            return json.loads(content)
        except (json.JSONDecodeError, OSError) as e:
            logger.debug(f"Error reading context file: {e}")
            return None

    def _write_file(self, data: Dict) -> bool:
        """Write context data to file with secure permissions."""
        if not self._context_file:
            return False
        try:
            content = json.dumps(data)

            if not self._context_file.exists():
                fd = os.open(
                    str(self._context_file),
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    stat.S_IRUSR | stat.S_IWUSR,  # 0600
                )
                try:
                    os.write(fd, content.encode("utf-8"))
                finally:
                    os.close(fd)
            else:
                self._context_file.write_text(content, encoding="utf-8")

            return True
        except OSError as e:
            logger.debug(f"Error writing context file: {e}")
            return False
