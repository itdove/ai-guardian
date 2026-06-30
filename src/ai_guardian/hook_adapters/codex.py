"""OpenAI Codex hook adapter.

Codex uses the same PascalCase format and JSON response structure as
Claude Code, so this adapter extends BaseAgentAdapter.

Codex stores JSONL transcripts at:
    ~/.codex/sessions/YYYY/MM/DD/*.jsonl
"""

import glob
import os
from typing import ClassVar, Dict, List

from ai_guardian.hook_adapters.base_agent import BaseAgentAdapter


class CodexAdapter(BaseAgentAdapter):
    """Adapter for OpenAI Codex.

    Codex shares Claude Code's hook format (PascalCase events, same
    JSON response structure). Detection relies on env var override only.
    """

    ENV_ALIASES: ClassVar[List[str]] = ["codex"]

    # Base directory for Codex session transcripts
    SESSIONS_DIR = os.path.expanduser("~/.codex/sessions")

    @property
    def name(self) -> str:
        return "OpenAI Codex"

    @classmethod
    def can_handle(cls, hook_data: Dict) -> bool:
        return False

    def get_default_transcript_paths(self) -> List[str]:
        """Return Codex JSONL transcript paths that exist on disk.

        Codex organises sessions by date: ~/.codex/sessions/YYYY/MM/DD/*.jsonl
        Returns all JSONL files sorted by modification time (most recent first)
        so the caller can scan the active session.
        """
        if not os.path.isdir(self.SESSIONS_DIR):
            return []

        pattern = os.path.join(self.SESSIONS_DIR, "**", "*.jsonl")
        files = glob.glob(pattern, recursive=True)
        if not files:
            return []

        # Sort by modification time, most recent first
        files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
        return files
