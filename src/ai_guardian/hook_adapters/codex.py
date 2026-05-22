"""OpenAI Codex hook adapter.

Codex uses the same PascalCase format and JSON response structure as
Claude Code, so this adapter extends ClaudeCodeAdapter.
"""

from typing import ClassVar, Dict, List

from ai_guardian.hook_adapters.claude_code import ClaudeCodeAdapter


class CodexAdapter(ClaudeCodeAdapter):
    """Adapter for OpenAI Codex.

    Codex shares Claude Code's hook format (PascalCase events, same
    JSON response structure). Detection relies on env var override only.
    """

    ENV_ALIASES: ClassVar[List[str]] = ["codex"]

    @property
    def name(self) -> str:
        return "OpenAI Codex"

    @classmethod
    def can_handle(cls, hook_data: Dict) -> bool:
        return False
