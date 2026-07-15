"""TranscriptAdapter ABC — polymorphic interface for per-IDE transcript scanning."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from ai_guardian.hook_adapters.base import HookAdapter


class TranscriptAdapter(ABC):
    """Base class for IDE-specific transcript scanners.

    Each subclass knows how to locate, read, and incrementally scan
    conversation transcripts for a specific IDE storage format
    (JSONL files, SQLite databases, etc.).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name (e.g., 'JSONL', 'OpenCode', 'Cursor IDE')."""

    @abstractmethod
    def can_scan(
        self,
        hook_data: Dict,
        adapter: Optional["HookAdapter"],
    ) -> bool:
        """Return True if this transcript adapter applies to the current hook invocation."""

    @abstractmethod
    def scan_incremental(
        self,
        hook_data: Dict,
        secret_config: Optional[Dict] = None,
        pii_config: Optional[Dict] = None,
        hook_context: Optional[Dict] = None,
        allowed_findings: Optional[set] = None,
    ) -> List[str]:
        """Full scan cycle: locate storage, read new content, scan, update position.

        Returns:
            List of warning message strings (empty if nothing found).
        """
