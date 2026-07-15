"""TranscriptAdapter ABC — polymorphic interface for per-IDE transcript scanning."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Dict, List, Optional

from ai_guardian.scanners.transcript.common import _get_transcript_path

if TYPE_CHECKING:
    from ai_guardian.hook_adapters.base import HookAdapter


class TranscriptAdapter(ABC):
    """Base class for IDE-specific transcript scanners.

    Each subclass knows how to locate, read, and incrementally scan
    conversation transcripts for a specific IDE storage format
    (JSONL files, SQLite databases, etc.).

    The default :meth:`can_scan` matches when the hook adapter's name
    equals :attr:`name` **and** no top-level ``transcript_path`` is
    present in hook data.  Adapters with different matching logic
    (e.g., JSONL) override :meth:`can_scan` directly.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name (e.g., 'JSONL', 'OpenCode', 'Cursor IDE')."""

    def can_scan(
        self,
        hook_data: Dict,
        adapter: Optional["HookAdapter"] = None,
    ) -> bool:
        """Return True if this transcript adapter applies to the current hook invocation.

        Default implementation matches on :attr:`name` and requires
        that no ``transcript_path`` field is present in *hook_data*.
        """
        if adapter and adapter.name == self.name:
            return not _get_transcript_path(hook_data)
        return False

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
