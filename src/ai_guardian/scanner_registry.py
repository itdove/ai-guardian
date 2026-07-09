"""Scanner registry for declarative, loop-based scanner invocation.

Phase 3 of scanner registry refactor (#1253). Provides a data-driven
mapping from hook events to ordered scanner pipelines, replacing
hardcoded per-scanner blocks in process_hook_data().
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from ai_guardian.constants import HookEvent, ViolationType
from ai_guardian.scan_result import ScanResult

logger = logging.getLogger(__name__)


class ScannerName(str, enum.Enum):
    """Canonical names for all registered scanners."""

    PROMPT_INJECTION = "prompt_injection"
    CONTEXT_POISONING = "context_poisoning"
    SUPPLY_CHAIN = "supply_chain"
    OFFENSIVE_LANGUAGE = "offensive_language"
    CANARY_DETECTION = "canary_detection"
    CONFIG_FILE = "config_file"
    SECRET = "secret"
    PII = "pii"
    CODE_SECURITY = "code_security"
    BASH_EXFIL = "bash_exfil"
    EXFIL_DETECTION = "exfil_detection"
    IMAGE = "image"
    DIRECTORY = "directory"


@dataclass
class ScannerEntry:
    """Registration record for a scanner in the pipeline."""

    name: ScannerName
    run_fn: Callable[..., Optional[ScanResult]]
    violation_type: ViolationType
    hook_events: Set[HookEvent]
    requires_content: bool = True
    requires_file_path: bool = False
    requires_command: bool = False
    order: int = 100


class ScannerRegistry:
    """Registry mapping hook events to ordered scanner pipelines.

    Wraps existing run_*_scan() functions in a declarative structure
    so process_hook_data() can iterate instead of hand-coding each
    scanner invocation.
    """

    def __init__(self) -> None:
        self._entries: Dict[ScannerName, ScannerEntry] = {}

    def register(self, entry: ScannerEntry) -> None:
        self._entries[entry.name] = entry

    def get_pipeline(
        self,
        hook_event: HookEvent,
        *,
        has_content: bool = False,
        has_file_path: bool = False,
        has_command: bool = False,
    ) -> List[ScannerEntry]:
        """Return ordered scanners applicable to this context."""
        applicable = []
        for entry in self._entries.values():
            if hook_event not in entry.hook_events:
                continue
            if entry.requires_content and not has_content:
                continue
            if entry.requires_file_path and not has_file_path:
                continue
            if entry.requires_command and not has_command:
                continue
            applicable.append(entry)
        applicable.sort(key=lambda e: e.order)
        return applicable

    def get(self, name: ScannerName) -> Optional[ScannerEntry]:
        return self._entries.get(name)

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, name: ScannerName) -> bool:
        return name in self._entries


_default_registry: Optional[ScannerRegistry] = None


def get_default_registry() -> ScannerRegistry:
    """Return the shared default scanner registry (lazy singleton)."""
    global _default_registry
    if _default_registry is None:
        _default_registry = _build_default_registry()
    return _default_registry


def reset_default_registry() -> None:
    """Reset the singleton (for testing)."""
    global _default_registry
    _default_registry = None


def _build_default_registry() -> ScannerRegistry:
    """Build the default registry with all known scanners."""
    from ai_guardian.hook_processing import (
        run_bash_exfil_scan,
        run_canary_detection_scan,
        run_code_security_scan,
        run_config_file_scan,
        run_context_poisoning_scan,
        run_directory_check,
        run_exfil_detection_scan,
        run_image_scan,
        run_offensive_language_scan,
        run_pii_scan,
        run_prompt_injection_scan,
        run_secret_scan,
        run_supply_chain_scan,
    )

    registry = ScannerRegistry()

    CONTENT_EVENTS = {
        HookEvent.PRE_TOOL_USE,
        HookEvent.BEFORE_READ_FILE,
        HookEvent.PROMPT,
    }

    registry.register(
        ScannerEntry(
            name=ScannerName.IMAGE,
            run_fn=run_image_scan,
            violation_type=ViolationType.IMAGE_SECRET_DETECTED,
            hook_events=CONTENT_EVENTS,
            requires_content=False,
            requires_file_path=True,
            order=1,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.BASH_EXFIL,
            run_fn=run_bash_exfil_scan,
            violation_type=ViolationType.CONFIG_FILE_EXFIL,
            hook_events={HookEvent.PRE_TOOL_USE},
            requires_content=False,
            requires_command=True,
            order=5,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.EXFIL_DETECTION,
            run_fn=run_exfil_detection_scan,
            violation_type=ViolationType.EXFIL_DETECTION,
            hook_events={HookEvent.PRE_TOOL_USE},
            requires_content=False,
            requires_command=True,
            order=6,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.CODE_SECURITY,
            run_fn=run_code_security_scan,
            violation_type=ViolationType.CODE_SECURITY,
            hook_events={HookEvent.PRE_TOOL_USE},
            requires_content=True,
            requires_file_path=True,
            order=7,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.PROMPT_INJECTION,
            run_fn=run_prompt_injection_scan,
            violation_type=ViolationType.PROMPT_INJECTION,
            hook_events=CONTENT_EVENTS | {HookEvent.POST_TOOL_USE},
            order=10,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.CONTEXT_POISONING,
            run_fn=run_context_poisoning_scan,
            violation_type=ViolationType.CONTEXT_POISONING,
            hook_events=CONTENT_EVENTS | {HookEvent.POST_TOOL_USE},
            order=20,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.SUPPLY_CHAIN,
            run_fn=run_supply_chain_scan,
            violation_type=ViolationType.SUPPLY_CHAIN,
            hook_events={HookEvent.PRE_TOOL_USE, HookEvent.BEFORE_READ_FILE},
            order=30,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.OFFENSIVE_LANGUAGE,
            run_fn=run_offensive_language_scan,
            violation_type=ViolationType.OFFENSIVE_LANGUAGE,
            hook_events=CONTENT_EVENTS | {HookEvent.POST_TOOL_USE},
            order=40,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.CANARY_DETECTION,
            run_fn=run_canary_detection_scan,
            violation_type=ViolationType.CANARY_DETECTED,
            hook_events=CONTENT_EVENTS,
            order=50,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.CONFIG_FILE,
            run_fn=run_config_file_scan,
            violation_type=ViolationType.CONFIG_FILE_EXFIL,
            hook_events={HookEvent.PRE_TOOL_USE, HookEvent.BEFORE_READ_FILE},
            requires_content=True,
            requires_file_path=True,
            order=60,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.SECRET,
            run_fn=run_secret_scan,
            violation_type=ViolationType.SECRET_DETECTED,
            hook_events=CONTENT_EVENTS | {HookEvent.POST_TOOL_USE},
            order=70,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.PII,
            run_fn=run_pii_scan,
            violation_type=ViolationType.PII_DETECTED,
            hook_events=CONTENT_EVENTS | {HookEvent.POST_TOOL_USE},
            order=80,
        )
    )

    registry.register(
        ScannerEntry(
            name=ScannerName.DIRECTORY,
            run_fn=run_directory_check,
            violation_type=ViolationType.DIRECTORY_BLOCKING,
            hook_events={HookEvent.PRE_TOOL_USE, HookEvent.BEFORE_READ_FILE},
            requires_content=False,
            requires_file_path=True,
            order=90,
        )
    )

    return registry
