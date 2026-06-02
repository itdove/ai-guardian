"""
Base classes for the multi-agent hook adapter architecture.

Defines the abstract HookAdapter interface and the NormalizedHookInput
dataclass that all concrete adapters produce.
"""

import json
import logging
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, List, Optional

from ai_guardian.constants import HookEvent

logger = logging.getLogger(__name__)


@dataclass
class NormalizedHookInput:
    """IDE-agnostic representation of hook input.

    Produced by each adapter's normalize_input() method, consumed by
    the core scanning pipeline in hook_processing.process_hook_data().
    """

    event: HookEvent
    tool_name: Optional[str] = None
    tool_input: Dict = field(default_factory=dict)
    file_path: Optional[str] = None
    working_dir: Optional[str] = None
    session_id: Optional[str] = None
    tool_use_id: Optional[str] = None
    prompt_text: Optional[str] = None
    tool_response: Any = None
    transcript_path: Optional[str] = None
    raw_data: Dict = field(default_factory=dict)


class HookAdapter(ABC):
    """Abstract base for IDE-specific hook adapters.

    Each supported AI coding agent gets a concrete subclass that handles:
    - Detection: can this adapter handle a given hook input?
    - Normalization: parse IDE-specific JSON into NormalizedHookInput
    - Response formatting: produce IDE-specific output (JSON/exit codes)
    """

    # Subclasses set this to map env var values to the adapter.
    # e.g., ClaudeCodeAdapter.ENV_ALIASES = ["claude", "codex", "windsurf"]
    ENV_ALIASES: ClassVar[List[str]] = []

    @property
    @abstractmethod
    def ide_type(self):
        """Return the IDEType enum value for this adapter."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name (e.g., 'Claude Code')."""

    @classmethod
    @abstractmethod
    def can_handle(cls, hook_data: Dict) -> bool:
        """Return True if this adapter should handle the given hook input.

        Called by the registry in priority order. The first adapter that
        returns True wins. Implementations should check for fields unique
        to their IDE's hook format.
        """

    @abstractmethod
    def normalize_input(self, hook_data: Dict) -> NormalizedHookInput:
        """Parse IDE-specific hook JSON into a NormalizedHookInput."""

    @abstractmethod
    def format_response(
        self,
        has_secrets: bool,
        error_message: Optional[str] = None,
        hook_event: HookEvent = HookEvent.PROMPT,
        warning_message: Optional[str] = None,
        modified_output: Optional[str] = None,
        violation_type: Optional[str] = None,
        security_message: Optional[str] = None,
    ) -> Dict:
        """Format a response dict in this IDE's expected output format.

        Returns:
            dict with 'output' (str or None), 'exit_code' (int), and
            optional metadata keys ('_blocked', '_violation_type').
        """

    def get_tool_name_map(self) -> Dict[str, str]:
        """Return a mapping of IDE-specific tool names to canonical names.

        Override in subclasses where tool names differ from the standard
        Claude Code names (e.g., Augment Code maps "launch-process" to "Bash").
        """
        return {}

    # -- Helpers available to all adapters --

    @staticmethod
    def _add_metadata(result: Dict, has_secrets: bool, violation_type: Optional[str] = None) -> Dict:
        """Attach daemon tracking metadata to a response dict."""
        if has_secrets:
            result["_blocked"] = True
        if violation_type:
            result["_violation_type"] = violation_type
        return result

    @staticmethod
    def _extract_file_path_from_tool_input(hook_data: Dict) -> Optional[str]:
        """Extract file_path from common hook data structures."""
        # Claude Code / Codex: tool_use.input.file_path or tool_use.parameters.file_path
        tool_use = hook_data.get("tool_use")
        if isinstance(tool_use, dict):
            for container_key in ("input", "parameters"):
                container = tool_use.get(container_key)
                if isinstance(container, dict):
                    fp = container.get("file_path") or container.get("path")
                    if fp:
                        return fp

        # Direct parameters field
        params = hook_data.get("parameters")
        if isinstance(params, dict):
            fp = params.get("file_path") or params.get("path")
            if fp:
                return fp

        # Cursor: tool_input.file_path
        tool_input = hook_data.get("tool_input")
        if isinstance(tool_input, dict):
            fp = tool_input.get("file_path") or tool_input.get("path")
            if fp:
                return fp

        # Cursor: tool.file_path
        tool = hook_data.get("tool")
        if isinstance(tool, dict):
            fp = tool.get("file_path") or tool.get("path")
            if fp:
                return fp

        return None

    @staticmethod
    def _extract_tool_name(hook_data: Dict) -> Optional[str]:
        """Extract tool name from common hook data structures."""
        tool_name = hook_data.get("tool_name")
        if tool_name:
            return tool_name

        tool_use = hook_data.get("tool_use")
        if isinstance(tool_use, dict):
            name = tool_use.get("name")
            if name:
                return name

        tool = hook_data.get("tool")
        if isinstance(tool, dict):
            name = tool.get("name")
            if name:
                return name

        return None

    @staticmethod
    def _extract_tool_input(hook_data: Dict) -> Dict:
        """Extract tool input/parameters from common hook data structures."""
        tool_use = hook_data.get("tool_use")
        if isinstance(tool_use, dict):
            # Try both "parameters" (PreToolUse) and "input" (PostToolUse)
            params = tool_use.get("parameters")
            if isinstance(params, dict):
                return params
            inp = tool_use.get("input")
            if isinstance(inp, dict):
                return inp

        tool_input = hook_data.get("tool_input")
        if isinstance(tool_input, dict):
            return tool_input

        return {}

    @staticmethod
    def _extract_prompt_text(hook_data: Dict) -> Optional[str]:
        """Extract user prompt text from hook data."""
        for key in ("prompt", "message", "userMessage", "user_message"):
            val = hook_data.get(key)
            if isinstance(val, str):
                return val
        return None

    @staticmethod
    def _extract_transcript_path(hook_data: Dict) -> Optional[str]:
        """Extract transcript path from hook data."""
        for key in ("transcript_path", "transcriptPath", "transcript", "conversation_path"):
            val = hook_data.get(key)
            if isinstance(val, str):
                return val
        return None

    @staticmethod
    def _combine_error_messages(error_message: Optional[str], warning_message: Optional[str]) -> Optional[str]:
        """Combine error and warning messages."""
        if not error_message:
            return None
        if warning_message:
            return f"{warning_message}\n\n{error_message}"
        return error_message

    @staticmethod
    def _detect_event_from_all_formats(hook_data: Dict) -> HookEvent:
        """Detect hook event from any known event name format.

        This is the universal fallback that handles event names from all
        supported agents. Used by the default adapter (ClaudeCodeAdapter)
        and any adapter that doesn't fully override normalize_input().
        """
        # Windsurf: agent_action_name field
        agent_action = hook_data.get("agent_action_name", "").lower()
        if agent_action:
            if agent_action == "pre_user_prompt":
                return HookEvent.PROMPT
            elif agent_action in ("pre_read_code",):
                return HookEvent.BEFORE_READ_FILE
            elif agent_action in ("pre_run_command", "pre_write_code", "pre_mcp_tool_use"):
                return HookEvent.PRE_TOOL_USE
            elif agent_action in ("post_run_command", "post_read_code", "post_write_code",
                                  "post_mcp_tool_use"):
                return HookEvent.POST_TOOL_USE

        event_name = hook_data.get("hook_event_name", "").lower()
        if not event_name:
            event_name = hook_data.get("hookName", "").lower()

        # OpenCode plugin events
        if event_name == "tool.execute.before":
            return HookEvent.PRE_TOOL_USE
        elif event_name == "tool.execute.after":
            return HookEvent.POST_TOOL_USE
        elif event_name == "message.submit":
            return HookEvent.PROMPT

        # Gemini CLI
        if event_name == "beforetool":
            return HookEvent.PRE_TOOL_USE
        elif event_name == "aftertool":
            return HookEvent.POST_TOOL_USE
        elif event_name in ("beforeagent", "sessionstart"):
            return HookEvent.PROMPT

        # Kiro
        if event_name in ("prompt_submit", "promptsubmit"):
            return HookEvent.PROMPT
        elif event_name == "agent_stop":
            return HookEvent.POST_TOOL_USE
        elif event_name == "pre_tool_use":
            return HookEvent.PRE_TOOL_USE
        elif event_name == "post_tool_use":
            return HookEvent.POST_TOOL_USE

        # Claude Code / Copilot / Cursor / Cline
        if event_name in ("userpromptsubmit", "beforesubmitprompt", "userpromptsubmitted"):
            return HookEvent.PROMPT
        elif event_name in ("pretooluse",):
            return HookEvent.PRE_TOOL_USE
        elif event_name in ("posttooluse",):
            return HookEvent.POST_TOOL_USE
        elif event_name in ("beforereadfile",):
            return HookEvent.BEFORE_READ_FILE

        # Cursor hook_name field
        hook_name = hook_data.get("hook_name", "").lower()
        if hook_name in ("beforesubmitprompt",):
            return HookEvent.PROMPT
        elif hook_name in ("pretooluse",):
            return HookEvent.PRE_TOOL_USE

        # Field-based fallbacks
        if "toolName" in hook_data:
            return HookEvent.PRE_TOOL_USE
        if "tool_response" in hook_data:
            return HookEvent.POST_TOOL_USE
        if "tool_use" in hook_data or "tool" in hook_data or "tool_name" in hook_data:
            return HookEvent.PRE_TOOL_USE
        if "prompt" in hook_data or "message" in hook_data or "userMessage" in hook_data:
            return HookEvent.PROMPT

        return HookEvent.PROMPT
