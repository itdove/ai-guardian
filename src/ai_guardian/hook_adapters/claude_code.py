"""Claude Code hook adapter.

Claude Code uses PascalCase event names (UserPromptSubmit, PreToolUse,
PostToolUse) and JSON responses on stdout. Exit code is always 0;
blocking is communicated via hookSpecificOutput.permissionDecision.

Also used as the base format for Codex and Windsurf (via subclasses).
"""

import json
from typing import ClassVar, Dict, List, Optional

from ai_guardian.constants import HookEvent
from ai_guardian.hook_adapters.base import HookAdapter, NormalizedHookInput


class ClaudeCodeAdapter(HookAdapter):
    """Adapter for Claude Code (Anthropic).

    Detection: hook_event_name in {UserPromptSubmit, PreToolUse, PostToolUse}
    or fallback (default adapter).
    """

    ENV_ALIASES: ClassVar[List[str]] = ["claude"]

    @property
    def ide_type(self):
        from ai_guardian.response_format import IDEType
        return IDEType.CLAUDE_CODE

    @property
    def name(self) -> str:
        return "Claude Code"

    @classmethod
    def can_handle(cls, hook_data: Dict) -> bool:
        event = hook_data.get("hook_event_name", "")
        return event in ("UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop",
                        "SessionEnd", "PostCompact")

    def normalize_input(self, hook_data: Dict) -> NormalizedHookInput:
        event = self._detect_event_from_all_formats(hook_data)

        tool_name = self._extract_tool_name(hook_data)
        tool_name_map = self.get_tool_name_map()
        if tool_name and tool_name in tool_name_map:
            tool_name = tool_name_map[tool_name]

        return NormalizedHookInput(
            event=event,
            tool_name=tool_name,
            tool_input=self._extract_tool_input(hook_data),
            file_path=self._extract_file_path_from_tool_input(hook_data),
            working_dir=hook_data.get("cwd"),
            session_id=hook_data.get("session_id"),
            tool_use_id=hook_data.get("tool_use_id"),
            prompt_text=self._extract_prompt_text(hook_data),
            tool_response=hook_data.get("tool_response"),
            transcript_path=self._extract_transcript_path(hook_data),
            raw_data=hook_data,
        )

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
        final_error = self._combine_error_messages(error_message, warning_message) if has_secrets else None

        if hook_event == HookEvent.POST_TOOL_USE:
            if has_secrets:
                response = {
                    "decision": "block",
                    "reason": final_error or "Secrets detected in tool output",
                    "hookSpecificOutput": {
                        "hookEventName": "PostToolUse",
                        "additionalContext": "Tool output contained sensitive information and was blocked by ai-guardian",
                    },
                }
            else:
                response = {}
                if warning_message:
                    response["systemMessage"] = warning_message
                    if "hookSpecificOutput" not in response:
                        response["hookSpecificOutput"] = {"hookEventName": "PostToolUse"}
                    response["hookSpecificOutput"]["additionalContext"] = warning_message
                if modified_output is not None:
                    if "hookSpecificOutput" not in response:
                        response["hookSpecificOutput"] = {"hookEventName": "PostToolUse"}
                    response["hookSpecificOutput"]["updatedToolOutput"] = modified_output
                    response["hookSpecificOutput"]["updatedMCPToolOutput"] = modified_output
        elif hook_event == HookEvent.PROMPT:
            if has_secrets and error_message:
                response = {
                    "decision": "block",
                    "reason": final_error,
                    "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
                }
            else:
                response = {}
                parts = []
                if security_message:
                    parts.append(security_message)
                if warning_message:
                    parts.append(warning_message)
                if parts:
                    combined = "\n\n".join(parts)
                    response["systemMessage"] = combined
                    response["hookSpecificOutput"] = {
                        "hookEventName": "UserPromptSubmit",
                        "additionalContext": combined,
                    }
        else:
            # PreToolUse
            if has_secrets and error_message:
                response = {
                    "hookSpecificOutput": {
                        "permissionDecision": "deny",
                        "hookEventName": "PreToolUse",
                    },
                    "systemMessage": final_error,
                }
            elif warning_message:
                response = {
                    "systemMessage": warning_message,
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "additionalContext": warning_message,
                    },
                }
            else:
                response = {}

        return self._add_metadata(
            {"output": json.dumps(response), "exit_code": 0},
            has_secrets,
            violation_type,
        )
