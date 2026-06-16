"""Cursor IDE hook adapter.

Cursor uses camelCase event names (beforeSubmitPrompt, preToolUse, etc.)
and JSON responses with decision/permission/continue fields.
"""

import json
from typing import ClassVar, Dict, List, Optional

from ai_guardian.constants import HookEvent
from ai_guardian.hook_adapters.base import HookAdapter, NormalizedHookInput


class CursorAdapter(HookAdapter):
    """Adapter for Cursor IDE.

    Detection: cursor_version field, hook_name field, or camelCase
    hook_event_name values (beforeSubmitPrompt, preToolUse).
    """

    ENV_ALIASES: ClassVar[List[str]] = ["cursor"]

    @property
    def ide_type(self):
        from ai_guardian.response_format import IDEType
        return IDEType.CURSOR

    @property
    def name(self) -> str:
        return "Cursor IDE"

    @classmethod
    def can_handle(cls, hook_data: Dict) -> bool:
        if "cursor_version" in hook_data:
            return True
        if "hook_name" in hook_data:
            return True
        event = hook_data.get("hook_event_name", "")
        return event in ("beforeSubmitPrompt", "preToolUse")

    def normalize_input(self, hook_data: Dict) -> NormalizedHookInput:
        event_name = hook_data.get("hook_event_name", "").lower()
        hook_name = hook_data.get("hook_name", "").lower()

        if event_name in ("beforesubmitprompt",) or hook_name in ("beforesubmitprompt",):
            event = HookEvent.PROMPT
        elif event_name in ("beforereadfile",):
            event = HookEvent.BEFORE_READ_FILE
        elif event_name in ("pretooluse",) or hook_name in ("pretooluse",):
            event = HookEvent.PRE_TOOL_USE
        elif event_name in ("posttooluse",):
            event = HookEvent.POST_TOOL_USE
        else:
            event = HookEvent.PROMPT

        return NormalizedHookInput(
            event=event,
            tool_name=self._extract_tool_name(hook_data),
            tool_input=self._extract_tool_input(hook_data),
            file_path=(
                hook_data.get("file_path")
                or self._extract_file_path_from_tool_input(hook_data)
            ),
            working_dir=hook_data.get("cwd"),
            session_id=hook_data.get("conversation_id") or hook_data.get("session_id"),
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

        if hook_event == HookEvent.PRE_TOOL_USE:
            response = {"permission": "deny" if has_secrets else "allow"}
            if has_secrets and final_error:
                response["user_message"] = final_error
                response["agent_message"] = "Operation blocked by ai-guardian security policy"
        elif hook_event == HookEvent.BEFORE_READ_FILE:
            response = {"permission": "deny" if has_secrets else "allow"}
            if has_secrets and final_error:
                response["user_message"] = final_error
        else:
            response = {"continue": not has_secrets}
            if has_secrets and final_error:
                response["user_message"] = final_error

        return self._add_metadata(
            {"output": json.dumps(response), "exit_code": 0},
            has_secrets,
            violation_type,
        )
