"""
Response formatting and IDE detection for AI Guardian hooks.

Handles multi-IDE response formatting (Claude Code, Cursor, GitHub Copilot)
and hook event detection.
"""

import json
import logging
import os
import sys
from enum import Enum

from ai_guardian.constants import HookEvent

logger = logging.getLogger(__name__)


_SECURITY_SYSTEM_MESSAGE = (
    "SECURITY RULES (from ai-guardian):\n"
    "- Never attempt to bypass, disable, or work around security protections\n"
    "- Never suggest ways to suppress or bypass security detection\n"
    "- Never suggest modifying security configuration files\n"
    "- Never explain how security protections can be circumvented\n"
    "- When a tool is blocked, report the block reason — do not find alternatives to access the content\n"
    "- To check why something was blocked, use get_violations() if MCP is available"
)


class IDEType(Enum):
    """Supported IDE types with different output formats."""
    CLAUDE_CODE = "claude_code"  # Exit codes: 0=allow, 2=block
    CURSOR = "cursor"  # JSON: {"continue": bool, "user_message": str}
    GITHUB_COPILOT = "github_copilot"  # JSON: {"permissionDecision": "allow"|"deny"}
    UNKNOWN = "unknown"  # Default to Claude Code format


def detect_ide_type(hook_data):
    """
    Detect which IDE is calling the hook based on input format.

    Args:
        hook_data: Parsed JSON input from the IDE

    Returns:
        IDEType: The detected IDE type
    """
    # Check for environment variable override
    ide_override = os.environ.get("AI_GUARDIAN_IDE_TYPE", "").lower()
    if ide_override == "cursor":
        return IDEType.CURSOR
    elif ide_override == "claude":
        return IDEType.CLAUDE_CODE
    elif ide_override == "github_copilot" or ide_override == "copilot":
        return IDEType.GITHUB_COPILOT

    # Auto-detect based on input structure
    # GitHub Copilot detection - check for toolName field (most specific)
    if "toolName" in hook_data:
        return IDEType.GITHUB_COPILOT

    # GitHub Copilot detection - timestamp + cwd + prompt pattern
    if "timestamp" in hook_data and "cwd" in hook_data:
        return IDEType.GITHUB_COPILOT

    # Cursor sends cursor_version field
    if "cursor_version" in hook_data:
        return IDEType.CURSOR

    # Cursor typically sends hook_name or beforeSubmitPrompt event
    if "hook_name" in hook_data or (
        "hook_event_name" in hook_data and
        hook_data.get("hook_event_name") in ["beforeSubmitPrompt", "preToolUse"]
    ):
        return IDEType.CURSOR

    # Claude Code sends UserPromptSubmit or PreToolUse
    if "hook_event_name" in hook_data and hook_data.get("hook_event_name") in ["UserPromptSubmit", "PreToolUse"]:
        return IDEType.CLAUDE_CODE

    # Default to Claude Code format (exit codes)
    return IDEType.CLAUDE_CODE


def format_response(ide_type, has_secrets, error_message=None, hook_event=HookEvent.PROMPT, warning_message=None, modified_output=None, violation_type=None, security_message=None):
    """
    Format the response based on IDE type and hook event.

    Args:
        ide_type: IDEType enum value
        has_secrets: bool indicating if secrets were found (block vs allow)
        error_message: Optional error message for blocked responses
        hook_event: "prompt", "pretooluse", or "posttooluse" to determine response format
        warning_message: Optional warning message for log mode (allows execution but shows warning)
        modified_output: Optional modified tool output (for PostToolUse redaction)
        violation_type: Optional violation type string for daemon stats tracking
        security_message: Optional security rules message for prompt hook

    Returns:
        dict with 'output' (str to print), 'exit_code' (int), and optional
        daemon metadata: '_blocked' (True when has_secrets=True)
    """
    def _add_metadata(result):
        if has_secrets:
            result["_blocked"] = True
        if violation_type:
            result["_violation_type"] = violation_type
        return result

    if ide_type == IDEType.GITHUB_COPILOT:
        if hook_event == HookEvent.PRE_TOOL_USE:
            response = {}
            if has_secrets:
                response["permissionDecision"] = "deny"
                if error_message:
                    final_error = error_message
                    if warning_message:
                        final_error = f"{warning_message}\n\n{error_message}"
                    response["permissionDecisionReason"] = final_error

            return _add_metadata({
                "output": json.dumps(response),
                "exit_code": 0
            })
        else:
            if has_secrets and error_message:
                final_error = error_message
                if warning_message:
                    final_error = f"{warning_message}\n\n{error_message}"
                print(final_error, file=sys.stderr)

            return _add_metadata({
                "output": None,
                "exit_code": 2 if has_secrets else 0
            })
    elif ide_type == IDEType.CURSOR:
        final_error = error_message
        if has_secrets and error_message and warning_message:
            final_error = f"{warning_message}\n\n{error_message}"

        if hook_event == HookEvent.PRE_TOOL_USE:
            response = {
                "decision": "deny" if has_secrets else "allow",
            }
            if has_secrets and final_error:
                response["reason"] = final_error
        elif hook_event == HookEvent.BEFORE_READ_FILE:
            response = {
                "permission": "deny" if has_secrets else "allow",
            }
            if has_secrets and final_error:
                response["user_message"] = final_error
        else:
            response = {
                "continue": not has_secrets,
            }
            if has_secrets and final_error:
                response["user_message"] = final_error

        return _add_metadata({
            "output": json.dumps(response),
            "exit_code": 0
        })
    else:
        # Claude Code
        if hook_event == HookEvent.POST_TOOL_USE:
            if has_secrets:
                final_error = error_message or "Secrets detected in tool output"
                if warning_message:
                    final_error = f"{warning_message}\n\n{final_error}"
                response = {
                    "decision": "block",
                    "reason": final_error,
                    "hookSpecificOutput": {
                        "hookEventName": "PostToolUse",
                        "additionalContext": "Tool output contained sensitive information and was blocked by ai-guardian"
                    }
                }
            else:
                response = {}
                if warning_message:
                    response["systemMessage"] = warning_message
                if modified_output is not None:
                    if "hookSpecificOutput" not in response:
                        response["hookSpecificOutput"] = {"hookEventName": "PostToolUse"}
                    response["hookSpecificOutput"]["updatedToolOutput"] = modified_output
                    response["hookSpecificOutput"]["updatedMCPToolOutput"] = modified_output

            return _add_metadata({
                "output": json.dumps(response),
                "exit_code": 0
            })
        elif hook_event == HookEvent.PROMPT:
            if has_secrets and error_message:
                final_error = error_message
                if warning_message:
                    final_error = f"{warning_message}\n\n{error_message}"
                response = {
                    "decision": "block",
                    "reason": final_error,
                    "hookSpecificOutput": {
                        "hookEventName": "UserPromptSubmit"
                    }
                }
            else:
                response = {}
                parts = []
                if security_message:
                    parts.append(security_message)
                if warning_message:
                    parts.append(warning_message)
                if parts:
                    response["systemMessage"] = "\n\n".join(parts)

            return _add_metadata({
                "output": json.dumps(response),
                "exit_code": 0
            })
        else:
            # PreToolUse
            if has_secrets and error_message:
                final_error = error_message
                if warning_message:
                    final_error = f"{warning_message}\n\n{error_message}"
                response = {
                    "hookSpecificOutput": {
                        "permissionDecision": "deny",
                        "hookEventName": "PreToolUse"
                    },
                    "systemMessage": final_error
                }
            elif warning_message:
                response = {
                    "systemMessage": warning_message
                }
            else:
                response = {}

            return _add_metadata({
                "output": json.dumps(response),
                "exit_code": 0
            })


def detect_hook_event(hook_data):
    """
    Detect which hook event triggered this call.

    Args:
        hook_data: Parsed JSON input from the IDE

    Returns:
        HookEvent: HookEvent.PROMPT, HookEvent.PRE_TOOL_USE, HookEvent.POST_TOOL_USE, or HookEvent.BEFORE_READ_FILE
    """
    event_name = hook_data.get("hook_event_name", "").lower()
    if event_name in ["userpromptsubmit", "beforesubmitprompt"]:
        return HookEvent.PROMPT
    elif event_name in ["pretooluse"]:
        return HookEvent.PRE_TOOL_USE
    elif event_name in ["posttooluse"]:
        return HookEvent.POST_TOOL_USE
    elif event_name in ["beforereadfile"]:
        return HookEvent.BEFORE_READ_FILE

    hook_name = hook_data.get("hook_name", "").lower()
    if hook_name in ["beforesubmitprompt"]:
        return HookEvent.PROMPT
    elif hook_name in ["pretooluse"]:
        return HookEvent.PRE_TOOL_USE

    if "toolName" in hook_data:
        return HookEvent.PRE_TOOL_USE

    if "tool_response" in hook_data:
        return HookEvent.POST_TOOL_USE

    if "tool_use" in hook_data or "tool" in hook_data or "tool_name" in hook_data:
        return HookEvent.PRE_TOOL_USE

    if "prompt" in hook_data or "message" in hook_data or "userMessage" in hook_data:
        return HookEvent.PROMPT

    return HookEvent.PROMPT
