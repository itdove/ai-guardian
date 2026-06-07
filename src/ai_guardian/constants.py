"""Constants for AI Guardian.

Centralizes string constants used across multiple modules to prevent
typos and provide IDE discoverability.
"""

from enum import Enum


class ActionMode(str, Enum):
    """Action modes for security policy enforcement."""
    BLOCK = "block"
    WARN = "warn"
    LOG_ONLY = "log-only"
    REDACT = "redact"


class ViolationType(str, Enum):
    """Violation types logged by the violation logger."""
    SECRET_DETECTED = "secret_detected"
    PII_DETECTED = "pii_detected"
    DIRECTORY_BLOCKING = "directory_blocking"
    TOOL_PERMISSION = "tool_permission"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_DETECTED = "jailbreak_detected"
    SSRF_BLOCKED = "ssrf_blocked"
    CONFIG_FILE_EXFIL = "config_file_exfil"
    SECRET_REDACTION = "secret_redaction"
    SECRET_IN_TRANSCRIPT = "secret_in_transcript"
    PII_IN_TRANSCRIPT = "pii_in_transcript"
    IMAGE_SECRET_DETECTED = "image_secret_detected"
    IMAGE_PII_DETECTED = "image_pii_detected"
    CONTEXT_POISONING = "context_poisoning"


class HookEvent(str, Enum):
    """Hook event types from IDE integrations."""
    PROMPT = "prompt"
    PRE_TOOL_USE = "pretooluse"
    POST_TOOL_USE = "posttooluse"
    BEFORE_READ_FILE = "beforereadfile"
    STOP = "stop"


AUGMENT_TOOL_MAP = {
    "launch-process": "Bash",
    "str-replace-editor": "Edit",
    "save-file": "Write",
    "view": "Read",
    "remove-files": "Delete",
}

ALL_VIOLATION_TYPES = tuple(v.value for v in ViolationType)
ALL_HOOK_EVENTS = tuple(e.value for e in HookEvent)
ALL_ACTION_MODES = tuple(a.value for a in ActionMode)
