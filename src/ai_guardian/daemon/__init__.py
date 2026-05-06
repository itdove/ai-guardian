"""
AI Guardian Daemon Service.

Long-running daemon that processes hook requests over Unix socket (or TCP on
Windows), eliminating per-invocation Python startup overhead and enabling
cross-hook state sharing between PreToolUse and PostToolUse events.
"""
