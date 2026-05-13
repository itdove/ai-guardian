"""
AI Guardian Daemon Service.

Long-running daemon that processes hook requests over Unix socket (or TCP on
Windows), eliminating per-invocation Python startup overhead and enabling
cross-hook state sharing between PreToolUse and PostToolUse events.
"""

from ai_guardian.config_utils import get_state_dir


def get_socket_path():
    """Get the Unix socket path for daemon IPC."""
    return get_state_dir() / "daemon.sock"


def get_pid_path():
    """Get the PID file path for daemon process tracking."""
    return get_state_dir() / "daemon.pid"
