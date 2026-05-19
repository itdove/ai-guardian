"""
AI Guardian Daemon Service.

Long-running daemon that processes hook requests over Unix socket (or TCP on
Windows), eliminating per-invocation Python startup overhead and enabling
cross-hook state sharing between PreToolUse and PostToolUse events.
"""

from ai_guardian.config_utils import get_config_dir, get_state_dir

DEFAULT_REST_PORT = 63152


def get_socket_path():
    """Get the Unix socket path for daemon IPC."""
    return get_state_dir() / "daemon.sock"


def get_pid_path():
    """Get the PID file path for daemon process tracking."""
    return get_state_dir() / "daemon.pid"


def get_tray_targets_path():
    """Get the path for manual tray daemon targets config."""
    return get_config_dir() / "tray-targets.json"
