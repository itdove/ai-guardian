"""
AI Guardian Daemon Service.

Long-running daemon that processes hook requests over Unix socket (or TCP on
Windows), eliminating per-invocation Python startup overhead and enabling
cross-hook state sharing between PreToolUse and PostToolUse events.
"""

import os
import shutil
import sys

from ai_guardian.config_utils import get_config_dir, get_state_dir

DEFAULT_REST_PORT = 63152


def is_pid_alive(pid):
    """Check if a process with the given PID is running.

    Args:
        pid: Process ID to check

    Returns:
        bool: True if the process exists
    """
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def get_executable_command():
    """Resolve the command to launch ai-guardian.

    Returns:
        list: Command list, e.g. ['/usr/local/bin/ai-guardian'] or
              ['/usr/bin/python', '-m', 'ai_guardian']
    """
    path = shutil.which("ai-guardian")
    if path:
        return [os.path.abspath(path)]
    return [sys.executable, "-m", "ai_guardian"]


def get_socket_path():
    """Get the Unix socket path for daemon IPC."""
    return get_state_dir() / "daemon.sock"


def get_pid_path():
    """Get the PID file path for daemon process tracking."""
    return get_state_dir() / "daemon.pid"


def get_tray_targets_path():
    """Get the path for manual tray daemon targets config."""
    return get_config_dir() / "tray-targets.json"
