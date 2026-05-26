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
    except PermissionError:
        return True
    except (ProcessLookupError, OSError):
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


def get_tray_plugins_dir():
    """Get the directory for tray plugin JSON files."""
    return get_config_dir() / "tray-plugins"


_IDE_MCP_CONFIGS = [
    ("~/.claude.json", "mcpServers"),
    ("~/.claude/settings.json", "mcpServers"),
    ("~/.cursor/mcp.json", "mcpServers"),
    ("~/.windsurf/mcp.json", "mcpServers"),
    ("~/.gemini/settings.json", "mcpServers"),
    ("~/.cline/mcp_settings.json", "mcpServers"),
    ("~/.augment/settings.json", "mcpServers"),
    ("~/.kiro/settings.json", "mcpServers"),
    ("~/.junie/mcp.json", "mcpServers"),
    ("~/.aider-desk/settings.json", "mcpServers"),
    ("~/.openclaw/settings.json", "mcpServers"),
]


def get_local_menu_tags():
    """Get menu_tags from the local daemon config for plugin filtering."""
    try:
        from ai_guardian.config_loaders import _load_config_file
        cfg, _ = _load_config_file()
        if cfg:
            tags = cfg.get("menu_tags")
            if isinstance(tags, list):
                return [t for t in tags if isinstance(t, str) and t]
    except Exception:
        pass
    return []


def is_mcp_installed():
    """Check if ai-guardian MCP server is configured in any supported IDE."""
    import json
    from pathlib import Path

    for config_file, key in _IDE_MCP_CONFIGS:
        try:
            path = Path(config_file).expanduser()
            if path.exists():
                config = json.loads(path.read_text(encoding="utf-8"))
                if "ai-guardian" in config.get(key, {}):
                    return True
        except Exception:
            continue
    return False
