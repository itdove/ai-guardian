"""CLI and daemon handler functions for AI Guardian.

These functions were extracted from hook_processing.py to reduce
cross-module coupling. They handle CLI subcommands and daemon
configuration — not hook processing logic.
"""

import json
import logging
import os
import sys
from pathlib import Path

from ai_guardian.config_utils import get_config_dir
from ai_guardian.config_loaders import _load_config_file
from ai_guardian.constants import ViolationType


def _handle_violations_command(args):
    """
    Handle the violations subcommand.

    Args:
        args: Parsed command-line arguments

    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    from ai_guardian.violation_logger import ViolationLogger

    violation_logger = ViolationLogger()

    # Handle --clear
    if args.clear:
        if args.yes:
            confirm = "y"
        else:
            confirm = input("Are you sure you want to clear all violations? [y/N] ")
        if confirm.lower() == 'y':
            if violation_logger.clear_log():
                print("Violations log cleared successfully")
                return 0
            else:
                print("Error: Failed to clear violations log", file=sys.stderr)
                return 1
        else:
            print("Cancelled")
            return 0

    # Handle --export
    if args.export:
        export_path = Path(args.export)
        if violation_logger.export_violations(export_path, violation_type=args.type):
            print(f"Violations exported to {export_path}")
            return 0
        else:
            print(f"Error: Failed to export violations to {export_path}", file=sys.stderr)
            return 1

    # Display violations
    violations = violation_logger.get_recent_violations(
        limit=args.limit,
        violation_type=args.type,
        resolved=False  # Only show unresolved violations by default
    )

    if not violations:
        print("No recent violations found")
        return 0

    # Format and display violations
    print(f"\nRecent Violations (last {len(violations)}):\n")

    for v in violations:
        timestamp = v.get("timestamp", "Unknown")
        vtype = v.get("violation_type", "unknown").upper().replace("_", " ")
        severity = v.get("severity", "warning").upper()
        blocked = v.get("blocked", {})
        suggestion = v.get("suggestion", {})

        # Format severity with color indicators
        severity_indicator = {
            "WARNING": "⚠",
            "HIGH": "🔴",
            "CRITICAL": "🔒"
        }.get(severity, "•")

        print(f"[{timestamp}] {severity_indicator} {vtype} ({severity.lower()})")

        # Display blocked details based on violation type
        if v.get("violation_type") == ViolationType.TOOL_PERMISSION:
            tool_name = blocked.get("tool_name", "Unknown")
            tool_value = blocked.get("tool_value", "")
            reason = blocked.get("reason", "")
            print(f"  Tool: {tool_name}/{tool_value}")
            if blocked.get("file_path"):
                print(f"  File: {blocked['file_path']}")
            print(f"  Reason: {reason}")

        elif v.get("violation_type") == ViolationType.DIRECTORY_BLOCKING:
            file_path = blocked.get("file_path", "Unknown")
            denied_dir = blocked.get("denied_directory", "")
            print(f"  File: {file_path}")
            print(f"  Denied by: {denied_dir}/.ai-read-deny")

        elif v.get("violation_type") == ViolationType.SECRET_DETECTED:
            source = blocked.get("source", "unknown")
            file_path = blocked.get("file_path")
            if file_path:
                location = f"  File: {file_path}"
                line_number = blocked.get("line_number")
                if line_number:
                    end_line = blocked.get("end_line")
                    if end_line and end_line != line_number:
                        location += f" (lines {line_number}-{end_line})"
                    else:
                        location += f" (line {line_number})"
                print(location)
            else:
                print(f"  Source: {source}")
            secret_type = blocked.get("secret_type", "Unknown")
            print(f"  Secret type: {secret_type}")

        elif v.get("violation_type") in (ViolationType.PROMPT_INJECTION, ViolationType.JAILBREAK_DETECTED):
            source = blocked.get("source", "unknown")
            pattern = blocked.get("pattern", "Unknown")
            print(f"  Type: {'Jailbreak' if v.get('violation_type') == ViolationType.JAILBREAK_DETECTED else 'Injection'}")
            if blocked.get("file_path"):
                print(f"  File: {blocked['file_path']}")
            else:
                print(f"  Source: {source}")
            print(f"  Pattern: {pattern}")

        # Display suggestion
        action = suggestion.get("action", "")
        if action:
            print(f"  → Suggestion: {action}")

        print()

    print("To allow blocked operations, run: ai-guardian console (when available)")
    print("Or manually edit: ~/.config/ai-guardian/ai-guardian.json\n")

    return 0


def _get_daemon_mode():
    """Get daemon mode from environment variable or config.

    Returns:
        str: "auto", "local", or "daemon"
    """
    valid_modes = ("auto", "local", "daemon")
    env_mode = os.environ.get("AI_GUARDIAN_DAEMON_MODE", "").lower()
    if env_mode in valid_modes:
        return env_mode

    try:
        config, _ = _load_config_file()
        if config:
            daemon_config = config.get("daemon", {})
            mode = daemon_config.get("mode", "auto")
            if mode in valid_modes:
                return mode
    except Exception:
        pass

    return "auto"


def _get_client_timeout():
    """Get daemon client timeout from config.

    Returns:
        float: Timeout in seconds (default 2.0, range 0.5-10.0)
    """
    try:
        config, _ = _load_config_file()
        if config:
            daemon_config = config.get("daemon", {})
            timeout = daemon_config.get("client_timeout_seconds", 2.0)
            try:
                timeout = float(timeout)
            except (TypeError, ValueError):
                return 2.0
            return max(0.5, min(10.0, timeout))
    except Exception:
        pass
    return 2.0


def _set_daemon_mode_in_config(mode):
    """Update daemon mode in the config file."""
    try:
        config_path = get_config_dir() / "ai-guardian.json"
        if config_path.exists():
            config = json.loads(config_path.read_text(encoding="utf-8"))
        else:
            config = {}
        if "daemon" not in config:
            config["daemon"] = {}
        config["daemon"]["mode"] = mode
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        logging.info(f"Daemon mode set to '{mode}'")
    except Exception as e:
        logging.warning(f"Failed to update daemon mode in config: {e}")


def _handle_daemon_command(args):
    """Handle daemon subcommands (start, stop, status, restart)."""
    cmd = getattr(args, "daemon_command", None)

    if cmd == "start":
        _set_daemon_mode_in_config("auto")
        if args.background:
            from ai_guardian.daemon.client import start_daemon_background

            if start_daemon_background():
                print("ai-guardian daemon started (mode set to 'auto')")
                return 0
            else:
                print("Failed to start daemon in background", file=sys.stderr)
                return 1
        else:
            from ai_guardian.daemon.server import DaemonServer

            idle_timeout = (args.idle_timeout or 30) * 60
            server = DaemonServer(
                idle_timeout=idle_timeout,
                enable_tray=not args.no_tray,
            )
            try:
                server.start()
            except RuntimeError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            return 0

    elif cmd == "stop":
        from ai_guardian.daemon.client import is_daemon_running, send_shutdown

        _set_daemon_mode_in_config("local")
        if not is_daemon_running():
            print("ai-guardian daemon is not running (mode set to 'local')")
            return 0

        if send_shutdown(timeout=_get_client_timeout()):
            print("ai-guardian daemon stopped (mode set to 'local')")
            return 0
        else:
            print("Failed to stop daemon", file=sys.stderr)
            return 1

    elif cmd == "status":
        from ai_guardian.daemon.client import is_daemon_running, send_status_request
        from ai_guardian.daemon import get_pid_path, get_socket_path

        if not is_daemon_running():
            print("ai-guardian daemon: not running")
            return 1

        stats = send_status_request(timeout=_get_client_timeout())
        if stats:
            uptime = stats.get("uptime_seconds", 0)
            hours = int(uptime // 3600)
            minutes = int((uptime % 3600) // 60)
            uptime_str = f"{hours}h {minutes}m" if hours else f"{minutes}m"

            pid_path = get_pid_path()
            pid = "unknown"
            try:
                import json as _json
                pid_info = _json.loads(pid_path.read_text())
                pid = pid_info.get("pid", "unknown")
            except Exception:
                pass

            blocked = stats.get("blocked_count", 0)
            req_count = stats.get("request_count", 0)
            paused = " (PAUSED)" if stats.get("paused") else ""

            reload_ago = stats.get("last_config_reload_seconds_ago")
            if reload_ago is not None:
                reload_secs = int(reload_ago)
                if reload_secs < 60:
                    reload_str = f"{reload_secs}s ago"
                elif reload_secs < 3600:
                    reload_str = f"{reload_secs // 60}m ago"
                elif reload_secs < 86400:
                    reload_str = f"{reload_secs // 3600}h ago"
                else:
                    reload_str = f"{reload_secs // 86400}d ago"
                config_str = f"loaded (last reload: {reload_str})"
            else:
                config_str = "loaded"

            print(f"ai-guardian daemon: running (pid {pid}){paused}")
            print(f"Uptime: {uptime_str}")
            print(f"Hooks processed: {req_count} ({blocked} blocked)")
            print(f"Config: {config_str}")
            print(f"Mode: {_get_daemon_mode()} (daemon active)")

            sock_path = get_socket_path()
            if sock_path.exists():
                print(f"Socket: {sock_path}")
            elif stats.get("port"):
                print(f"TCP: 127.0.0.1:{stats['port']}")

            project_count = stats.get("project_configs_tracked", 0)
            project_reload_ago = stats.get("last_project_config_reload_seconds_ago")
            if project_count > 0:
                if project_reload_ago is not None:
                    pr_secs = int(project_reload_ago)
                    if pr_secs < 60:
                        pr_str = f"{pr_secs}s ago"
                    elif pr_secs < 3600:
                        pr_str = f"{pr_secs // 60}m ago"
                    elif pr_secs < 86400:
                        pr_str = f"{pr_secs // 3600}h ago"
                    else:
                        pr_str = f"{pr_secs // 86400}d ago"
                    print(f"Project configs tracked: {project_count} (last reload: {pr_str})")
                else:
                    print(f"Project configs tracked: {project_count}")

            print(f"Active contexts: {stats.get('active_contexts', 0)}")
            print(f"Cached patterns: {stats.get('cached_patterns', 0)}")
        else:
            print("ai-guardian daemon: running (could not fetch stats)")
        return 0

    elif cmd == "restart":
        from ai_guardian.daemon.client import is_daemon_running, send_shutdown

        if is_daemon_running():
            send_shutdown(timeout=_get_client_timeout())
            import time
            time.sleep(0.5)

        # Re-invoke start in foreground
        args.daemon_command = "start"
        args.background = False
        if not hasattr(args, "idle_timeout"):
            args.idle_timeout = None
        if not hasattr(args, "no_tray"):
            args.no_tray = False
        return _handle_daemon_command(args)

    else:
        print("Usage: ai-guardian daemon {start|stop|status|restart}")
        return 1
