"""
Thin client for communicating with the ai-guardian daemon.

Used by hook invocations to forward requests to the running daemon
instead of processing them in-process.
"""

import json
import logging
import os
import platform
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path

from ai_guardian.daemon import get_pid_path, get_socket_path, is_pid_alive
from ai_guardian.daemon.protocol import (
    decode_message,
    encode_message,
    make_hook_request,
    make_ping,
    make_shutdown,
    make_status_request,
    make_reload_config,
)

logger = logging.getLogger(__name__)


def is_daemon_running():
    """Check if the daemon is running by testing PID file and socket connectivity.

    Returns:
        bool: True if daemon is running and responsive
    """
    pid_path = get_pid_path()
    if not pid_path.exists():
        return False

    try:
        pid_info = json.loads(pid_path.read_text())
        pid = pid_info.get("pid", 0)
        if not pid:
            return False

        # Check if process exists
        if not is_pid_alive(pid):
            return False

        # Verify socket connectivity with a ping
        sock = _connect(timeout=1.0)
        if sock is None:
            return False

        try:
            sock.sendall(encode_message(make_ping()))
            response = decode_message(sock, timeout=1.0)
            return response.get("type") == "pong"
        finally:
            sock.close()

    except (json.JSONDecodeError, OSError, Exception):
        return False


def send_hook_request(hook_data, timeout=2.0):
    """Send hook data to daemon and get response.

    Args:
        hook_data: Parsed JSON hook data from IDE
        timeout: Connection + response timeout in seconds

    Returns:
        dict or None: Response with 'output' and 'exit_code', or None on failure
    """
    try:
        sock = _connect(timeout)
        if sock is None:
            return None

        try:
            hook_data = {**hook_data, "_daemon_cwd": os.getcwd()}
            request = make_hook_request(hook_data)
            sock.sendall(encode_message(request))
            response = decode_message(sock, timeout=timeout)

            if response.get("type") == "response":
                return response.get("data")
            return None
        finally:
            sock.close()

    except (socket.error, socket.timeout, ConnectionError, ValueError):
        return None
    except Exception as e:
        logger.debug(f"Daemon request failed: {e}")
        return None


def send_shutdown(timeout=2.0):
    """Send shutdown request to the daemon.

    Args:
        timeout: Connection + response timeout in seconds

    Returns:
        bool: True if shutdown was acknowledged
    """
    try:
        sock = _connect(timeout=timeout)
        if sock is None:
            return False

        try:
            sock.sendall(encode_message(make_shutdown()))
            response = decode_message(sock, timeout=timeout)
            return response.get("type") == "response"
        finally:
            sock.close()
    except Exception:
        return False


def send_status_request(timeout=2.0):
    """Request daemon status/stats.

    Args:
        timeout: Connection + response timeout in seconds

    Returns:
        dict or None: Daemon stats, or None on failure
    """
    try:
        sock = _connect(timeout=timeout)
        if sock is None:
            return None

        try:
            sock.sendall(encode_message(make_status_request()))
            response = decode_message(sock, timeout=timeout)
            if response.get("type") == "response":
                return response.get("data")
            return None
        finally:
            sock.close()
    except Exception:
        return None


def send_reload_config(timeout=2.0):
    """Request daemon to reload its configuration.

    Args:
        timeout: Connection + response timeout in seconds

    Returns:
        bool: True if reload was acknowledged
    """
    try:
        sock = _connect(timeout=timeout)
        if sock is None:
            return False

        try:
            sock.sendall(encode_message(make_reload_config()))
            response = decode_message(sock, timeout=timeout)
            return response.get("type") == "response"
        finally:
            sock.close()
    except Exception:
        return False


def cleanup_stale_pid():
    """Remove stale PID and socket files if daemon is not actually running.

    Only cleans up when the process referenced by the PID file is truly
    dead.  If the process is alive but the daemon socket is unresponsive,
    the PID file is left intact so the daemon can recover.

    Returns:
        bool: True if a stale PID file was cleaned up
    """
    pid_path = get_pid_path()
    if not pid_path.exists():
        return False

    if is_daemon_running():
        return False

    try:
        pid_info = json.loads(pid_path.read_text())
        pid = pid_info.get("pid", 0)
        if pid and is_pid_alive(pid):
            return False
    except (json.JSONDecodeError, OSError):
        pass

    try:
        pid_path.unlink()
        logger.info("Cleaned up stale PID file")
    except OSError:
        pass

    sock_path = get_socket_path()
    if sock_path.exists():
        try:
            sock_path.unlink()
        except OSError:
            pass

    return True


def start_daemon_background():
    """Start daemon as a background process for lazy start in auto mode.

    Respects the stop-requested marker written by ``daemon stop``.

    Returns:
        bool: True if daemon started successfully
    """
    try:
        # Honour explicit stop — don't auto-restart (#775)
        from ai_guardian.daemon import get_state_dir
        marker = get_state_dir() / "daemon.stop-requested"
        if marker.exists():
            logger.debug("Skipping auto-start: stop-requested marker present")
            return False

        cleanup_stale_pid()

        # Find the ai-guardian command
        cmd = _find_executable()
        daemon_cmd = cmd + ["daemon", "start"]
        logger.info(f"Starting daemon: {' '.join(daemon_cmd)}")

        # Start detached daemon process
        if platform.system() == "Darwin":
            # On macOS, use osascript to launch with GUI session access
            # so the system tray icon can attach to the menu bar
            cmd_str = " ".join(shlex.quote(arg) for arg in daemon_cmd)
            script = f'do shell script "{cmd_str} &> /dev/null &"'
            subprocess.Popen(
                ["osascript", "-e", script],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        elif platform.system() == "Windows":
            subprocess.Popen(
                daemon_cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=(
                    subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW
                ),
            )
        else:
            subprocess.Popen(
                daemon_cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )

        # Wait for daemon to become ready
        sock_path = get_socket_path()
        for _ in range(30):  # up to 3 seconds
            time.sleep(0.1)
            if sock_path.exists() or _tcp_pid_has_port():
                if is_daemon_running():
                    logger.info("Daemon started in background")
                    return True

        logger.warning("Daemon start timed out after 3s")
        return False

    except Exception as e:
        logger.debug(f"Failed to start daemon: {e}")
        return False


def _connect(timeout):
    """Connect to daemon socket (Unix or TCP).

    Args:
        timeout: Connection timeout in seconds

    Returns:
        socket.socket or None: Connected socket, or None on failure
    """
    if platform.system() == "Windows":
        return _connect_tcp(timeout)
    return _connect_unix(timeout)


def _connect_unix(timeout):
    """Connect to Unix domain socket."""
    sock_path = get_socket_path()
    if not sock_path.exists():
        return None

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(str(sock_path))
        return sock
    except (socket.error, OSError):
        return None


def _connect_tcp(timeout):
    """Connect to TCP socket (read port from PID file)."""
    pid_path = get_pid_path()
    if not pid_path.exists():
        return None

    try:
        pid_info = json.loads(pid_path.read_text())
        port = pid_info.get("port")
        if not port:
            return None

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", port))
        return sock
    except (socket.error, OSError, json.JSONDecodeError):
        return None


def _find_executable():
    """Find the ai-guardian command.

    Returns:
        list: Command to invoke ai-guardian
    """
    from ai_guardian.daemon import get_executable_command
    return get_executable_command()


def _tcp_pid_has_port():
    """Check if PID file contains a TCP port (for Windows)."""
    try:
        pid_path = get_pid_path()
        if not pid_path.exists():
            return False
        pid_info = json.loads(pid_path.read_text())
        return "port" in pid_info
    except Exception:
        return False
