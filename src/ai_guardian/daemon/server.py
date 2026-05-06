"""
Daemon server for ai-guardian.

Listens on a Unix domain socket (or TCP on Windows), accepts hook requests,
processes them via process_hook_data(), and manages lifecycle including
idle timeout and graceful shutdown.
"""

import json
import logging
import os
import platform
import signal
import socket
import sys
import threading
import time
from pathlib import Path

from ai_guardian.config_utils import get_state_dir
from ai_guardian.daemon.protocol import (
    decode_message,
    encode_message,
    make_pong,
    make_response,
)
from ai_guardian.daemon.state import DaemonState

logger = logging.getLogger(__name__)

IDLE_CHECK_INTERVAL = 60  # seconds


def get_socket_path():
    """Get the Unix socket path for daemon IPC."""
    return get_state_dir() / "daemon.sock"


def get_pid_path():
    """Get the PID file path for daemon process tracking."""
    return get_state_dir() / "daemon.pid"


def _is_pid_alive(pid):
    """Check if a process with the given PID is running."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


class DaemonServer:
    """Long-running daemon server for ai-guardian."""

    def __init__(self, idle_timeout=1800.0, use_tcp=False, enable_tray=True):
        """Initialize daemon server.

        Args:
            idle_timeout: Seconds of inactivity before auto-stop (0 to disable)
            use_tcp: Force TCP mode (auto-detected on Windows)
            enable_tray: Enable system tray icon if available
        """
        self._use_tcp = use_tcp or (platform.system() == "Windows")
        self._enable_tray = enable_tray
        self._server_socket = None
        self._running = False
        self._shutdown_event = threading.Event()
        self._tray = None
        self._tcp_port = 0
        self.state = DaemonState(idle_timeout=idle_timeout)

    def start(self):
        """Start the daemon server (blocking).

        Sets up signal handlers, creates socket, and enters accept loop.
        On macOS, the tray icon must run on the main thread (AppKit requirement),
        so the socket server runs in a background thread instead.
        """
        self._cleanup_stale()
        self._write_pid_file()
        self._setup_signals()
        self._server_socket = self._setup_socket()
        self._running = True

        # Start idle check background thread
        idle_thread = threading.Thread(
            target=self._idle_check_loop, daemon=True, name="idle-checker"
        )
        idle_thread.start()

        sock_info = self._socket_info()
        logger.info(f"Daemon started (pid {os.getpid()}, {sock_info})")
        print(f"ai-guardian daemon started (pid {os.getpid()}, {sock_info})")

        if self._enable_tray and self._should_use_main_thread_tray():
            # macOS: tray must run on main thread, socket server in background
            server_thread = threading.Thread(
                target=self._accept_loop_with_error_handling,
                daemon=True,
                name="socket-server",
            )
            server_thread.start()
            self._start_tray_blocking()  # Blocks main thread
            # Tray exited (user quit or stop called) — shut down server
            self.stop()
            server_thread.join(timeout=3)
        else:
            # Linux/Windows/headless: tray in background thread, server on main
            if self._enable_tray:
                self._start_tray()
            try:
                self._accept_loop()
            except Exception as e:
                logger.error(f"Daemon accept loop error: {e}")
            finally:
                self.stop()

    def stop(self):
        """Graceful shutdown."""
        if not self._running:
            return
        self._running = False
        self._shutdown_event.set()
        logger.info("Daemon shutting down...")

        # Close server socket to unblock accept()
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
            self._server_socket = None

        # Cleanup files
        sock_path = get_socket_path()
        if sock_path.exists() and not self._use_tcp:
            try:
                sock_path.unlink()
            except OSError:
                pass

        pid_path = get_pid_path()
        if pid_path.exists():
            try:
                pid_path.unlink()
            except OSError:
                pass

        # Stop tray
        if self._tray:
            try:
                self._tray.stop()
            except Exception:
                pass

        logger.info("Daemon stopped")

    def _setup_socket(self):
        """Create and bind the server socket."""
        if self._use_tcp:
            return self._setup_tcp_socket()
        return self._setup_unix_socket()

    def _setup_unix_socket(self):
        """Create Unix domain socket."""
        sock_path = get_socket_path()
        sock_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove existing socket file
        if sock_path.exists():
            sock_path.unlink()

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(str(sock_path))
        sock.listen(5)
        sock.settimeout(1.0)  # Allow periodic shutdown checks

        # Owner-only permissions
        os.chmod(str(sock_path), 0o600)
        return sock

    def _setup_tcp_socket(self):
        """Create TCP socket on localhost (Windows fallback)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))  # OS assigns port
        sock.listen(5)
        sock.settimeout(1.0)

        self._tcp_port = sock.getsockname()[1]
        # Update PID file with port
        self._write_pid_file()
        logger.info(f"TCP socket bound to 127.0.0.1:{self._tcp_port}")
        return sock

    def _accept_loop(self):
        """Main accept loop — blocks until stop() is called."""
        while self._running:
            try:
                client_sock, addr = self._server_socket.accept()
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock,),
                    daemon=True,
                    name="client-handler",
                )
                thread.start()
            except socket.timeout:
                continue  # Check self._running
            except OSError:
                if self._running:
                    logger.error("Socket accept error")
                break

    def _handle_client(self, client_sock):
        """Handle a single client connection."""
        try:
            request = decode_message(client_sock, timeout=5.0)
            msg_type = request.get("type", "")

            if msg_type == "hook":
                response_data = self._handle_hook_request(request.get("data", {}))
                response = make_response(response_data)
            elif msg_type == "ping":
                response = make_pong()
            elif msg_type == "shutdown":
                response = make_response({"status": "shutting_down"})
                client_sock.sendall(encode_message(response))
                client_sock.close()
                self.stop()
                return
            elif msg_type == "status":
                response = make_response(self.state.get_stats())
            elif msg_type == "reload_config":
                self.state.force_reload_config()
                response = make_response({"status": "config_reloaded"})
            else:
                response = make_response(
                    {"error": f"Unknown message type: {msg_type}"}
                )

            client_sock.sendall(encode_message(response))
        except (ConnectionError, ValueError, OSError) as e:
            logger.debug(f"Client connection error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error handling client: {e}")
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

    def _handle_hook_request(self, hook_data):
        """Process a hook request through existing ai-guardian logic.

        Args:
            hook_data: Parsed JSON hook data from IDE

        Returns:
            dict: Response with 'output' and 'exit_code'
        """
        if self.state.paused:
            return {"output": None, "exit_code": 0}

        self.state.record_activity()

        from ai_guardian import process_hook_data
        result = process_hook_data(hook_data)

        # Track stats
        exit_code = result.get("exit_code", 0)
        if exit_code != 0 or result.get("_blocked"):
            self.state.record_blocked()
        elif result.get("_warning"):
            self.state.record_warning()
        elif result.get("_log_only"):
            for _ in range(result["_log_only"]):
                self.state.record_log_only()

        # Strip internal metadata before returning to client
        result.pop("_blocked", None)
        result.pop("_warning", None)
        result.pop("_log_only", None)
        return result

    def _idle_check_loop(self):
        """Background thread: check idle timeout and cleanup expired contexts."""
        while not self._shutdown_event.is_set():
            self._shutdown_event.wait(IDLE_CHECK_INTERVAL)
            if self._shutdown_event.is_set():
                break

            self.state.cleanup_expired_contexts()

            if self.state.is_idle_timeout_expired():
                logger.info("Idle timeout reached, shutting down daemon")
                self.stop()
                break

    def _setup_signals(self):
        """Set up signal handlers for graceful shutdown."""
        if threading.current_thread() is not threading.main_thread():
            return
        try:
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
        except (OSError, ValueError):
            pass  # Signals not available (e.g., non-main thread on some platforms)

    def _signal_handler(self, signum, frame):
        """Handle SIGTERM/SIGINT for graceful shutdown."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def _write_pid_file(self):
        """Write PID file with process info."""
        pid_path = get_pid_path()
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_info = {"pid": os.getpid()}
        if self._use_tcp and self._tcp_port:
            pid_info["port"] = self._tcp_port
        pid_path.write_text(json.dumps(pid_info))

    def _cleanup_stale(self):
        """Clean up stale socket and PID files from crashed daemon."""
        pid_path = get_pid_path()
        if pid_path.exists():
            try:
                pid_info = json.loads(pid_path.read_text())
                old_pid = pid_info.get("pid", 0)
                if old_pid and _is_pid_alive(old_pid):
                    raise RuntimeError(
                        f"Daemon already running (pid {old_pid}). "
                        f"Stop it first with: ai-guardian daemon stop"
                    )
                # Stale PID file — clean up
                pid_path.unlink()
                logger.info(f"Cleaned up stale PID file (pid {old_pid})")
            except (json.JSONDecodeError, OSError):
                pid_path.unlink(missing_ok=True)

        sock_path = get_socket_path()
        if sock_path.exists() and not self._use_tcp:
            sock_path.unlink()
            logger.info("Cleaned up stale socket file")

    def _start_tray(self):
        """Start system tray icon in a background thread."""
        try:
            from ai_guardian.daemon.tray import DaemonTray, is_tray_available

            if not is_tray_available():
                logger.debug("System tray not available")
                return

            self._tray = DaemonTray(
                get_stats_callback=self.state.get_stats,
                stop_callback=self.stop,
                pause_callback=self._pause_for,
            )
            self._tray.start()
            logger.info("System tray icon started")
        except Exception as e:
            logger.debug(f"System tray failed to start: {e}")

    def _start_tray_blocking(self):
        """Start system tray icon on the current (main) thread.

        Used on macOS where AppKit requires the tray to run on the main thread.
        This call blocks until the tray is stopped (user quits or daemon stops).
        """
        try:
            from ai_guardian.daemon.tray import DaemonTray, is_tray_available

            if not is_tray_available():
                logger.debug("System tray not available, running headless")
                # Block on shutdown event instead so daemon doesn't exit
                self._shutdown_event.wait()
                return

            self._tray = DaemonTray(
                get_stats_callback=self.state.get_stats,
                stop_callback=self.stop,
                pause_callback=self._pause_for,
            )
            logger.info("System tray icon starting on main thread (macOS)")
            self._tray.run_blocking()  # Blocks until tray exits
        except Exception as e:
            logger.debug(f"System tray failed: {e}")
            # Fall back to blocking on shutdown event
            self._shutdown_event.wait()

    def _accept_loop_with_error_handling(self):
        """Wrapper around _accept_loop that catches exceptions."""
        try:
            self._accept_loop()
        except Exception as e:
            logger.error(f"Daemon accept loop error: {e}")
            self.stop()

    @staticmethod
    def _should_use_main_thread_tray():
        """Check if the tray icon needs to run on the main thread.

        macOS requires AppKit/NSApplication to run on the main thread.
        """
        return platform.system() == "Darwin"

    def _pause_for(self, duration_minutes):
        """Pause or resume scanning.

        Args:
            duration_minutes: Minutes to pause. 0 = resume, -1 = indefinite.
        """
        if duration_minutes < 0:
            self.state.pause(0)  # 0 = indefinite in state API
            if self._tray:
                self._tray.update_status("paused")
        elif duration_minutes > 0:
            self.state.pause(duration_minutes)
            if self._tray:
                self._tray.update_status("paused")
        else:
            self.state.resume()
            if self._tray:
                self._tray.update_status("running")

    def _socket_info(self):
        """Get human-readable socket info string."""
        if self._use_tcp:
            return f"tcp://127.0.0.1:{self._tcp_port}"
        return f"unix://{get_socket_path()}"
