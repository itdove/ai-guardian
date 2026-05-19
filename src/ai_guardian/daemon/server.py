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

from ai_guardian.daemon import get_pid_path, get_socket_path
from ai_guardian.daemon.protocol import (
    decode_message,
    encode_message,
    make_pong,
    make_response,
)
from ai_guardian.daemon.state import DaemonState

logger = logging.getLogger(__name__)

IDLE_CHECK_INTERVAL = 60  # seconds


def _is_pid_alive(pid):
    """Check if a process with the given PID is running."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


class DaemonServer:
    """Long-running daemon server for ai-guardian."""

    def __init__(self, idle_timeout=1800.0, use_tcp=False,
                 enable_rest_api=True):
        """Initialize daemon server.

        Args:
            idle_timeout: Seconds of inactivity before auto-stop (0 to disable)
            use_tcp: Force TCP mode (auto-detected on Windows)
            enable_rest_api: Enable REST API for tray/remote queries
        """
        self._use_tcp = use_tcp or (platform.system() == "Windows")
        self._enable_rest_api = enable_rest_api
        self._server_socket = None
        self._running = False
        self._shutdown_event = threading.Event()
        self._rest_api = None
        self._rest_port = 0
        self._tcp_port = 0
        self.state = DaemonState(idle_timeout=idle_timeout)

    def start(self):
        """Start the daemon server (blocking).

        Sets up signal handlers, creates socket, and enters accept loop.
        The daemon runs headless — use 'ai-guardian tray' for the system
        tray client.
        """
        self._cleanup_stale()
        self._write_pid_file()
        self._setup_signals()
        self._server_socket = self._setup_socket()
        self._running = True

        if self._enable_rest_api:
            self._start_rest_api()

        idle_thread = threading.Thread(
            target=self._idle_check_loop, daemon=True, name="idle-checker"
        )
        idle_thread.start()

        sock_info = self._socket_info()
        name_info = f", name={self._daemon_name}" if hasattr(self, '_daemon_name') else ""
        logger.info(f"Daemon started (pid {os.getpid()}, {sock_info}{name_info})")
        print(f"ai-guardian daemon started (pid {os.getpid()}, {sock_info}{name_info})")
        print("Use 'ai-guardian tray' to start the system tray client")

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

        # Flush pending session state to disk before cleanup (#592)
        try:
            self.state.flush_sessions()
        except Exception as e:
            logger.debug(f"Error flushing session state: {e}")

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

        # Stop REST API
        if self._rest_api:
            try:
                self._rest_api.stop()
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
            return {"output": "{}", "exit_code": 0}

        self.state.record_activity()

        cwd = hook_data.pop("_daemon_cwd", None)
        if cwd:
            from ai_guardian.config_utils import set_project_dir_override, clear_project_dir_override
            from ai_guardian.config_loaders import _clear_config_cache
            set_project_dir_override(cwd)
            _clear_config_cache()

        try:
            self.state.get_config()
            self.state.check_project_config(cwd)

            from ai_guardian import process_hook_data
            result = process_hook_data(hook_data, daemon_state=self.state)
        finally:
            if cwd:
                clear_project_dir_override()
                _clear_config_cache()

        # Track stats
        exit_code = result.get("exit_code", 0)
        violation_type = result.get("_violation_type")
        if exit_code != 0 or result.get("_blocked"):
            self.state.record_blocked(violation_type=violation_type)
            session_key = hook_data.get("session_id") or hook_data.get("transcript_path")
            if session_key:
                self.state.mark_security_reinject(session_key)
        elif result.get("_warning"):
            self.state.record_warning()
        elif result.get("_log_only"):
            for _ in range(result["_log_only"]):
                self.state.record_log_only()

        # Strip internal metadata before returning to client
        result.pop("_blocked", None)
        result.pop("_warning", None)
        result.pop("_log_only", None)
        result.pop("_violation_type", None)
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
        if self._rest_port:
            pid_info["rest_port"] = self._rest_port
        if hasattr(self, '_daemon_name') and self._daemon_name:
            pid_info["name"] = self._daemon_name
        pid_path.write_text(json.dumps(pid_info))
        os.chmod(str(pid_path), 0o600)

    def _start_rest_api(self):
        """Start the REST API server for tray/remote queries."""
        try:
            from ai_guardian.daemon.rest_api import DaemonRestAPI
            from ai_guardian.daemon import DEFAULT_REST_PORT
            from ai_guardian.config_loaders import _load_config_file

            daemon_cfg = {}
            try:
                cfg, _err = _load_config_file()
                if cfg:
                    daemon_cfg = cfg.get("daemon", {})
            except Exception:
                pass

            self._daemon_name = daemon_cfg.get("name")
            cfg_port = daemon_cfg.get("rest_port", DEFAULT_REST_PORT)

            default_host = "127.0.0.1"
            if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
                default_host = "0.0.0.0"
            host = daemon_cfg.get("rest_host", default_host)
            self._rest_api = DaemonRestAPI(
                state=self.state, host=host, port=cfg_port,
                daemon_name=self._daemon_name,
            )
            self._rest_port = self._rest_api.start()
            self._write_pid_file()
            logger.info(f"REST API started on port {self._rest_port}")
        except Exception as e:
            logger.debug(f"REST API failed to start: {e}")

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

    def _socket_info(self):
        """Get human-readable socket info string."""
        if self._use_tcp:
            return f"tcp://127.0.0.1:{self._tcp_port}"
        return f"unix://{get_socket_path()}"
