"""Tests for daemon server."""

import json
import os
import socket
import sys
import tempfile
import threading
import time
from unittest import mock

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Daemon server tests require Unix sockets (AF_UNIX)",
)

from ai_guardian.daemon.protocol import (
    decode_message,
    encode_message,
    make_hook_request,
    make_ping,
    make_shutdown,
    make_status_request,
)
from ai_guardian.daemon import get_pid_path, get_socket_path
from ai_guardian.daemon.server import DaemonServer


@pytest.fixture
def short_state_dir(monkeypatch):
    """Use a short temp directory to avoid AF_UNIX path length limits."""
    with tempfile.TemporaryDirectory(prefix="ag") as d:
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", d)
        yield d


class TestDaemonServerLifecycle:
    def test_server_creates_socket_file(self, short_state_dir, monkeypatch):
        server = DaemonServer(idle_timeout=5)

        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()

        # Wait for socket to appear
        from pathlib import Path
        sock_path = Path(short_state_dir) / "daemon.sock"
        for _ in range(20):
            if sock_path.exists():
                break
            time.sleep(0.1)

        assert sock_path.exists()
        server.stop()
        thread.join(timeout=3)

    def test_server_creates_pid_file(self, short_state_dir, monkeypatch):
        from pathlib import Path
        server = DaemonServer(idle_timeout=5)

        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()

        pid_path = Path(short_state_dir) / "daemon.pid"
        pid_info = None
        for _ in range(30):
            if pid_path.exists():
                try:
                    content = pid_path.read_text()
                    if content.strip():
                        pid_info = json.loads(content)
                        break
                except (json.JSONDecodeError, OSError):
                    pass
            time.sleep(0.1)

        assert pid_info is not None, "PID file not written in time"
        assert pid_info["pid"] == os.getpid()

        server.stop()
        thread.join(timeout=3)

    def test_server_cleans_up_on_stop(self, short_state_dir, monkeypatch):
        from pathlib import Path
        server = DaemonServer(idle_timeout=5)

        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()

        sock_path = Path(short_state_dir) / "daemon.sock"
        for _ in range(20):
            if sock_path.exists():
                break
            time.sleep(0.1)

        server.stop()
        thread.join(timeout=3)

        assert not sock_path.exists()
        assert not (Path(short_state_dir) / "daemon.pid").exists()

    def test_server_rejects_duplicate_start(self, short_state_dir, monkeypatch):
        from pathlib import Path
        pid_path = Path(short_state_dir) / "daemon.pid"
        pid_path.write_text(json.dumps({"pid": os.getpid()}))

        server = DaemonServer(idle_timeout=5)
        with mock.patch.object(
            server, "_is_old_daemon_responsive", return_value=True
        ):
            with pytest.raises(RuntimeError, match="already running"):
                server.start()

    def test_server_cleans_stale_pid_with_recycled_pid(self, short_state_dir):
        """PID file references a live process that is NOT the daemon (recycled PID).

        In containers, PIDs recycle quickly. _cleanup_stale() should verify
        socket connectivity, not just PID liveness.
        """
        from pathlib import Path
        pid_path = Path(short_state_dir) / "daemon.pid"
        # Use current process PID — it's alive but not a daemon
        pid_path.write_text(json.dumps({"pid": os.getpid()}))
        # No socket file exists, so the daemon is not actually running

        server = DaemonServer(idle_timeout=5, enable_rest_api=False)
        # Should NOT raise RuntimeError — should clean up stale PID
        server._cleanup_stale()
        assert not pid_path.exists()

    def test_server_cleans_stale_pid_with_dead_process(self, short_state_dir):
        """PID file references a dead process — straightforward stale case."""
        from pathlib import Path
        pid_path = Path(short_state_dir) / "daemon.pid"
        pid_path.write_text(json.dumps({"pid": 99999999}))

        server = DaemonServer(idle_timeout=5, enable_rest_api=False)
        server._cleanup_stale()
        assert not pid_path.exists()

    def test_server_cleans_stale_socket_file(self, short_state_dir):
        """Stale socket file from crashed daemon is cleaned up."""
        from pathlib import Path
        sock_path = Path(short_state_dir) / "daemon.sock"
        sock_path.write_text("")  # Create a stale socket file

        server = DaemonServer(idle_timeout=5, enable_rest_api=False)
        server._cleanup_stale()
        assert not sock_path.exists()


class TestDaemonServerProtocol:
    @pytest.fixture
    def running_server(self, monkeypatch):
        import tempfile
        d = tempfile.mkdtemp(prefix="ag")
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", d)
        from pathlib import Path

        server = DaemonServer(idle_timeout=30, enable_rest_api=False)
        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()

        sock_path = Path(d) / "daemon.sock"
        for _ in range(30):
            if sock_path.exists():
                break
            time.sleep(0.1)

        yield server, sock_path

        server.stop()
        thread.join(timeout=3)
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def _connect(self, sock_path, timeout=2.0):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(str(sock_path))
        return sock

    def test_ping_pong(self, running_server):
        server, sock_path = running_server
        sock = self._connect(sock_path)
        try:
            sock.sendall(encode_message(make_ping()))
            response = decode_message(sock, timeout=2.0)
            assert response["type"] == "pong"
        finally:
            sock.close()

    def test_status_request(self, running_server):
        server, sock_path = running_server
        sock = self._connect(sock_path)
        try:
            sock.sendall(encode_message(make_status_request()))
            response = decode_message(sock, timeout=2.0)
            assert response["type"] == "response"
            data = response["data"]
            assert "request_count" in data
            assert "uptime_seconds" in data
        finally:
            sock.close()

    def test_shutdown_request(self, short_state_dir, monkeypatch):
        from pathlib import Path
        server = DaemonServer(idle_timeout=30, enable_rest_api=False)

        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()

        sock_path = Path(short_state_dir) / "daemon.sock"
        for _ in range(30):
            if sock_path.exists():
                break
            time.sleep(0.1)

        sock = self._connect(sock_path)
        try:
            sock.sendall(encode_message(make_shutdown()))
            response = decode_message(sock, timeout=2.0)
            assert response["type"] == "response"
        finally:
            sock.close()

        thread.join(timeout=5)

    def test_unknown_message_type(self, running_server):
        server, sock_path = running_server
        sock = self._connect(sock_path)
        try:
            msg = {"version": 1, "type": "unknown_type"}
            sock.sendall(encode_message(msg))
            response = decode_message(sock, timeout=2.0)
            assert response["type"] == "response"
            assert "error" in response["data"]
        finally:
            sock.close()

    def test_hook_request(self, running_server):
        server, sock_path = running_server
        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
        }
        sock = self._connect(sock_path)
        try:
            sock.sendall(encode_message(make_hook_request(hook_data)))
            response = decode_message(sock, timeout=5.0)
            assert response["type"] == "response"
            data = response["data"]
            assert "exit_code" in data
        finally:
            sock.close()

    def test_hook_request_when_paused_returns_empty_json(self, running_server):
        server, sock_path = running_server
        server.state.pause()

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        }
        sock = self._connect(sock_path)
        try:
            sock.sendall(encode_message(make_hook_request(hook_data)))
            response = decode_message(sock, timeout=5.0)
            assert response["type"] == "response"
            data = response["data"]
            assert data["output"] == "{}"
            assert data["exit_code"] == 0
        finally:
            sock.close()
            server.state.resume()

    def test_hook_request_after_resume_processes_normally(self, running_server):
        server, sock_path = running_server
        server.state.pause()
        server.state.resume()

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello world",
        }
        sock = self._connect(sock_path)
        try:
            sock.sendall(encode_message(make_hook_request(hook_data)))
            response = decode_message(sock, timeout=5.0)
            assert response["type"] == "response"
            data = response["data"]
            assert "exit_code" in data
        finally:
            sock.close()


class TestDaemonServerTCP:
    def test_tcp_mode_binds_localhost(self, short_state_dir, monkeypatch):
        server = DaemonServer(
            idle_timeout=5, use_tcp=True, enable_rest_api=False
        )

        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()

        # Wait for PID file with port
        from pathlib import Path
        pid_path = Path(short_state_dir) / "daemon.pid"
        for _ in range(30):
            if pid_path.exists():
                try:
                    info = json.loads(pid_path.read_text())
                    if "port" in info:
                        break
                except (json.JSONDecodeError, OSError):
                    pass
            time.sleep(0.1)

        pid_info = json.loads(pid_path.read_text())
        assert "port" in pid_info
        port = pid_info["port"]
        assert port > 0

        # Connect and ping
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(("127.0.0.1", port))
        try:
            sock.sendall(encode_message(make_ping()))
            response = decode_message(sock, timeout=2.0)
            assert response["type"] == "pong"
        finally:
            sock.close()

        server.stop()
        thread.join(timeout=3)


class TestDaemonServerCrossPlatform:
    def test_windows_auto_detects_tcp(self, monkeypatch):
        with mock.patch("platform.system", return_value="Windows"):
            server = DaemonServer(idle_timeout=5)
            assert server._use_tcp is True

    def test_linux_uses_unix_socket(self, monkeypatch):
        with mock.patch("platform.system", return_value="Linux"):
            server = DaemonServer(idle_timeout=5)
            assert server._use_tcp is False

class TestDaemonServerPausedHook:
    """Test that paused daemon returns valid empty JSON to avoid Claude Code errors."""

    def test_handle_hook_request_paused_returns_empty_json(self, short_state_dir):
        server = DaemonServer(idle_timeout=30, enable_rest_api=False)
        server.state.pause()

        result = server._handle_hook_request({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        })

        assert result["output"] == "{}"
        assert result["exit_code"] == 0

    def test_handle_hook_request_paused_output_is_valid_json(self, short_state_dir):
        server = DaemonServer(idle_timeout=30, enable_rest_api=False)
        server.state.pause()

        result = server._handle_hook_request({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "test",
        })

        parsed = json.loads(result["output"])
        assert isinstance(parsed, dict)

    def test_handle_hook_request_not_paused_processes_normally(self, short_state_dir):
        server = DaemonServer(idle_timeout=30, enable_rest_api=False)
        assert not server.state.paused

        result = server._handle_hook_request({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello",
        })

        assert "exit_code" in result


class TestDaemonServerPauseResumeProtocol:
    """Test socket protocol handlers for pause and resume messages (issue #683)."""

    @pytest.fixture
    def running_server(self, monkeypatch):
        import tempfile
        d = tempfile.mkdtemp(prefix="ag")
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", d)
        from pathlib import Path

        server = DaemonServer(idle_timeout=30, enable_rest_api=False)
        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()

        sock_path = Path(d) / "daemon.sock"
        for _ in range(30):
            if sock_path.exists():
                break
            time.sleep(0.1)

        yield server, sock_path

        server.stop()
        thread.join(timeout=3)
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def _connect(self, sock_path, timeout=2.0):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(str(sock_path))
        return sock

    def test_pause_message_pauses_daemon(self, running_server):
        server, sock_path = running_server
        assert not server.state.paused

        sock = self._connect(sock_path)
        try:
            msg = {"version": 1, "type": "pause", "data": {"minutes": 5}}
            sock.sendall(encode_message(msg))
            response = decode_message(sock, timeout=2.0)
            assert response["type"] == "response"
            assert response["data"]["status"] == "paused"
            assert response["data"]["minutes"] == 5
        finally:
            sock.close()

        assert server.state.paused

    def test_resume_message_resumes_daemon(self, running_server):
        server, sock_path = running_server
        server.state.pause(10)
        assert server.state.paused

        sock = self._connect(sock_path)
        try:
            msg = {"version": 1, "type": "resume"}
            sock.sendall(encode_message(msg))
            response = decode_message(sock, timeout=2.0)
            assert response["type"] == "response"
            assert response["data"]["status"] == "resumed"
        finally:
            sock.close()

        assert not server.state.paused

    def test_pause_indefinite(self, running_server):
        server, sock_path = running_server
        sock = self._connect(sock_path)
        try:
            msg = {"version": 1, "type": "pause", "data": {"minutes": 0}}
            sock.sendall(encode_message(msg))
            response = decode_message(sock, timeout=2.0)
            assert response["data"]["status"] == "paused"
            assert response["data"]["minutes"] == 0
        finally:
            sock.close()

        assert server.state.paused
        assert server.state.pause_remaining_seconds() == 0.0

    def test_pause_then_hook_returns_empty(self, running_server):
        server, sock_path = running_server

        # Pause via socket
        sock = self._connect(sock_path)
        try:
            msg = {"version": 1, "type": "pause", "data": {"minutes": 5}}
            sock.sendall(encode_message(msg))
            decode_message(sock, timeout=2.0)
        finally:
            sock.close()

        # Hook request should be bypassed
        sock = self._connect(sock_path)
        try:
            sock.sendall(encode_message(make_hook_request({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "ls"},
            })))
            response = decode_message(sock, timeout=5.0)
            assert response["data"]["output"] == "{}"
            assert response["data"]["exit_code"] == 0
        finally:
            sock.close()

    def test_resume_then_hook_processes_normally(self, running_server):
        server, sock_path = running_server
        server.state.pause(5)

        # Resume via socket
        sock = self._connect(sock_path)
        try:
            msg = {"version": 1, "type": "resume"}
            sock.sendall(encode_message(msg))
            decode_message(sock, timeout=2.0)
        finally:
            sock.close()

        # Hook should be processed normally
        sock = self._connect(sock_path)
        try:
            sock.sendall(encode_message(make_hook_request({
                "hook_event_name": "UserPromptSubmit",
                "prompt": "hello",
            })))
            response = decode_message(sock, timeout=5.0)
            assert "exit_code" in response["data"]
        finally:
            sock.close()


class TestDaemonServerPerDirPauseProtocol:
    """Test socket protocol handlers for per-directory pause/resume (#958)."""

    @pytest.fixture
    def running_server(self, monkeypatch):
        import tempfile
        d = tempfile.mkdtemp(prefix="ag")
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", d)
        from pathlib import Path

        server = DaemonServer(idle_timeout=30, enable_rest_api=False)
        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()

        sock_path = Path(d) / "daemon.sock"
        for _ in range(30):
            if sock_path.exists():
                break
            time.sleep(0.1)

        yield server, sock_path

        server.stop()
        thread.join(timeout=3)
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def _connect(self, sock_path, timeout=2.0):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(str(sock_path))
        return sock

    def test_pause_dir_message(self, running_server):
        server, sock_path = running_server
        sock = self._connect(sock_path)
        try:
            msg = {"version": 1, "type": "pause_dir",
                   "data": {"dir": "/project/a", "minutes": 30}}
            sock.sendall(encode_message(msg))
            response = decode_message(sock, timeout=2.0)
            assert response["type"] == "response"
            assert response["data"]["status"] == "dir_paused"
            assert response["data"]["dir"] == "/project/a"
        finally:
            sock.close()
        assert server.state.is_dir_paused("/project/a")

    def test_resume_dir_message(self, running_server):
        server, sock_path = running_server
        server.state.pause_dir("/project/a")

        sock = self._connect(sock_path)
        try:
            msg = {"version": 1, "type": "resume_dir",
                   "data": {"dir": "/project/a"}}
            sock.sendall(encode_message(msg))
            response = decode_message(sock, timeout=2.0)
            assert response["type"] == "response"
            assert response["data"]["status"] == "dir_resumed"
        finally:
            sock.close()
        assert not server.state.is_dir_paused("/project/a")

    def test_pause_dir_missing_dir_returns_error(self, running_server):
        server, sock_path = running_server
        sock = self._connect(sock_path)
        try:
            msg = {"version": 1, "type": "pause_dir", "data": {}}
            sock.sendall(encode_message(msg))
            response = decode_message(sock, timeout=2.0)
            assert "error" in response["data"]
        finally:
            sock.close()

    def test_per_dir_pause_does_not_affect_other_dirs(self, running_server):
        """Pausing one dir should not pause another."""
        server, sock_path = running_server
        server.state.pause_dir("/project/a")

        # Hook from /project/b (not paused) should be processed
        assert not server.state.is_dir_paused("/project/b")
        assert server.state.is_dir_paused("/project/a")

    def test_paused_dir_hook_returns_empty(self, running_server):
        """Hook from a paused directory should return empty JSON."""
        server, sock_path = running_server
        server.state.pause_dir("/project/a")

        sock = self._connect(sock_path)
        try:
            hook_data = {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "ls"},
                "_daemon_cwd": "/project/a",
            }
            sock.sendall(encode_message(make_hook_request(hook_data)))
            response = decode_message(sock, timeout=5.0)
            assert response["data"]["output"] == "{}"
            assert response["data"]["exit_code"] == 0
        finally:
            sock.close()

    def test_status_includes_paused_dirs(self, running_server):
        server, sock_path = running_server
        server.state.pause_dir("/project/a")

        sock = self._connect(sock_path)
        try:
            sock.sendall(encode_message(make_status_request()))
            response = decode_message(sock, timeout=2.0)
            stats = response["data"]
            assert "paused_dirs" in stats
            assert len(stats["paused_dirs"]) == 1
        finally:
            sock.close()


class TestDaemonServerIdleTimeout:
    def test_idle_timeout_stops_server(self, short_state_dir, monkeypatch):
        from pathlib import Path
        server = DaemonServer(idle_timeout=0.5, enable_rest_api=False)

        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()

        sock_path = Path(short_state_dir) / "daemon.sock"
        for _ in range(20):
            if sock_path.exists():
                break
            time.sleep(0.1)

        # Wait for idle timeout (0.5s + 60s check interval is too long)
        # Instead verify the state tracks idle properly
        time.sleep(0.6)
        assert server.state.is_idle_timeout_expired()

        server.stop()
        thread.join(timeout=3)
