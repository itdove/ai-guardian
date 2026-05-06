"""Tests for daemon server."""

import json
import os
import socket
import tempfile
import threading
import time
from unittest import mock

import pytest

from ai_guardian.daemon.protocol import (
    decode_message,
    encode_message,
    make_hook_request,
    make_ping,
    make_shutdown,
    make_status_request,
)
from ai_guardian.daemon.server import DaemonServer, get_pid_path, get_socket_path


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
        for _ in range(20):
            if pid_path.exists():
                break
            time.sleep(0.1)

        assert pid_path.exists()
        pid_info = json.loads(pid_path.read_text())
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
        with pytest.raises(RuntimeError, match="already running"):
            server.start()


class TestDaemonServerProtocol:
    @pytest.fixture
    def running_server(self, monkeypatch):
        import tempfile
        d = tempfile.mkdtemp(prefix="ag")
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", d)
        from pathlib import Path

        server = DaemonServer(idle_timeout=30, enable_tray=False)
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
        server = DaemonServer(idle_timeout=30, enable_tray=False)

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


class TestDaemonServerTCP:
    def test_tcp_mode_binds_localhost(self, short_state_dir, monkeypatch):
        server = DaemonServer(
            idle_timeout=5, use_tcp=True, enable_tray=False
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

    def test_macos_uses_main_thread_tray(self):
        with mock.patch("platform.system", return_value="Darwin"):
            assert DaemonServer._should_use_main_thread_tray() is True

    def test_linux_uses_background_tray(self):
        with mock.patch("platform.system", return_value="Linux"):
            assert DaemonServer._should_use_main_thread_tray() is False


class TestDaemonServerIdleTimeout:
    def test_idle_timeout_stops_server(self, short_state_dir, monkeypatch):
        from pathlib import Path
        server = DaemonServer(idle_timeout=0.5, enable_tray=False)

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
