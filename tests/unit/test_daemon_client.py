"""Tests for daemon client."""

import json
import os
import socket
import tempfile
import threading
import time
from unittest import mock

import pytest

from ai_guardian.daemon.client import (
    get_pid_path,
    get_socket_path,
    is_daemon_running,
    send_hook_request,
    send_reload_config,
    send_shutdown,
    send_status_request,
    start_daemon_background,
)
from ai_guardian.daemon.protocol import (
    decode_message,
    encode_message,
    make_pong,
    make_response,
)


@pytest.fixture
def short_state_dir(monkeypatch):
    """Use a short temp directory to avoid AF_UNIX path length limits."""
    with tempfile.TemporaryDirectory(prefix="ag") as d:
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", d)
        yield d


class TestIsDaemonRunning:
    def test_no_pid_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", str(tmp_path))
        assert not is_daemon_running()

    def test_stale_pid_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", str(tmp_path))
        pid_path = tmp_path / "daemon.pid"
        pid_path.write_text(json.dumps({"pid": 99999999}))
        assert not is_daemon_running()

    def test_pid_alive_but_no_socket(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", str(tmp_path))
        pid_path = tmp_path / "daemon.pid"
        pid_path.write_text(json.dumps({"pid": os.getpid()}))
        # PID exists but no socket to connect to
        assert not is_daemon_running()


class TestSendHookRequest:
    def test_returns_none_when_no_daemon(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", str(tmp_path))
        result = send_hook_request({"prompt": "test"}, timeout=0.5)
        assert result is None

    def test_returns_none_on_timeout(self, short_state_dir):
        from pathlib import Path

        sock_path = Path(short_state_dir) / "daemon.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(1)

        try:
            result = send_hook_request({"prompt": "test"}, timeout=0.3)
            assert result is None
        finally:
            server.close()
            sock_path.unlink(missing_ok=True)

    def test_successful_request(self, short_state_dir):
        from pathlib import Path

        sock_path = Path(short_state_dir) / "daemon.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(1)

        response_data = {"output": None, "exit_code": 0}

        def mock_server():
            conn, _ = server.accept()
            try:
                request = decode_message(conn, timeout=2.0)
                response = make_response(response_data)
                conn.sendall(encode_message(response))
            finally:
                conn.close()

        thread = threading.Thread(target=mock_server, daemon=True)
        thread.start()

        try:
            result = send_hook_request({"prompt": "test"}, timeout=2.0)
            assert result == response_data
        finally:
            server.close()
            thread.join(timeout=3)


class TestSendShutdown:
    def test_returns_false_when_no_daemon(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", str(tmp_path))
        assert not send_shutdown()


class TestSendStatusRequest:
    def test_returns_none_when_no_daemon(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", str(tmp_path))
        assert send_status_request() is None


class TestSendReloadConfig:
    def test_returns_false_when_no_daemon(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", str(tmp_path))
        assert not send_reload_config()


class TestStartDaemonBackground:
    def test_returns_false_on_popen_failure(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", str(tmp_path))
        with mock.patch(
            "ai_guardian.daemon.client._find_executable",
            return_value=["/nonexistent/ai-guardian"],
        ):
            with mock.patch(
                "subprocess.Popen", side_effect=OSError("not found")
            ):
                assert not start_daemon_background()


class TestTCPConnection:
    def test_tcp_connect_reads_port_from_pid(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", str(tmp_path))

        # Set up a TCP server
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server.bind(("127.0.0.1", 0))
        tcp_server.listen(1)
        port = tcp_server.getsockname()[1]

        # Write PID file with port
        pid_path = tmp_path / "daemon.pid"
        pid_path.write_text(json.dumps({"pid": os.getpid(), "port": port}))

        response_data = {"output": None, "exit_code": 0}

        def mock_server():
            conn, _ = tcp_server.accept()
            try:
                request = decode_message(conn, timeout=2.0)
                conn.sendall(encode_message(make_response(response_data)))
            finally:
                conn.close()

        thread = threading.Thread(target=mock_server, daemon=True)
        thread.start()

        try:
            # Mock platform to Windows to force TCP path
            with mock.patch("ai_guardian.daemon.client.platform") as mock_platform:
                mock_platform.system.return_value = "Windows"

                result = send_hook_request({"prompt": "test"}, timeout=2.0)
                assert result == response_data
        finally:
            tcp_server.close()
            thread.join(timeout=3)
