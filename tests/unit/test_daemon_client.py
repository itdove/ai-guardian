"""Tests for daemon client."""

import json
import os
import socket
import sys
import tempfile
import threading
import time
from unittest import mock

import pytest

_skip_no_unix_socket = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="AF_UNIX not available on Windows",
)

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


@_skip_no_unix_socket
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

    def test_injects_daemon_cwd(self, short_state_dir):
        """send_hook_request includes _daemon_cwd in the hook data."""
        from pathlib import Path

        sock_path = Path(short_state_dir) / "daemon.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(1)

        received_data = {}

        def mock_server():
            conn, _ = server.accept()
            try:
                request = decode_message(conn, timeout=2.0)
                received_data.update(request.get("data", {}))
                response = make_response({"output": "{}", "exit_code": 0})
                conn.sendall(encode_message(response))
            finally:
                conn.close()

        thread = threading.Thread(target=mock_server, daemon=True)
        thread.start()

        try:
            send_hook_request({"prompt": "test"}, timeout=2.0)
            assert "_daemon_cwd" in received_data
            assert received_data["_daemon_cwd"] == os.getcwd()
        finally:
            server.close()
            thread.join(timeout=3)

    def test_does_not_mutate_caller_dict(self, short_state_dir):
        """send_hook_request should not add _daemon_cwd to caller's dict."""
        from pathlib import Path

        sock_path = Path(short_state_dir) / "daemon.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(1)

        def mock_server():
            conn, _ = server.accept()
            try:
                decode_message(conn, timeout=2.0)
                response = make_response({"output": "{}", "exit_code": 0})
                conn.sendall(encode_message(response))
            finally:
                conn.close()

        thread = threading.Thread(target=mock_server, daemon=True)
        thread.start()

        original = {"prompt": "test"}
        try:
            send_hook_request(original, timeout=2.0)
            assert "_daemon_cwd" not in original
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

    def test_skips_when_stop_requested(self, tmp_path, monkeypatch):
        """Issue #775: auto-start respects stop-requested marker."""
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", str(tmp_path))
        marker = tmp_path / "daemon.stop-requested"
        marker.touch()
        with mock.patch("subprocess.Popen") as mock_popen:
            assert not start_daemon_background()
        mock_popen.assert_not_called()


class TestClientTimeout:
    """Tests for _get_client_timeout() config reading."""

    def test_default_when_no_config(self):
        from ai_guardian import _get_client_timeout

        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(None, None)):
            assert _get_client_timeout() == 2.0

    def test_reads_from_config(self):
        from ai_guardian import _get_client_timeout

        config = {"daemon": {"client_timeout_seconds": 5.0}}
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(config, None)):
            assert _get_client_timeout() == 5.0

    def test_clamped_low(self):
        from ai_guardian import _get_client_timeout

        config = {"daemon": {"client_timeout_seconds": 0.1}}
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(config, None)):
            assert _get_client_timeout() == 0.5

    def test_clamped_high(self):
        from ai_guardian import _get_client_timeout

        config = {"daemon": {"client_timeout_seconds": 99.0}}
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(config, None)):
            assert _get_client_timeout() == 10.0

    def test_invalid_type_returns_default(self):
        from ai_guardian import _get_client_timeout

        config = {"daemon": {"client_timeout_seconds": "not a number"}}
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(config, None)):
            assert _get_client_timeout() == 2.0

    def test_missing_daemon_section(self):
        from ai_guardian import _get_client_timeout

        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=({}, None)):
            assert _get_client_timeout() == 2.0

    def test_hook_forwarding_passes_config_timeout(self):
        config = {"daemon": {"client_timeout_seconds": 3.5, "mode": "auto"}}
        with mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=(config, None)):
            with mock.patch(
                "ai_guardian.daemon.client.is_daemon_running", return_value=True
            ):
                with mock.patch(
                    "ai_guardian.daemon.client.send_hook_request",
                    return_value={"output": None, "exit_code": 0},
                ) as mock_send:
                    from ai_guardian import _get_client_timeout

                    mock_send({"prompt": "test"}, timeout=_get_client_timeout())
                    mock_send.assert_called_once_with(
                        {"prompt": "test"}, timeout=3.5
                    )


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


class TestIsPidAlive:
    def test_own_process_is_alive(self):
        from ai_guardian.daemon import is_pid_alive

        assert is_pid_alive(os.getpid())

    def test_nonexistent_pid(self):
        from ai_guardian.daemon import is_pid_alive

        assert not is_pid_alive(99999999)

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows uses ctypes, not os.kill")
    def test_permission_error_means_alive(self):
        from ai_guardian.daemon import is_pid_alive

        with mock.patch("os.kill", side_effect=PermissionError("EPERM")):
            assert is_pid_alive(12345)

    def test_process_lookup_error_means_dead(self):
        from ai_guardian.daemon import is_pid_alive

        with mock.patch("os.kill", side_effect=ProcessLookupError("ESRCH")):
            assert not is_pid_alive(12345)


class TestStartDaemonBackgroundNoClientCleanup:
    def test_start_background_does_not_call_cleanup(self, tmp_path, monkeypatch):
        """start_daemon_background() delegates cleanup to the daemon process."""
        monkeypatch.setenv("AI_GUARDIAN_STATE_DIR", str(tmp_path))
        with mock.patch(
            "ai_guardian.daemon.client._find_executable",
            return_value=["/nonexistent/ai-guardian"],
        ):
            with mock.patch(
                "subprocess.Popen", side_effect=OSError("not found")
            ):
                start_daemon_background()
