"""Tests for multi-daemon client routing."""

from unittest import mock

import pytest

from ai_guardian.daemon.discovery import DaemonTarget
from ai_guardian.daemon.multi_client import MultiDaemonClient


class TestLocalRouting:
    @mock.patch("ai_guardian.daemon.client.send_status_request")
    def test_status_via_socket(self, mock_status):
        mock_status.return_value = {"request_count": 100}
        client = MultiDaemonClient()
        target = DaemonTarget(name="local", runtime="local")
        result = client.get_status(target)
        assert result == {"request_count": 100}
        mock_status.assert_called_once()

    @mock.patch("subprocess.Popen")
    @mock.patch("shutil.which", return_value="/usr/bin/ai-guardian")
    def test_restart_local(self, mock_which, mock_popen):
        client = MultiDaemonClient()
        target = DaemonTarget(name="local", runtime="local")
        result = client.send_restart(target)
        assert result is True
        mock_popen.assert_called_once()


class TestLocalPauseResumeRouting:
    """Test local daemon pause/resume via socket (issue #683)."""

    @mock.patch.object(MultiDaemonClient, "_local_socket_send", return_value=True)
    def test_pause_local_sends_socket_message(self, mock_send):
        client = MultiDaemonClient()
        target = DaemonTarget(name="local", runtime="local")
        result = client.send_pause(target, 5)
        assert result is True
        mock_send.assert_called_once_with(
            {"version": 1, "type": "pause", "data": {"minutes": 5}}
        )

    @mock.patch.object(MultiDaemonClient, "_local_socket_send", return_value=True)
    def test_resume_local_sends_socket_message(self, mock_send):
        client = MultiDaemonClient()
        target = DaemonTarget(name="local", runtime="local")
        result = client.send_resume(target)
        assert result is True
        mock_send.assert_called_once_with(
            {"version": 1, "type": "resume"}
        )

    @mock.patch.object(MultiDaemonClient, "_local_socket_send", return_value=False)
    def test_pause_local_returns_false_on_failure(self, mock_send):
        client = MultiDaemonClient()
        target = DaemonTarget(name="local", runtime="local")
        result = client.send_pause(target, 10)
        assert result is False


class TestContainerRouting:
    def test_status_via_rest(self):
        client = MultiDaemonClient()
        target = DaemonTarget(
            name="test", runtime="container",
            host="127.0.0.1", port=49200,
            container_id="abc123def456abc123", container_engine="podman"
        )
        with mock.patch.object(
            client, "_rest_request",
            return_value={"request_count": 50}
        ):
            result = client.get_status(target)
            assert result == {"request_count": 50}

    def test_pause_via_rest(self):
        client = MultiDaemonClient()
        target = DaemonTarget(
            name="test", runtime="container",
            host="127.0.0.1", port=49200,
            container_id="abc123def456abc123", container_engine="podman"
        )
        with mock.patch.object(
            client, "_rest_request",
            return_value={"status": "paused"}
        ):
            result = client.send_pause(target, 15)
            assert result is True

    @mock.patch("subprocess.run")
    def test_restart_via_podman_exec(self, mock_run):
        mock_run.return_value = mock.MagicMock(returncode=0, stdout="ok", stderr="")
        client = MultiDaemonClient()
        target = DaemonTarget(
            name="test", runtime="container",
            container_id="abc123def456abc123", container_engine="podman"
        )
        result = client.send_restart(target)
        assert result is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "podman"
        assert "exec" in cmd
        assert "abc123def456abc123" in cmd

    @mock.patch("subprocess.run")
    def test_support_via_container_exec(self, mock_run):
        mock_run.return_value = mock.MagicMock(
            returncode=0, stdout="bundle ready", stderr=""
        )
        client = MultiDaemonClient()
        target = DaemonTarget(
            name="test", runtime="container",
            container_id="abc789def012abc789", container_engine="docker"
        )
        result = client.export_support(target)
        assert result == "bundle ready"
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "docker"

    @mock.patch("subprocess.Popen")
    @mock.patch("platform.system", return_value="Linux")
    @mock.patch("shutil.which", return_value="/usr/bin/gnome-terminal")
    def test_console_via_podman_exec(self, mock_which, mock_platform, mock_popen):
        client = MultiDaemonClient()
        target = DaemonTarget(
            name="test", runtime="container",
            container_id="abc123def456abc123", container_engine="podman"
        )
        client.open_console(target)
        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        assert "podman" in cmd
        assert "exec" in cmd
        assert "-it" in cmd


class TestKubernetesRouting:
    @mock.patch("subprocess.run")
    def test_restart_via_kubectl_exec(self, mock_run):
        mock_run.return_value = mock.MagicMock(returncode=0, stdout="ok", stderr="")
        client = MultiDaemonClient()
        target = DaemonTarget(
            name="test", runtime="kubernetes",
            pod_name="guardian-abc", namespace="ai-sdlc"
        )
        result = client.send_restart(target)
        assert result is True
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "kubectl"
        assert "exec" in cmd
        assert "guardian-abc" in cmd
        assert "-n" in cmd
        assert "ai-sdlc" in cmd

    @mock.patch("subprocess.run")
    def test_kubectl_exec_failure(self, mock_run):
        mock_run.return_value = mock.MagicMock(
            returncode=1, stdout="", stderr="connection refused"
        )
        client = MultiDaemonClient()
        target = DaemonTarget(
            name="test", runtime="kubernetes",
            pod_name="guardian-abc", namespace="default"
        )
        result = client.send_restart(target)
        assert result is False


class TestRestRequest:
    @mock.patch.object(MultiDaemonClient, "_tcp_reachable", return_value=True)
    @mock.patch("ai_guardian.daemon.multi_client.urlopen")
    def test_successful_get(self, mock_urlopen, _mock_tcp):
        response_data = {"request_count": 100}
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = b'{"request_count": 100}'
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        target = DaemonTarget(
            name="test", runtime="container",
            host="127.0.0.1", port=49200
        )
        result = MultiDaemonClient._rest_request(target, "GET", "/api/stats")
        assert result == response_data

    def test_no_port_returns_none(self):
        target = DaemonTarget(name="test", runtime="container", port=0)
        result = MultiDaemonClient._rest_request(target, "GET", "/api/stats")
        assert result is None

    @mock.patch.object(MultiDaemonClient, "_tcp_reachable", return_value=True)
    @mock.patch("ai_guardian.daemon.multi_client.urlopen")
    def test_auth_token_in_url_target(self, mock_urlopen, _mock_tcp):
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = b'{}'
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        target = DaemonTarget(
            name="test", runtime="manual",
            url="https://guardian.co:63152",
            auth_token="my-token"
        )
        MultiDaemonClient._rest_request(target, "GET", "/api/health")
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer my-token"


class TestManualRouting:
    def test_restart_manual_returns_false(self):
        client = MultiDaemonClient()
        target = DaemonTarget(name="test", runtime="manual")
        assert client.send_restart(target) is False


class TestTcpReachable:
    """Tests for TCP reachability check (issue #711)."""

    def test_reachable_host_returns_true(self):
        with mock.patch("socket.socket") as mock_socket_cls:
            mock_sock = mock.MagicMock()
            mock_socket_cls.return_value = mock_sock
            assert MultiDaemonClient._tcp_reachable("127.0.0.1", 63152) is True
            mock_sock.connect.assert_called_once_with(("127.0.0.1", 63152))
            mock_sock.close.assert_called_once()

    def test_unreachable_host_returns_false(self):
        with mock.patch("socket.socket") as mock_socket_cls:
            mock_sock = mock.MagicMock()
            mock_sock.connect.side_effect = OSError("Network unreachable")
            mock_socket_cls.return_value = mock_sock
            assert MultiDaemonClient._tcp_reachable("10.0.0.99", 63152) is False

    def test_timeout_returns_false(self):
        import socket
        with mock.patch("socket.socket") as mock_socket_cls:
            mock_sock = mock.MagicMock()
            mock_sock.connect.side_effect = socket.timeout("timed out")
            mock_socket_cls.return_value = mock_sock
            assert MultiDaemonClient._tcp_reachable("10.0.0.99", 63152) is False


class TestRestRequestReachabilityCheck:
    """Tests for REST request socket pre-check (issue #711)."""

    @mock.patch.object(MultiDaemonClient, "_tcp_reachable", return_value=False)
    @mock.patch("ai_guardian.daemon.multi_client.urlopen")
    def test_skips_request_on_unreachable_host(self, mock_urlopen, mock_reachable):
        target = DaemonTarget(
            name="remote", runtime="manual",
            host="10.0.0.99", port=63152,
        )
        result = MultiDaemonClient._rest_request(target, "GET", "/api/status")
        assert result is None
        mock_urlopen.assert_not_called()

    @mock.patch.object(MultiDaemonClient, "_tcp_reachable", return_value=True)
    @mock.patch("ai_guardian.daemon.multi_client.urlopen")
    def test_proceeds_on_reachable_host(self, mock_urlopen, mock_reachable):
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = b'{"status": "running"}'
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        target = DaemonTarget(
            name="remote", runtime="manual",
            host="10.0.0.99", port=63152,
        )
        result = MultiDaemonClient._rest_request(target, "GET", "/api/status")
        assert result == {"status": "running"}
        mock_urlopen.assert_called_once()


class TestOpenShellRouting:
    """Tests for open_shell() routing per runtime (issue #706)."""

    @mock.patch.object(MultiDaemonClient, "_local_shell")
    def test_local_routes_to_local_shell(self, mock_shell):
        client = MultiDaemonClient()
        target = DaemonTarget(name="local", runtime="local")
        client.open_shell(target)
        mock_shell.assert_called_once()

    @mock.patch.object(MultiDaemonClient, "_container_shell")
    def test_container_routes_to_container_shell(self, mock_shell):
        client = MultiDaemonClient()
        target = DaemonTarget(
            name="test", runtime="container",
            container_id="abc123def456abc123", container_engine="podman"
        )
        client.open_shell(target)
        mock_shell.assert_called_once_with(target)

    @mock.patch.object(MultiDaemonClient, "_kubectl_shell")
    def test_kubernetes_routes_to_kubectl_shell(self, mock_shell):
        client = MultiDaemonClient()
        target = DaemonTarget(
            name="test", runtime="kubernetes",
            pod_name="guardian-abc", namespace="ai-sdlc"
        )
        client.open_shell(target)
        mock_shell.assert_called_once_with(target)

    def test_manual_runtime_is_noop(self):
        client = MultiDaemonClient()
        target = DaemonTarget(name="test", runtime="manual")
        client.open_shell(target)

    @mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal")
    def test_local_shell_uses_shell_env(self, mock_launch):
        with mock.patch.dict("os.environ", {"SHELL": "/bin/zsh"}):
            MultiDaemonClient._local_shell()
        mock_launch.assert_called_once_with(["/bin/zsh"], keep_open=True)

    @mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal")
    def test_local_shell_defaults_to_sh(self, mock_launch):
        with mock.patch.dict("os.environ", {}, clear=True):
            MultiDaemonClient._local_shell()
        mock_launch.assert_called_once_with(["/bin/sh"], keep_open=True)

    @mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal")
    def test_container_shell_builds_exec_command(self, mock_launch):
        target = DaemonTarget(
            name="test", runtime="container",
            container_id="abc123def456abc123", container_engine="podman"
        )
        MultiDaemonClient._container_shell(target)
        mock_launch.assert_called_once()
        cmd = mock_launch.call_args[0][0]
        assert cmd == ["podman", "exec", "-it", "abc123def456abc123", "/bin/sh"]

    @mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal")
    def test_container_shell_uses_docker_engine(self, mock_launch):
        target = DaemonTarget(
            name="test", runtime="container",
            container_id="abc123def456abc123", container_engine="docker"
        )
        MultiDaemonClient._container_shell(target)
        cmd = mock_launch.call_args[0][0]
        assert cmd[0] == "docker"

    @mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal")
    def test_kubectl_shell_builds_exec_command(self, mock_launch):
        target = DaemonTarget(
            name="test", runtime="kubernetes",
            pod_name="guardian-abc", namespace="ai-sdlc"
        )
        MultiDaemonClient._kubectl_shell(target)
        mock_launch.assert_called_once()
        cmd = mock_launch.call_args[0][0]
        assert cmd == [
            "kubectl", "exec", "-it", "guardian-abc",
            "-n", "ai-sdlc", "--", "/bin/sh",
        ]

    @mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal")
    def test_kubectl_shell_defaults_namespace(self, mock_launch):
        target = DaemonTarget(
            name="test", runtime="kubernetes",
            pod_name="guardian-abc", namespace=None
        )
        MultiDaemonClient._kubectl_shell(target)
        cmd = mock_launch.call_args[0][0]
        assert "-n" in cmd
        assert cmd[cmd.index("-n") + 1] == "default"


class TestGetPlugins:
    """Tests for get_plugins() routing (issue #590)."""

    @mock.patch.object(MultiDaemonClient, "_local_plugins")
    def test_local_target_calls_local_plugins(self, mock_local):
        mock_local.return_value = {"plugins": [{"name": "Test", "items": []}]}
        client = MultiDaemonClient()
        target = DaemonTarget(name="local", runtime="local")
        result = client.get_plugins(target)
        assert result == {"plugins": [{"name": "Test", "items": []}]}
        mock_local.assert_called_once()

    @mock.patch.object(MultiDaemonClient, "_rest_request")
    def test_container_target_uses_rest(self, mock_rest):
        mock_rest.return_value = {"plugins": []}
        client = MultiDaemonClient()
        target = DaemonTarget(
            name="sandbox", runtime="container",
            container_engine="podman", container_id="abc123def456",
            host="127.0.0.1", port=63152,
        )
        result = client.get_plugins(target)
        mock_rest.assert_called_once_with(target, "GET", "/api/tray-plugins")
        assert result == {"plugins": []}

    @mock.patch.object(MultiDaemonClient, "_rest_request")
    def test_manual_target_uses_rest(self, mock_rest):
        mock_rest.return_value = {"plugins": [{"name": "P", "items": []}]}
        client = MultiDaemonClient()
        target = DaemonTarget(
            name="remote", runtime="manual",
            host="10.0.0.1", port=63152,
        )
        result = client.get_plugins(target)
        mock_rest.assert_called_once_with(target, "GET", "/api/tray-plugins")

    @mock.patch.object(MultiDaemonClient, "_rest_request", return_value=None)
    def test_returns_none_on_network_failure(self, mock_rest):
        client = MultiDaemonClient()
        target = DaemonTarget(name="remote", runtime="manual", host="10.0.0.1", port=63152)
        result = client.get_plugins(target)
        assert result is None
