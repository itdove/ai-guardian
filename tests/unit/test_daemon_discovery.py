"""Tests for multi-daemon discovery engine."""

import json
import os
import tempfile
from unittest import mock

import pytest

from ai_guardian.daemon.discovery import (
    DaemonDiscovery,
    DaemonTarget,
    HAS_DOCKER_SDK,
    _engine_from_source,
    _get_podman_socket,
)


class TestDaemonTarget:
    def test_dataclass_defaults(self):
        t = DaemonTarget(name="test", runtime="local")
        assert t.name == "test"
        assert t.runtime == "local"
        assert t.status == "unknown"
        assert t.host == "127.0.0.1"
        assert t.port == 0
        assert t.container_id is None
        assert t.container_engine is None
        assert t.pod_name is None
        assert t.namespace is None
        assert t.socket_path is None
        assert t.stats is None
        assert t.last_seen == 0.0

    def test_local_target(self):
        t = DaemonTarget(
            name="local", runtime="local",
            socket_path="/tmp/daemon.sock", status="running"
        )
        assert t.runtime == "local"
        assert t.socket_path == "/tmp/daemon.sock"

    def test_container_target(self):
        t = DaemonTarget(
            name="my-container", runtime="container",
            container_id="abc123", container_engine="podman",
            host="127.0.0.1", port=49152
        )
        assert t.runtime == "container"
        assert t.container_id == "abc123"
        assert t.container_engine == "podman"
        assert t.port == 49152

    def test_kubernetes_target(self):
        t = DaemonTarget(
            name="my-pod", runtime="kubernetes",
            pod_name="guardian-abc", namespace="ai-sdlc", port=63152
        )
        assert t.runtime == "kubernetes"
        assert t.pod_name == "guardian-abc"
        assert t.namespace == "ai-sdlc"

    def test_manual_target(self):
        t = DaemonTarget(
            name="remote", runtime="manual",
            url="https://guardian.company.com:63152",
            auth_token="secret"
        )
        assert t.runtime == "manual"
        assert t.url == "https://guardian.company.com:63152"
        assert t.auth_token == "secret"


class TestGetContainerEngines:
    def test_both_available(self):
        d = DaemonDiscovery()
        with mock.patch("shutil.which", side_effect=lambda x: f"/usr/bin/{x}" if x in ("podman", "docker") else None):
            assert d.get_container_engines() == ["podman", "docker"]

    def test_podman_only(self):
        d = DaemonDiscovery()
        with mock.patch("shutil.which", side_effect=lambda x: "/usr/bin/podman" if x == "podman" else None):
            assert d.get_container_engines() == ["podman"]

    def test_docker_only(self):
        d = DaemonDiscovery()
        with mock.patch("shutil.which", side_effect=lambda x: "/usr/bin/docker" if x == "docker" else None):
            assert d.get_container_engines() == ["docker"]

    def test_none_available(self):
        d = DaemonDiscovery()
        with mock.patch("shutil.which", return_value=None):
            assert d.get_container_engines() == []

    def test_result_is_cached(self):
        d = DaemonDiscovery()
        with mock.patch("shutil.which", return_value="/usr/bin/podman") as m:
            d.get_container_engines()
            d.get_container_engines()
            assert m.call_count == 2  # called for podman and docker, cached after


class TestDiscoverLocal:
    """Tests for local discovery with config file check.

    discover_local() now requires ai-guardian.json to exist.
    All tests use a temp directory to isolate config state.
    """

    def _make_config_dir(self, tmp_path, config_content=None):
        """Create a temp config dir, optionally with ai-guardian.json."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        if config_content is not None:
            (config_dir / "ai-guardian.json").write_text(
                json.dumps(config_content), encoding="utf-8"
            )
        return config_dir

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    def test_no_config_returns_none(self, mock_pid, tmp_path):
        """No ai-guardian.json → discover_local() returns None."""
        config_dir = self._make_config_dir(tmp_path)
        mock_pid.return_value = mock.MagicMock(exists=lambda: False)
        d = DaemonDiscovery()
        with mock.patch(
            "ai_guardian.config_utils.get_config_dir", return_value=config_dir
        ):
            target = d.discover_local()
        assert target is None

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_config_exists_daemon_running(self, mock_running, mock_pid, tmp_path):
        """Config exists + daemon running → status='running', config_exists=True."""
        config_dir = self._make_config_dir(tmp_path, {})
        mock_pid.return_value = mock.MagicMock(exists=lambda: False)
        d = DaemonDiscovery()
        with mock.patch(
            "ai_guardian.config_utils.get_config_dir", return_value=config_dir
        ):
            target = d.discover_local()
        assert target is not None
        assert target.status == "running"
        assert target.config_exists is True

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=False)
    def test_config_exists_daemon_not_running(self, mock_running, mock_pid, tmp_path):
        """Config exists + daemon not running → status='stopped'."""
        config_dir = self._make_config_dir(tmp_path, {})
        mock_pid.return_value = mock.MagicMock(exists=lambda: False)
        d = DaemonDiscovery()
        with mock.patch(
            "ai_guardian.config_utils.get_config_dir", return_value=config_dir
        ):
            target = d.discover_local()
        assert target is not None
        assert target.status == "stopped"
        assert target.config_exists is True

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=False)
    def test_config_name_loaded(self, mock_running, mock_pid, tmp_path):
        """Name loaded from daemon.name in config file."""
        config_dir = self._make_config_dir(
            tmp_path, {"daemon": {"name": "my-workstation"}}
        )
        mock_pid.return_value = mock.MagicMock(exists=lambda: False)
        d = DaemonDiscovery()
        with mock.patch(
            "ai_guardian.config_utils.get_config_dir", return_value=config_dir
        ):
            target = d.discover_local()
        assert target.name == "my-workstation"

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_pid_file_name_overrides_config_name(self, mock_running, mock_pid, tmp_path):
        """PID file name takes precedence over config name."""
        config_dir = self._make_config_dir(
            tmp_path, {"daemon": {"name": "config-name"}}
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            json.dump({"pid": 12345, "rest_port": 54321, "name": "pid-name"}, f)
            f.flush()
            from pathlib import Path
            mock_pid.return_value = Path(f.name)

        try:
            d = DaemonDiscovery()
            with mock.patch(
                "ai_guardian.config_utils.get_config_dir", return_value=config_dir
            ):
                target = d.discover_local()
            assert target.name == "pid-name"
            assert target.port == 54321
        finally:
            os.unlink(f.name)

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_finds_running_daemon(self, mock_running, mock_pid, tmp_path):
        config_dir = self._make_config_dir(tmp_path, {})
        mock_pid.return_value = mock.MagicMock(exists=lambda: False)
        d = DaemonDiscovery()
        with mock.patch(
            "ai_guardian.config_utils.get_config_dir", return_value=config_dir
        ):
            target = d.discover_local()
        assert target is not None
        assert target.name == "local"
        assert target.runtime == "local"
        assert target.status == "running"

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_reads_rest_port_from_pid_file(self, mock_running, mock_pid, tmp_path):
        config_dir = self._make_config_dir(tmp_path, {})
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            json.dump({"pid": 12345, "rest_port": 54321}, f)
            f.flush()
            from pathlib import Path
            mock_pid.return_value = Path(f.name)

        try:
            d = DaemonDiscovery()
            with mock.patch(
                "ai_guardian.config_utils.get_config_dir", return_value=config_dir
            ):
                target = d.discover_local()
            assert target.port == 54321
        finally:
            os.unlink(f.name)


def _make_mock_container(
    container_id="abc123def456",
    name="my-guardian",
    labels=None,
    ports=None,
):
    """Create a mock docker SDK Container object."""
    c = mock.MagicMock()
    c.id = container_id
    c.name = name
    c.labels = labels or {"ai-guardian.daemon": "true"}
    c.ports = ports or {"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49200"}]}
    return c


class TestEngineFromSource:
    def test_docker_socket(self):
        assert _engine_from_source("/var/run/docker.sock") == "docker"

    def test_podman_rootless_socket(self):
        assert _engine_from_source("/run/user/1000/podman/podman.sock") == "podman"

    def test_podman_rootful_socket(self):
        assert _engine_from_source("/run/podman/podman.sock") == "podman"

    def test_docker_host_tcp(self):
        assert _engine_from_source("tcp://localhost:2375") == "docker"

    def test_docker_host_podman(self):
        assert _engine_from_source("unix:///run/podman/podman.sock") == "podman"


class TestGetPodmanSocket:
    @mock.patch("os.getuid", return_value=1000)
    def test_returns_rootless_path(self, mock_uid):
        assert _get_podman_socket() == "/run/user/1000/podman/podman.sock"

    def test_returns_none_on_windows(self):
        with mock.patch("os.getuid", side_effect=AttributeError):
            assert _get_podman_socket() is None


class TestDiscoverContainers:
    """Tests for SDK-based container discovery.

    All tests mock _probe_daemon and _sdk_exec_instance_name to avoid
    actual HTTP/exec calls during container discovery.
    """

    def _patch_probes(self, d, probe_return=None):
        """Patch _probe_daemon and _sdk_exec_instance_name on a discovery instance."""
        return (
            mock.patch.object(d, "_probe_daemon", return_value=probe_return),
            mock.patch.object(d, "_sdk_exec_instance_name", return_value=None),
        )

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", False)
    def test_no_sdk_returns_empty(self):
        d = DaemonDiscovery()
        assert d.discover_containers() == []

    def test_no_reachable_sockets_returns_empty(self):
        d = DaemonDiscovery()
        with mock.patch.object(d, "_get_docker_clients", return_value=[]):
            assert d.discover_containers() == []

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_label_discovery_via_sdk(self):
        container = _make_mock_container()
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [container]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "_get_docker_clients", return_value=[(mock_client, "podman")]), p1, p2:
            targets = d.discover_containers()

        assert len(targets) == 1
        assert targets[0].name == "my-guardian"
        assert targets[0].container_id == "abc123def456"
        assert targets[0].port == 49200
        assert targets[0].container_engine == "podman"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_label_discovery_multiple_containers(self):
        c1 = _make_mock_container(
            container_id="aaa111bbb222ccc333", name="daemon-1",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "50001"}]}
        )
        c2 = _make_mock_container(
            container_id="bbb222ccc333ddd444", name="daemon-2",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "50002"}]}
        )
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [c1, c2]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "_get_docker_clients", return_value=[(mock_client, "docker")]), p1, p2:
            targets = d.discover_containers()

        assert len(targets) == 2

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_port_fallback_discovery(self):
        container = _make_mock_container(
            container_id="abc789def012abc789", name="some-container",
            labels={},
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49300"}]}
        )
        mock_client = mock.MagicMock()
        mock_client.containers.list.side_effect = [
            [],
            [container],
        ]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "_get_docker_clients", return_value=[(mock_client, "podman")]), p1, p2:
            targets = d.discover_containers()

        assert len(targets) == 1
        assert targets[0].name == "some-container"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_deduplicates_by_container_id(self):
        container = _make_mock_container(
            container_id="abc123def456abc123", name="guardian",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49400"}]}
        )
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [container]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "_get_docker_clients", return_value=[(mock_client, "podman")]), p1, p2:
            targets = d.discover_containers()

        assert len(targets) == 1

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_empty_container_list(self):
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = []
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d)
        with mock.patch.object(d, "_get_docker_clients", return_value=[(mock_client, "podman")]), p1, p2:
            targets = d.discover_containers()
        assert targets == []

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_custom_name_from_label(self):
        container = _make_mock_container(
            container_id="abc123def456abc123", name="default-name",
            labels={"ai-guardian.daemon": "true", "ai-guardian.name": "my-sandbox"},
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49500"}]}
        )
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [container]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "_get_docker_clients", return_value=[(mock_client, "podman")]), p1, p2:
            targets = d.discover_containers()
        assert targets[0].name == "my-sandbox"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_custom_rest_port_from_label(self):
        container = _make_mock_container(
            container_id="abc123def456abc123", name="guardian",
            labels={"ai-guardian.daemon": "true", "ai-guardian.rest-port": "8080"},
            ports={"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49600"}]}
        )
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [container]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "_get_docker_clients", return_value=[(mock_client, "podman")]), p1, p2:
            targets = d.discover_containers()
        assert targets[0].port == 49600

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_multi_engine_discovery(self):
        podman_container = _make_mock_container(
            container_id="aaa111bbb222ccc333", name="carbonite",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49700"}]}
        )
        docker_container = _make_mock_container(
            container_id="ddd444eee555fff666", name="dev-api",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49800"}]}
        )
        podman_client = mock.MagicMock()
        podman_client.containers.list.return_value = [podman_container]
        podman_client.close = mock.MagicMock()

        docker_client = mock.MagicMock()
        docker_client.containers.list.return_value = [docker_container]
        docker_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "_get_docker_clients", return_value=[
            (podman_client, "podman"), (docker_client, "docker")
        ]), p1, p2:
            targets = d.discover_containers()

        assert len(targets) == 2
        engines = {t.container_engine for t in targets}
        assert engines == {"podman", "docker"}
        names = {t.name for t in targets}
        assert names == {"carbonite", "dev-api"}

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_multi_engine_deduplication(self):
        container = _make_mock_container(
            container_id="abc123def456abc123", name="guardian",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49900"}]}
        )
        podman_client = mock.MagicMock()
        podman_client.containers.list.return_value = [container]
        podman_client.close = mock.MagicMock()

        docker_client = mock.MagicMock()
        docker_client.containers.list.return_value = [container]
        docker_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "_get_docker_clients", return_value=[
            (podman_client, "podman"), (docker_client, "docker")
        ]), p1, p2:
            targets = d.discover_containers()

        assert len(targets) == 1
        assert targets[0].container_engine == "podman"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_client_close_called(self):
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = []
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        with mock.patch.object(d, "_get_docker_clients", return_value=[(mock_client, "docker")]):
            d.discover_containers()

        mock_client.close.assert_called_once()

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_client_close_called_on_error(self):
        mock_client = mock.MagicMock()
        mock_client.containers.list.side_effect = Exception("connection lost")
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        with mock.patch.object(d, "_get_docker_clients", return_value=[(mock_client, "docker")]):
            targets = d.discover_containers()

        assert targets == []
        mock_client.close.assert_called_once()


class TestGetDockerClients:
    """Tests for _get_docker_clients socket discovery."""

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    @mock.patch("os.path.exists", return_value=False)
    @mock.patch.dict(os.environ, {}, clear=True)
    def test_no_sockets_returns_empty(self, mock_exists):
        d = DaemonDiscovery()
        with mock.patch("ai_guardian.daemon.discovery.docker_sdk") as mock_docker:
            clients = d._get_docker_clients()
        assert clients == []

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    @mock.patch("os.path.exists")
    @mock.patch.dict(os.environ, {"DOCKER_HOST": "unix:///var/run/docker.sock"})
    def test_docker_host_env_used_first(self, mock_exists):
        mock_exists.return_value = False
        mock_client = mock.MagicMock()
        mock_client.ping.return_value = True

        d = DaemonDiscovery()
        with mock.patch("ai_guardian.daemon.discovery.docker_sdk") as mock_docker:
            mock_docker.DockerClient.return_value = mock_client
            clients = d._get_docker_clients()

        assert len(clients) == 1
        assert clients[0][1] == "docker"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    @mock.patch.dict(os.environ, {}, clear=True)
    def test_podman_socket_detected(self):
        mock_client = mock.MagicMock()
        mock_client.ping.return_value = True

        d = DaemonDiscovery()
        podman_sock = _get_podman_socket()

        def mock_exists(path):
            return path == podman_sock

        with mock.patch("ai_guardian.daemon.discovery.docker_sdk") as mock_docker, \
             mock.patch("os.path.exists", side_effect=mock_exists):
            mock_docker.DockerClient.return_value = mock_client
            clients = d._get_docker_clients()

        if podman_sock:
            assert len(clients) == 1
            assert clients[0][1] == "podman"


class TestSdkFindHostPort:
    def test_finds_port_from_sdk_format(self):
        c = _make_mock_container(
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49200"}]}
        )
        assert DaemonDiscovery._sdk_find_host_port(c, 63152) == 49200

    def test_no_match_returns_zero(self):
        c = _make_mock_container(ports={"8080/tcp": [{"HostPort": "49200"}]})
        assert DaemonDiscovery._sdk_find_host_port(c, 63152) == 0

    def test_empty_ports_returns_zero(self):
        c = mock.MagicMock()
        c.ports = {}
        assert DaemonDiscovery._sdk_find_host_port(c, 63152) == 0

    def test_none_bindings_returns_zero(self):
        c = _make_mock_container(ports={"63152/tcp": None})
        assert DaemonDiscovery._sdk_find_host_port(c, 63152) == 0


class TestSdkExecInstanceName:
    def test_reads_name_from_config(self):
        c = mock.MagicMock()
        c.exec_run.return_value = (0, b"my-daemon\n")
        assert DaemonDiscovery._sdk_exec_instance_name(c) == "my-daemon"

    def test_fallback_to_show_config(self):
        c = mock.MagicMock()
        c.exec_run.side_effect = [
            (1, b""),
            (0, json.dumps({"daemon": {"name": "fallback-name"}}).encode()),
        ]
        assert DaemonDiscovery._sdk_exec_instance_name(c) == "fallback-name"

    def test_returns_none_on_failure(self):
        c = mock.MagicMock()
        c.exec_run.side_effect = Exception("container stopped")
        assert DaemonDiscovery._sdk_exec_instance_name(c) is None

    def test_empty_name_tries_fallback(self):
        c = mock.MagicMock()
        c.exec_run.side_effect = [
            (0, b"\n"),
            (0, json.dumps({"daemon": {"name": "from-show-config"}}).encode()),
        ]
        assert DaemonDiscovery._sdk_exec_instance_name(c) == "from-show-config"


class TestDiscoverKubernetes:
    def test_no_kubectl_returns_empty(self):
        d = DaemonDiscovery(config={"daemon": {"tray": {"discover_kubernetes": True}}})
        with mock.patch("shutil.which", return_value=None):
            assert d.discover_kubernetes() == []

    @mock.patch("subprocess.run")
    @mock.patch("shutil.which", return_value="/usr/bin/kubectl")
    def test_discovers_running_pods(self, mock_which, mock_run):
        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "guardian-abc12",
                        "labels": {"app": "ai-guardian", "user": "testuser"}
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }
        mock_run.return_value = mock.MagicMock(
            returncode=0, stdout=json.dumps(pods), stderr=""
        )
        d = DaemonDiscovery(config={"daemon": {"tray": {"discover_kubernetes": True}}})
        targets = d.discover_kubernetes()
        assert len(targets) == 1
        assert targets[0].name == "guardian-abc12"
        assert targets[0].runtime == "kubernetes"
        assert targets[0].status == "running"

    @mock.patch("subprocess.run")
    @mock.patch("shutil.which", return_value="/usr/bin/kubectl")
    def test_kubectl_failure_returns_empty(self, mock_which, mock_run):
        mock_run.return_value = mock.MagicMock(
            returncode=1, stdout="", stderr="connection refused"
        )
        d = DaemonDiscovery()
        assert d.discover_kubernetes() == []


class TestDiscoverManual:
    def test_missing_file_returns_empty(self):
        d = DaemonDiscovery()
        with mock.patch("ai_guardian.daemon.discovery.get_tray_targets_path") as m:
            m.return_value = mock.MagicMock(exists=lambda: False)
            assert d.discover_manual() == []

    def test_loads_targets(self):
        data = {
            "daemons": [
                {
                    "name": "central",
                    "url": "https://guardian.company.com:63152",
                    "token": "secret123"
                }
            ]
        }
        d = DaemonDiscovery()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            from pathlib import Path

            with mock.patch("ai_guardian.daemon.discovery.get_tray_targets_path", return_value=Path(f.name)):
                targets = d.discover_manual()

        os.unlink(f.name)
        assert len(targets) == 1
        assert targets[0].name == "central"
        assert targets[0].runtime == "manual"
        assert targets[0].host == "guardian.company.com"
        assert targets[0].port == 63152
        assert targets[0].auth_token == "secret123"

    def test_invalid_json_returns_empty(self):
        d = DaemonDiscovery()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json{{{")
            f.flush()
            from pathlib import Path

            with mock.patch("ai_guardian.daemon.discovery.get_tray_targets_path", return_value=Path(f.name)):
                targets = d.discover_manual()

        os.unlink(f.name)
        assert targets == []


class TestParseContainerJson:
    def test_empty_string(self):
        assert DaemonDiscovery._parse_container_json("") == []

    def test_json_array(self):
        data = [{"Id": "a"}, {"Id": "b"}]
        result = DaemonDiscovery._parse_container_json(json.dumps(data))
        assert len(result) == 2

    def test_single_object(self):
        data = {"Id": "a"}
        result = DaemonDiscovery._parse_container_json(json.dumps(data))
        assert len(result) == 1

    def test_line_delimited(self):
        lines = '{"Id": "a"}\n{"Id": "b"}\n'
        result = DaemonDiscovery._parse_container_json(lines)
        assert len(result) == 2


class TestHasPortMapping:
    def test_list_of_dicts_container_port(self):
        container = {"Ports": [{"container_port": 63152, "host_port": 49200}]}
        assert DaemonDiscovery._has_port_mapping(container, 63152)

    def test_list_of_dicts_containerPort(self):
        container = {"Ports": [{"containerPort": 63152, "hostPort": 49200}]}
        assert DaemonDiscovery._has_port_mapping(container, 63152)

    def test_no_match(self):
        container = {"Ports": [{"container_port": 8080, "host_port": 49200}]}
        assert not DaemonDiscovery._has_port_mapping(container, 63152)

    def test_string_ports(self):
        container = {"Ports": "0.0.0.0:49200->63152/tcp"}
        assert DaemonDiscovery._has_port_mapping(container, 63152)

    def test_empty_ports(self):
        container = {"Ports": []}
        assert not DaemonDiscovery._has_port_mapping(container, 63152)


class TestFindHostPort:
    def test_finds_host_port_from_dict(self):
        container = {"Ports": [{"container_port": 63152, "host_port": 49200}]}
        assert DaemonDiscovery._find_host_port(container, 63152) == 49200

    def test_finds_host_port_from_string(self):
        container = {"Ports": "0.0.0.0:49200->63152/tcp"}
        assert DaemonDiscovery._find_host_port(container, 63152) == 49200

    def test_no_match_returns_zero(self):
        container = {"Ports": []}
        assert DaemonDiscovery._find_host_port(container, 63152) == 0


class TestBackgroundDiscovery:
    @mock.patch.object(DaemonDiscovery, "discover_all")
    def test_callback_receives_targets(self, mock_discover):
        targets = [DaemonTarget(name="local", runtime="local", status="running")]
        mock_discover.return_value = targets

        received = []
        d = DaemonDiscovery()
        d.start_background_discovery(lambda t: received.append(t))

        import time
        time.sleep(0.3)
        d.stop()

        assert len(received) >= 1
        assert received[0][0].name == "local"

    def test_stop_terminates_thread(self):
        d = DaemonDiscovery()
        with mock.patch.object(d, "discover_all", return_value=[]):
            d.start_background_discovery(lambda t: None)
            assert d._thread is not None
            d.stop()
            assert not d._running
