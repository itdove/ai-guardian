"""Tests for multi-daemon discovery engine."""

import json
import os
import tempfile
from unittest import mock


from ai_guardian.daemon.discovery import (
    DaemonDiscovery,
    DaemonTarget,
    _detect_engine,
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
        assert t.container_name is None
        assert t.pod_name is None
        assert t.namespace is None
        assert t.socket_path is None
        assert t.stats is None
        assert t.last_seen == 0.0

    def test_container_name_field(self):
        t = DaemonTarget(
            name="my-project",
            runtime="container",
            container_id="abc123def456",
            container_engine="podman",
            container_name="sandbox-1",
        )
        assert t.container_name == "sandbox-1"
        assert t.name == "my-project"

    def test_container_name_defaults_none_for_local(self):
        t = DaemonTarget(name="local", runtime="local")
        assert t.container_name is None

    def test_local_target(self):
        t = DaemonTarget(
            name="local",
            runtime="local",
            socket_path="/tmp/daemon.sock",
            status="running",
        )
        assert t.runtime == "local"
        assert t.socket_path == "/tmp/daemon.sock"

    def test_container_target(self):
        t = DaemonTarget(
            name="my-container",
            runtime="container",
            container_id="abc123",
            container_engine="podman",
            host="127.0.0.1",
            port=49152,
        )
        assert t.runtime == "container"
        assert t.container_id == "abc123"
        assert t.container_engine == "podman"
        assert t.port == 49152

    def test_kubernetes_target(self):
        t = DaemonTarget(
            name="my-pod",
            runtime="kubernetes",
            pod_name="guardian-abc",
            namespace="ai-sdlc",
            port=63152,
        )
        assert t.runtime == "kubernetes"
        assert t.pod_name == "guardian-abc"
        assert t.namespace == "ai-sdlc"

    def test_manual_target(self):
        t = DaemonTarget(
            name="remote",
            runtime="manual",
            url="https://guardian.company.com:63152",
            auth_token="secret",
        )
        assert t.runtime == "manual"
        assert t.url == "https://guardian.company.com:63152"
        assert t.auth_token == "secret"


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
            "ai_guardian.config.utils.get_config_dir", return_value=config_dir
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
            "ai_guardian.config.utils.get_config_dir", return_value=config_dir
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
            "ai_guardian.config.utils.get_config_dir", return_value=config_dir
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
            "ai_guardian.config.utils.get_config_dir", return_value=config_dir
        ):
            target = d.discover_local()
        assert target.name == "my-workstation"

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_pid_file_name_overrides_config_name(
        self, mock_running, mock_pid, tmp_path
    ):
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
                "ai_guardian.config.utils.get_config_dir", return_value=config_dir
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
            "ai_guardian.config.utils.get_config_dir", return_value=config_dir
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
                "ai_guardian.config.utils.get_config_dir", return_value=config_dir
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


class TestDetectEngine:
    def test_podman_detected_via_api(self):
        client = mock.MagicMock()
        client.version.return_value = {
            "Components": [{"Name": "Podman Engine", "Version": "5.4.0"}],
        }
        assert _detect_engine(client, "/var/run/docker.sock") == "podman"

    def test_docker_detected_via_api(self):
        client = mock.MagicMock()
        client.version.return_value = {
            "Components": [{"Name": "Engine", "Version": "27.0.0"}],
        }
        assert _detect_engine(client, "/var/run/docker.sock") == "docker"

    def test_fallback_to_socket_path_on_api_error(self):
        client = mock.MagicMock()
        client.version.side_effect = Exception("connection lost")
        assert _detect_engine(client, "/run/user/1000/podman/podman.sock") == "podman"
        assert _detect_engine(client, "/var/run/docker.sock") == "docker"

    def test_fallback_when_components_empty(self):
        client = mock.MagicMock()
        client.version.return_value = {"Version": "27.0.0"}
        assert _detect_engine(client, "/run/podman/podman.sock") == "podman"
        assert _detect_engine(client, "/var/run/docker.sock") == "docker"

    def test_podman_via_docker_host_env(self):
        client = mock.MagicMock()
        client.version.return_value = {
            "Components": [{"Name": "Podman Engine", "Version": "5.4.0"}],
        }
        assert _detect_engine(client, "unix:///var/run/docker.sock") == "podman"


class TestGetPodmanSocket:
    def test_prefers_xdg_runtime_dir(self):
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/5000"}):
            assert _get_podman_socket() == "/run/user/5000/podman/podman.sock"

    @mock.patch("os.getuid", create=True, return_value=1000)
    def test_falls_back_to_uid_path_when_no_xdg(self, mock_uid):
        env = {k: v for k, v in os.environ.items() if k != "XDG_RUNTIME_DIR"}
        with mock.patch.dict(os.environ, env, clear=True):
            assert _get_podman_socket() == "/run/user/1000/podman/podman.sock"

    def test_returns_none_on_windows(self):
        env = {k: v for k, v in os.environ.items() if k != "XDG_RUNTIME_DIR"}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch("os.getuid", create=True, side_effect=AttributeError):
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
        with (
            mock.patch.object(
                d, "_get_docker_clients", return_value=[(mock_client, "podman")]
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()

        assert len(targets) == 1
        assert targets[0].name == "my-guardian"
        assert targets[0].container_id == "abc123def456"
        assert targets[0].port == 49200
        assert targets[0].container_engine == "podman"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_label_discovery_multiple_containers(self):
        c1 = _make_mock_container(
            container_id="aaa111bbb222ccc333",
            name="daemon-1",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "50001"}]},
        )
        c2 = _make_mock_container(
            container_id="bbb222ccc333ddd444",
            name="daemon-2",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "50002"}]},
        )
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [c1, c2]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with (
            mock.patch.object(
                d, "_get_docker_clients", return_value=[(mock_client, "docker")]
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()

        assert len(targets) == 2

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_port_fallback_discovery(self):
        container = _make_mock_container(
            container_id="abc789def012abc789",
            name="some-container",
            labels={},
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49300"}]},
        )
        mock_client = mock.MagicMock()
        mock_client.containers.list.side_effect = [
            [],
            [container],
        ]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with (
            mock.patch.object(
                d, "_get_docker_clients", return_value=[(mock_client, "podman")]
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()

        assert len(targets) == 1
        assert targets[0].name == "some-container"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_deduplicates_by_container_id(self):
        container = _make_mock_container(
            container_id="abc123def456abc123",
            name="guardian",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49400"}]},
        )
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [container]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with (
            mock.patch.object(
                d, "_get_docker_clients", return_value=[(mock_client, "podman")]
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()

        assert len(targets) == 1

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_empty_container_list(self):
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = []
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d)
        with (
            mock.patch.object(
                d, "_get_docker_clients", return_value=[(mock_client, "podman")]
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()
        assert targets == []

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_custom_name_from_label(self):
        container = _make_mock_container(
            container_id="abc123def456abc123",
            name="default-name",
            labels={"ai-guardian.daemon": "true", "ai-guardian.name": "my-sandbox"},
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49500"}]},
        )
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [container]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with (
            mock.patch.object(
                d, "_get_docker_clients", return_value=[(mock_client, "podman")]
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()
        assert targets[0].name == "my-sandbox"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_custom_rest_port_from_label(self):
        container = _make_mock_container(
            container_id="abc123def456abc123",
            name="guardian",
            labels={"ai-guardian.daemon": "true", "ai-guardian.rest-port": "8080"},
            ports={"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49600"}]},
        )
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [container]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with (
            mock.patch.object(
                d, "_get_docker_clients", return_value=[(mock_client, "podman")]
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()
        assert targets[0].port == 49600

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_multi_engine_discovery(self):
        podman_container = _make_mock_container(
            container_id="aaa111bbb222ccc333",
            name="carbonite",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49700"}]},
        )
        docker_container = _make_mock_container(
            container_id="ddd444eee555fff666",
            name="dev-api",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49800"}]},
        )
        podman_client = mock.MagicMock()
        podman_client.containers.list.return_value = [podman_container]
        podman_client.close = mock.MagicMock()

        docker_client = mock.MagicMock()
        docker_client.containers.list.return_value = [docker_container]
        docker_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with (
            mock.patch.object(
                d,
                "_get_docker_clients",
                return_value=[(podman_client, "podman"), (docker_client, "docker")],
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()

        assert len(targets) == 2
        engines = {t.container_engine for t in targets}
        assert engines == {"podman", "docker"}
        names = {t.name for t in targets}
        assert names == {"carbonite", "dev-api"}

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_multi_engine_deduplication(self):
        container = _make_mock_container(
            container_id="abc123def456abc123",
            name="guardian",
            ports={"63152/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49900"}]},
        )
        podman_client = mock.MagicMock()
        podman_client.containers.list.return_value = [container]
        podman_client.close = mock.MagicMock()

        docker_client = mock.MagicMock()
        docker_client.containers.list.return_value = [container]
        docker_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with (
            mock.patch.object(
                d,
                "_get_docker_clients",
                return_value=[(podman_client, "podman"), (docker_client, "docker")],
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()

        assert len(targets) == 1
        assert targets[0].container_engine == "podman"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_client_close_called(self):
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = []
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        with mock.patch.object(
            d, "_get_docker_clients", return_value=[(mock_client, "docker")]
        ):
            d.discover_containers()

        mock_client.close.assert_called_once()

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_client_close_called_on_error(self):
        mock_client = mock.MagicMock()
        mock_client.containers.list.side_effect = Exception("connection lost")
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        with mock.patch.object(
            d, "_get_docker_clients", return_value=[(mock_client, "docker")]
        ):
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
        mock_client.version.return_value = {
            "Components": [{"Name": "Engine", "Version": "27.0.0"}],
        }

        d = DaemonDiscovery()
        with mock.patch("ai_guardian.daemon.discovery.docker_sdk") as mock_docker:
            mock_docker.DockerClient.return_value = mock_client
            clients = d._get_docker_clients()

        assert len(clients) == 1
        assert clients[0][1] == "docker"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    @mock.patch("os.path.exists")
    @mock.patch.dict(os.environ, {"DOCKER_HOST": "unix:///var/run/docker.sock"})
    def test_podman_behind_docker_socket(self, mock_exists):
        """Podman providing Docker-compatible socket is detected as podman."""
        mock_exists.return_value = False
        mock_client = mock.MagicMock()
        mock_client.ping.return_value = True
        mock_client.version.return_value = {
            "Components": [{"Name": "Podman Engine", "Version": "5.4.0"}],
        }

        d = DaemonDiscovery()
        with mock.patch("ai_guardian.daemon.discovery.docker_sdk") as mock_docker:
            mock_docker.DockerClient.return_value = mock_client
            clients = d._get_docker_clients()

        assert len(clients) == 1
        assert clients[0][1] == "podman"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    @mock.patch.dict(os.environ, {}, clear=True)
    def test_podman_socket_detected(self):
        mock_client = mock.MagicMock()
        mock_client.ping.return_value = True

        d = DaemonDiscovery()
        podman_sock = _get_podman_socket()

        def mock_exists(path):
            return path == podman_sock

        with (
            mock.patch("ai_guardian.daemon.discovery.docker_sdk") as mock_docker,
            mock.patch("os.path.exists", side_effect=mock_exists),
        ):
            mock_docker.DockerClient.return_value = mock_client
            clients = d._get_docker_clients()

        if podman_sock:
            assert len(clients) == 1
            assert clients[0][1] == "podman"


class TestDiscoverPausedState:
    """Tests for paused state detection from API response (issue #696)."""

    def _patch_probes(self, d, probe_return=None):
        return (
            mock.patch.object(d, "_probe_daemon", return_value=probe_return),
            mock.patch.object(d, "_sdk_exec_instance_name", return_value=None),
        )

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_sdk_container_paused_status(self):
        """Container with paused API response gets status='paused'."""
        container = _make_mock_container()
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [container]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"paused": True})
        with (
            mock.patch.object(
                d, "_get_docker_clients", return_value=[(mock_client, "podman")]
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()

        assert len(targets) == 1
        assert targets[0].status == "paused"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_sdk_container_running_status(self):
        """Container with paused=False API response gets status='running'."""
        container = _make_mock_container()
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [container]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"paused": False})
        with (
            mock.patch.object(
                d, "_get_docker_clients", return_value=[(mock_client, "podman")]
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()

        assert len(targets) == 1
        assert targets[0].status == "running"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_sdk_container_no_paused_field(self):
        """Container with no paused field in API response gets status='running'."""
        container = _make_mock_container()
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [container]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with (
            mock.patch.object(
                d, "_get_docker_clients", return_value=[(mock_client, "podman")]
            ),
            p1,
            p2,
        ):
            targets = d.discover_containers()

        assert len(targets) == 1
        assert targets[0].status == "running"

    @mock.patch("ai_guardian.daemon.discovery.HAS_DOCKER_SDK", True)
    def test_sdk_paused_container_still_resolves_exec_name(self):
        """Paused container should NOT fall through to exec name resolution."""
        container = _make_mock_container(labels={})
        mock_client = mock.MagicMock()
        mock_client.containers.list.return_value = [container]
        mock_client.close = mock.MagicMock()

        d = DaemonDiscovery()
        with (
            mock.patch.object(d, "_probe_daemon", return_value={"paused": True}),
            mock.patch.object(
                d, "_sdk_exec_instance_name", return_value="exec-name"
            ) as mock_exec,
        ):
            with mock.patch.object(
                d, "_get_docker_clients", return_value=[(mock_client, "podman")]
            ):
                targets = d.discover_containers()

        mock_exec.assert_not_called()
        assert targets[0].status == "paused"

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_local_daemon_paused_via_api(self, mock_running, mock_pid, tmp_path):
        """Local daemon with paused API response gets status='paused'."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text("{}", encoding="utf-8")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            json.dump({"pid": 12345, "rest_port": 54321}, f)
            f.flush()
            from pathlib import Path

            mock_pid.return_value = Path(f.name)

        try:
            d = DaemonDiscovery()
            with (
                mock.patch(
                    "ai_guardian.config.utils.get_config_dir", return_value=config_dir
                ),
                mock.patch.object(d, "_probe_daemon", return_value={"paused": True}),
            ):
                target = d.discover_local()
            assert target.status == "paused"
        finally:
            os.unlink(f.name)

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_local_daemon_running_via_api(self, mock_running, mock_pid, tmp_path):
        """Local daemon with paused=False API response gets status='running'."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text("{}", encoding="utf-8")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            json.dump({"pid": 12345, "rest_port": 54321}, f)
            f.flush()
            from pathlib import Path

            mock_pid.return_value = Path(f.name)

        try:
            d = DaemonDiscovery()
            with (
                mock.patch(
                    "ai_guardian.config.utils.get_config_dir", return_value=config_dir
                ),
                mock.patch.object(d, "_probe_daemon", return_value={"paused": False}),
            ):
                target = d.discover_local()
            assert target.status == "running"
        finally:
            os.unlink(f.name)

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_local_daemon_no_port_stays_running(self, mock_running, mock_pid, tmp_path):
        """Local daemon without REST port falls back to socket check."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text("{}", encoding="utf-8")
        mock_pid.return_value = mock.MagicMock(exists=lambda: False)

        d = DaemonDiscovery()
        with (
            mock.patch(
                "ai_guardian.config.utils.get_config_dir", return_value=config_dir
            ),
            mock.patch.object(d, "_check_pause_via_socket", return_value=False),
        ):
            target = d.discover_local()
        assert target.status == "running"

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_local_probe_fail_socket_fallback_paused(
        self, mock_running, mock_pid, tmp_path
    ):
        """Probe failure falls back to socket check — paused detected."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text("{}", encoding="utf-8")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            json.dump({"pid": 12345, "rest_port": 54321}, f)
            f.flush()
            from pathlib import Path

            mock_pid.return_value = Path(f.name)

        try:
            d = DaemonDiscovery()
            with (
                mock.patch(
                    "ai_guardian.config.utils.get_config_dir", return_value=config_dir
                ),
                mock.patch.object(d, "_probe_daemon", return_value=None),
                mock.patch.object(d, "_check_pause_via_socket", return_value=True),
            ):
                target = d.discover_local()
            assert target.status == "paused"
        finally:
            os.unlink(f.name)

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_local_no_port_socket_fallback_paused(
        self, mock_running, mock_pid, tmp_path
    ):
        """No REST port falls back to socket check — paused detected."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text("{}", encoding="utf-8")
        mock_pid.return_value = mock.MagicMock(exists=lambda: False)

        d = DaemonDiscovery()
        with (
            mock.patch(
                "ai_guardian.config.utils.get_config_dir", return_value=config_dir
            ),
            mock.patch.object(d, "_check_pause_via_socket", return_value=True),
        ):
            target = d.discover_local()
        assert target.status == "paused"

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    def test_in_process_shortcut_checks_pause(self, mock_pid, tmp_path):
        """In-process shortcut (local_pid == os.getpid()) checks pause state."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text("{}", encoding="utf-8")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            json.dump({"pid": os.getpid(), "rest_port": 54321}, f)
            f.flush()
            from pathlib import Path

            mock_pid.return_value = Path(f.name)

        try:
            d = DaemonDiscovery()
            with (
                mock.patch(
                    "ai_guardian.config.utils.get_config_dir", return_value=config_dir
                ),
                mock.patch.object(d, "_check_pause_via_socket", return_value=True),
            ):
                target = d.discover_local()
            assert target.status == "paused"
        finally:
            os.unlink(f.name)

    def test_check_pause_via_socket_returns_true(self):
        """_check_pause_via_socket returns True when daemon reports paused."""
        with mock.patch(
            "ai_guardian.daemon.client.send_status_request",
            return_value={"paused": True},
        ):
            assert DaemonDiscovery._check_pause_via_socket() is True

    def test_check_pause_via_socket_returns_false(self):
        """_check_pause_via_socket returns False when daemon is running."""
        with mock.patch(
            "ai_guardian.daemon.client.send_status_request",
            return_value={"paused": False},
        ):
            assert DaemonDiscovery._check_pause_via_socket() is False

    def test_check_pause_via_socket_returns_false_on_failure(self):
        """_check_pause_via_socket returns False when socket fails."""
        with mock.patch(
            "ai_guardian.daemon.client.send_status_request", return_value=None
        ):
            assert DaemonDiscovery._check_pause_via_socket() is False


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

    def test_fallback_to_config_show_summary(self):
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
            (0, json.dumps({"daemon": {"name": "from-config-show"}}).encode()),
        ]
        assert DaemonDiscovery._sdk_exec_instance_name(c) == "from-config-show"


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
                        "labels": {"app": "ai-guardian", "user": "testuser"},
                    },
                    "status": {"phase": "Running"},
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
                    "token": "secret123",
                }
            ]
        }
        d = DaemonDiscovery()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            from pathlib import Path

            with mock.patch(
                "ai_guardian.daemon.discovery.get_tray_targets_path",
                return_value=Path(f.name),
            ):
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

            with mock.patch(
                "ai_guardian.daemon.discovery.get_tray_targets_path",
                return_value=Path(f.name),
            ):
                targets = d.discover_manual()

        os.unlink(f.name)
        assert targets == []


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

    @mock.patch.object(DaemonDiscovery, "discover_all")
    def test_callback_called_with_empty_list_on_exception(self, mock_discover):
        mock_discover.side_effect = RuntimeError("discovery failed")

        received = []
        d = DaemonDiscovery()
        d.start_background_discovery(lambda t: received.append(t))

        import time

        time.sleep(0.3)
        d.stop()

        assert len(received) >= 1
        assert received[0] == []


class TestProbeDaemonSocketPreCheck:
    """Tests for socket-level connect check in _probe_daemon (issue #711)."""

    def test_returns_none_on_socket_timeout(self):
        with mock.patch("socket.socket") as mock_socket_cls:
            import socket

            mock_sock = mock.MagicMock()
            mock_sock.connect.side_effect = socket.timeout("timed out")
            mock_socket_cls.return_value = mock_sock
            assert DaemonDiscovery._probe_daemon(63152) is None
            mock_sock.connect.assert_called_once_with(("127.0.0.1", 63152))

    def test_returns_none_on_connection_refused(self):
        with mock.patch("socket.socket") as mock_socket_cls:
            mock_sock = mock.MagicMock()
            mock_sock.connect.side_effect = ConnectionRefusedError
            mock_socket_cls.return_value = mock_sock
            assert DaemonDiscovery._probe_daemon(63152) is None

    @mock.patch("urllib.request.urlopen")
    def test_succeeds_after_socket_connect(self, mock_urlopen):
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = b'{"status": "running"}'
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        with mock.patch("socket.socket") as mock_socket_cls:
            mock_sock = mock.MagicMock()
            mock_socket_cls.return_value = mock_sock
            result = DaemonDiscovery._probe_daemon(63152)
            assert result == {"status": "running"}
            mock_sock.connect.assert_called_once()
            mock_sock.close.assert_called_once()

    def test_accepts_host_parameter(self):
        with mock.patch("socket.socket") as mock_socket_cls:
            mock_sock = mock.MagicMock()
            mock_sock.connect.side_effect = ConnectionRefusedError
            mock_socket_cls.return_value = mock_sock
            DaemonDiscovery._probe_daemon(63152, host="10.0.0.5")
            mock_sock.connect.assert_called_once_with(("10.0.0.5", 63152))


class TestDiscoverAllParallel:
    """Tests for parallel discovery with ThreadPoolExecutor (issue #711)."""

    def test_all_methods_run(self):
        d = DaemonDiscovery()
        local_target = DaemonTarget(name="local", runtime="local")
        manual_targets = [DaemonTarget(name="m1", runtime="manual")]

        with (
            mock.patch.object(d, "discover_local", return_value=local_target) as ml,
            mock.patch.object(d, "discover_containers", return_value=[]) as mc,
            mock.patch.object(d, "discover_manual", return_value=manual_targets) as mm,
        ):
            results = d.discover_all()
            ml.assert_called_once()
            mc.assert_called_once()
            mm.assert_called_once()
            assert len(results) == 2

    def test_results_merged_correctly(self):
        d = DaemonDiscovery()
        local = DaemonTarget(name="local", runtime="local")
        containers = [
            DaemonTarget(name="c1", runtime="container"),
            DaemonTarget(name="c2", runtime="container"),
        ]
        manual = [DaemonTarget(name="m1", runtime="manual")]

        with (
            mock.patch.object(d, "discover_local", return_value=local),
            mock.patch.object(d, "discover_containers", return_value=containers),
            mock.patch.object(d, "discover_manual", return_value=manual),
        ):
            results = d.discover_all()
            names = [t.name for t in results]
            assert "local" in names
            assert "c1" in names
            assert "c2" in names
            assert "m1" in names

    def test_slow_method_does_not_block_others(self):
        import time

        d = DaemonDiscovery()
        local = DaemonTarget(name="local", runtime="local")

        def slow_containers():
            time.sleep(30)
            return []

        with (
            mock.patch.object(d, "discover_local", return_value=local),
            mock.patch.object(d, "discover_containers", side_effect=slow_containers),
            mock.patch.object(d, "discover_manual", return_value=[]),
        ):
            start = time.monotonic()
            results = d.discover_all()
            elapsed = time.monotonic() - start
            assert elapsed < 7
            assert any(t.name == "local" for t in results)

    def test_failing_method_does_not_affect_others(self):
        d = DaemonDiscovery()
        local = DaemonTarget(name="local", runtime="local")

        with (
            mock.patch.object(d, "discover_local", return_value=local),
            mock.patch.object(
                d, "discover_containers", side_effect=RuntimeError("boom")
            ),
            mock.patch.object(d, "discover_manual", return_value=[]),
        ):
            results = d.discover_all()
            assert any(t.name == "local" for t in results)

    def test_config_disables_containers(self):
        d = DaemonDiscovery(config={"daemon": {"tray": {"discover_containers": False}}})
        local = DaemonTarget(name="local", runtime="local")

        with (
            mock.patch.object(d, "discover_local", return_value=local),
            mock.patch.object(d, "discover_containers") as mc,
            mock.patch.object(d, "discover_manual", return_value=[]),
        ):
            d.discover_all()
            mc.assert_not_called()

    def test_local_none_not_appended(self):
        d = DaemonDiscovery()
        with (
            mock.patch.object(d, "discover_local", return_value=None),
            mock.patch.object(d, "discover_containers", return_value=[]),
            mock.patch.object(d, "discover_manual", return_value=[]),
        ):
            results = d.discover_all()
            assert len(results) == 0

    def test_targets_stored_under_lock(self):
        d = DaemonDiscovery()
        local = DaemonTarget(name="local", runtime="local")

        with (
            mock.patch.object(d, "discover_local", return_value=local),
            mock.patch.object(d, "discover_containers", return_value=[]),
            mock.patch.object(d, "discover_manual", return_value=[]),
        ):
            d.discover_all()
            assert len(d.targets) == 1
            assert d.targets[0].name == "local"
