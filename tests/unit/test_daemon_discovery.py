"""Tests for multi-daemon discovery engine."""

import json
import os
import tempfile
from unittest import mock

import pytest

from ai_guardian.daemon.discovery import DaemonDiscovery, DaemonTarget


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


class TestGetContainerEngine:
    def test_auto_prefers_podman(self):
        d = DaemonDiscovery()
        with mock.patch("shutil.which", side_effect=lambda x: f"/usr/bin/{x}" if x in ("podman", "docker") else None):
            assert d.get_container_engine() == "podman"

    def test_auto_falls_back_to_docker(self):
        d = DaemonDiscovery()
        with mock.patch("shutil.which", side_effect=lambda x: "/usr/bin/docker" if x == "docker" else None):
            assert d.get_container_engine() == "docker"

    def test_no_engine_available(self):
        d = DaemonDiscovery()
        with mock.patch("shutil.which", return_value=None):
            assert d.get_container_engine() is None

    def test_config_override_podman(self):
        d = DaemonDiscovery(config={"daemon": {"container_engine": "podman"}})
        with mock.patch("shutil.which", return_value="/usr/bin/podman"):
            assert d.get_container_engine() == "podman"

    def test_config_override_docker(self):
        d = DaemonDiscovery(config={"daemon": {"container_engine": "docker"}})
        with mock.patch("shutil.which", side_effect=lambda x: "/usr/bin/docker" if x == "docker" else None):
            assert d.get_container_engine() == "docker"

    def test_config_override_missing_engine(self):
        d = DaemonDiscovery(config={"daemon": {"container_engine": "podman"}})
        with mock.patch("shutil.which", return_value=None):
            assert d.get_container_engine() is None


class TestDiscoverLocal:
    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_finds_running_daemon(self, mock_running, mock_pid):
        mock_pid.return_value = mock.MagicMock(exists=lambda: False)
        d = DaemonDiscovery()
        target = d.discover_local()
        assert target is not None
        assert target.name == "local"
        assert target.runtime == "local"
        assert target.status == "running"

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=False)
    def test_no_daemon_running(self, mock_running, mock_pid):
        mock_pid.return_value = mock.MagicMock(exists=lambda: False)
        d = DaemonDiscovery()
        target = d.discover_local()
        assert target is not None
        assert target.status == "unknown"

    @mock.patch("ai_guardian.daemon.discovery.get_pid_path")
    @mock.patch("ai_guardian.daemon.client.is_daemon_running", return_value=True)
    def test_reads_rest_port_from_pid_file(self, mock_running, mock_pid):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            json.dump({"pid": 12345, "rest_port": 54321}, f)
            f.flush()
            from pathlib import Path
            mock_pid.return_value = Path(f.name)

        try:
            d = DaemonDiscovery()
            target = d.discover_local()
            assert target.port == 54321
        finally:
            os.unlink(f.name)


class TestDiscoverContainers:
    """Tests for container discovery.

    All tests mock _probe_daemon and _exec_daemon_name to avoid
    actual HTTP/exec calls during container discovery.
    """

    def _patch_probes(self, d, probe_return=None):
        """Patch _probe_daemon and _exec_daemon_name on a discovery instance."""
        return (
            mock.patch.object(d, "_probe_daemon", return_value=probe_return),
            mock.patch.object(d, "_exec_daemon_name", return_value=None),
        )

    def test_no_engine_returns_empty(self):
        d = DaemonDiscovery()
        with mock.patch.object(d, "get_container_engine", return_value=None):
            assert d.discover_containers() == []

    @mock.patch("subprocess.run")
    def test_label_discovery_podman_array(self, mock_run):
        containers = [
            {
                "Id": "abc123def456",
                "Names": ["my-guardian"],
                "Labels": {"ai-guardian.daemon": "true"},
                "Ports": [{"container_port": 63152, "host_port": 49200}],
            }
        ]
        mock_run.return_value = mock.MagicMock(
            returncode=0, stdout=json.dumps(containers), stderr=""
        )

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "get_container_engine", return_value="podman"), p1, p2:
            targets = d.discover_containers()

        assert len(targets) == 1
        assert targets[0].name == "my-guardian"
        assert targets[0].container_id == "abc123def456"
        assert targets[0].port == 49200
        assert targets[0].container_engine == "podman"

    @mock.patch("subprocess.run")
    def test_label_discovery_docker_line_delimited(self, mock_run):
        line1 = json.dumps({
            "Id": "aaa111bbb222ccc333", "Names": ["daemon-1"],
            "Labels": {"ai-guardian.daemon": "true"},
            "Ports": [{"containerPort": 63152, "hostPort": 50001}],
        })
        line2 = json.dumps({
            "Id": "bbb222ccc333ddd444", "Names": ["daemon-2"],
            "Labels": {"ai-guardian.daemon": "true"},
            "Ports": [{"containerPort": 63152, "hostPort": 50002}],
        })

        mock_run.return_value = mock.MagicMock(
            returncode=0, stdout=f"{line1}\n{line2}\n", stderr=""
        )

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "get_container_engine", return_value="docker"), p1, p2:
            targets = d.discover_containers()

        assert len(targets) == 2

    @mock.patch("subprocess.run")
    def test_port_fallback_discovery(self, mock_run):
        label_result = mock.MagicMock(returncode=0, stdout="[]", stderr="")
        port_result = mock.MagicMock(
            returncode=0,
            stdout=json.dumps([{
                "Id": "abc789def012abc789", "Names": ["some-container"],
                "Labels": {},
                "Ports": [{"container_port": 63152, "host_port": 49300}],
            }]),
            stderr=""
        )
        mock_run.side_effect = [label_result, port_result]

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "get_container_engine", return_value="podman"), p1, p2:
            targets = d.discover_containers()

        assert len(targets) == 1
        assert targets[0].name == "some-container"

    @mock.patch("subprocess.run")
    def test_deduplicates_by_container_id(self, mock_run):
        container = {
            "Id": "abc123def456abc123", "Names": ["guardian"],
            "Labels": {"ai-guardian.daemon": "true"},
            "Ports": [{"container_port": 63152, "host_port": 49400}],
        }
        label_result = mock.MagicMock(
            returncode=0, stdout=json.dumps([container]), stderr=""
        )
        port_result = mock.MagicMock(
            returncode=0, stdout=json.dumps([container]), stderr=""
        )
        mock_run.side_effect = [label_result, port_result]

        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "get_container_engine", return_value="podman"), p1, p2:
            targets = d.discover_containers()

        assert len(targets) == 1

    @mock.patch("subprocess.run")
    def test_empty_container_list(self, mock_run):
        mock_run.return_value = mock.MagicMock(
            returncode=0, stdout="[]", stderr=""
        )
        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d)
        with mock.patch.object(d, "get_container_engine", return_value="podman"), p1, p2:
            targets = d.discover_containers()
        assert targets == []

    @mock.patch("subprocess.run")
    def test_custom_name_from_label(self, mock_run):
        containers = [{
            "Id": "abc123def456abc123", "Names": ["default-name"],
            "Labels": {"ai-guardian.daemon": "true", "ai-guardian.name": "my-sandbox"},
            "Ports": [{"container_port": 63152, "host_port": 49500}],
        }]
        mock_run.return_value = mock.MagicMock(
            returncode=0, stdout=json.dumps(containers), stderr=""
        )
        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "get_container_engine", return_value="podman"), p1, p2:
            targets = d.discover_containers()
        assert targets[0].name == "my-sandbox"

    @mock.patch("subprocess.run")
    def test_custom_rest_port_from_label(self, mock_run):
        containers = [{
            "Id": "abc123def456abc123", "Names": ["guardian"],
            "Labels": {
                "ai-guardian.daemon": "true",
                "ai-guardian.rest-port": "8080"
            },
            "Ports": [{"container_port": 8080, "host_port": 49600}],
        }]
        mock_run.return_value = mock.MagicMock(
            returncode=0, stdout=json.dumps(containers), stderr=""
        )
        d = DaemonDiscovery()
        p1, p2 = self._patch_probes(d, probe_return={"running": True})
        with mock.patch.object(d, "get_container_engine", return_value="podman"), p1, p2:
            targets = d.discover_containers()
        assert targets[0].port == 49600


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
        d = DaemonDiscovery(discovery_interval=0.1)
        d.start_background_discovery(lambda t: received.append(t))

        import time
        time.sleep(0.3)
        d.stop()

        assert len(received) >= 1
        assert received[0][0].name == "local"

    def test_stop_terminates_thread(self):
        d = DaemonDiscovery(discovery_interval=0.1)
        with mock.patch.object(d, "discover_all", return_value=[]):
            d.start_background_discovery(lambda t: None)
            assert d._thread is not None
            d.stop()
            assert not d._running
