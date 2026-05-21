"""
Multi-daemon discovery engine.

Discovers AI Guardian daemons across local, container (Podman/Docker),
Kubernetes, and manually configured targets. Used by the tray client
to manage multiple daemons from a single system tray icon.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

try:
    import docker as docker_sdk
    from docker.errors import DockerException
    HAS_DOCKER_SDK = True
except ImportError:
    HAS_DOCKER_SDK = False

_CONTAINER_ID_RE = re.compile(r"^[a-fA-F0-9]{12,64}$")

DOCKER_SOCKET = "/var/run/docker.sock"
PODMAN_ROOTFUL_SOCKET = "/run/podman/podman.sock"


def _get_podman_socket():
    """Get the rootless Podman socket path."""
    try:
        uid = os.getuid()
    except AttributeError:
        return None
    return f"/run/user/{uid}/podman/podman.sock"


def _engine_from_source(source: str) -> str:
    """Derive 'podman' or 'docker' from a socket path or URL."""
    return "podman" if "podman" in source else "docker"


def _detect_engine(client, source: str) -> str:
    """Detect container engine via API, falling back to socket path heuristic."""
    try:
        version_info = client.version()
        for comp in version_info.get("Components", []):
            if "podman" in comp.get("Name", "").lower():
                return "podman"
    except Exception:
        pass
    return _engine_from_source(source)

from ai_guardian.daemon import (
    DEFAULT_REST_PORT,
    get_pid_path,
    get_socket_path,
    get_tray_targets_path,
)

logger = logging.getLogger(__name__)


@dataclass
class DaemonTarget:
    """Represents a discovered AI Guardian daemon instance."""

    name: str
    runtime: str  # "local", "container", "kubernetes", "manual"
    status: str = "unknown"  # "running", "paused", "error", "unknown"
    host: str = "127.0.0.1"
    port: int = 0
    container_id: Optional[str] = None
    container_engine: Optional[str] = None  # "podman" or "docker"
    pod_name: Optional[str] = None
    namespace: Optional[str] = None
    socket_path: Optional[str] = None
    url: Optional[str] = None
    auth_token: Optional[str] = dc_field(default=None, repr=False)
    config_exists: bool = False
    stats: Optional[dict] = None
    last_seen: float = 0.0
    error_message: Optional[str] = None


class DaemonDiscovery:
    """Discovers AI Guardian daemons across multiple runtimes."""

    def __init__(self, config=None):
        self._config = config or {}
        self._targets: List[DaemonTarget] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._container_engines: Optional[List[str]] = None
        self._callback: Optional[Callable] = None
        self._refresh_event: Optional[threading.Event] = None
        self._last_refresh: float = 0.0
        self._pending_done: List[threading.Event] = []
        self._done_lock: Optional[threading.Lock] = None

    @property
    def targets(self) -> List[DaemonTarget]:
        with self._lock:
            return list(self._targets)

    def discover_all(self) -> List[DaemonTarget]:
        """Run all discovery methods in parallel, return merged list."""
        from concurrent.futures import (
            ThreadPoolExecutor, as_completed,
            TimeoutError as FuturesTimeoutError,
        )

        daemon_cfg = self._config.get("daemon", {})
        tray_cfg = daemon_cfg.get("tray", {})

        tasks = {"local": self.discover_local}

        if tray_cfg.get("discover_containers", True):
            tasks["containers"] = self.discover_containers

        if tray_cfg.get("discover_kubernetes", False):
            tasks["kubernetes"] = self.discover_kubernetes

        tasks["manual"] = self.discover_manual

        results: List[DaemonTarget] = []
        overall_timeout = 5.0

        pool = ThreadPoolExecutor(max_workers=len(tasks))
        futures = {pool.submit(fn): name for name, fn in tasks.items()}
        try:
            for future in as_completed(futures, timeout=overall_timeout):
                name = futures[future]
                try:
                    result = future.result()
                    if name == "local":
                        if result:
                            results.append(result)
                    else:
                        results.extend(result)
                except Exception as e:
                    logger.debug("Discovery stage %s failed: %s", name, e)
        except FuturesTimeoutError:
            logger.debug(
                "Discovery timed out after %.1fs, returning partial results",
                overall_timeout,
            )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        with self._lock:
            self._targets = results

        return results

    def discover_local(self) -> Optional[DaemonTarget]:
        """Check for a local ai-guardian installation via config file.

        Returns None if no ai-guardian.json config exists locally.
        When config exists but the daemon is not running, returns a
        target with status="stopped" so the tray can show a warning.
        """
        from ai_guardian.config_utils import get_config_dir
        config_path = get_config_dir() / "ai-guardian.json"

        if not config_path.exists():
            return None

        name = "local"
        try:
            config_data = json.loads(config_path.read_text(encoding="utf-8"))
            cfg_name = config_data.get("daemon", {}).get("name")
            if cfg_name:
                name = cfg_name
        except (json.JSONDecodeError, OSError):
            pass

        target = DaemonTarget(
            name=name,
            runtime="local",
            socket_path=str(get_socket_path()),
            config_exists=True,
        )

        pid_path = get_pid_path()
        if pid_path.exists():
            try:
                pid_info = json.loads(pid_path.read_text())
                rest_port = pid_info.get("rest_port", 0)
                if rest_port:
                    target.port = rest_port

                pid_name = pid_info.get("name")
                if pid_name:
                    target.name = pid_name

                pid = pid_info.get("pid", 0)
                if pid == os.getpid():
                    target.status = "running"
                    target.last_seen = time.monotonic()
                    return target
            except (json.JSONDecodeError, OSError):
                pass

        from ai_guardian.daemon.client import is_daemon_running
        if is_daemon_running():
            if target.port:
                api_data = self._probe_daemon(target.port)
                if api_data and api_data.get("paused"):
                    target.status = "paused"
                else:
                    target.status = "running"
            else:
                target.status = "running"
            target.last_seen = time.monotonic()
        else:
            target.status = "stopped"

        return target

    def discover_containers(self) -> List[DaemonTarget]:
        """Discover container daemons via docker SDK.

        Uses the docker Python SDK (compatible with both Docker and Podman)
        to scan available container engine sockets:
        1. DOCKER_HOST env var (if set)
        2. Well-known sockets (Docker, Podman rootless, Podman rootful)

        Per socket, uses cascading discovery:
        1. Label filter (primary): containers with ai-guardian.daemon=true label
        2. Port filter (fallback): containers with port mapping to rest_port
        3. Merge and deduplicate by container ID across all engines
        """
        if not HAS_DOCKER_SDK:
            logger.debug(
                "docker SDK not installed; skipping container discovery "
                "(install with: pip install ai-guardian[tray])"
            )
            return []

        clients = self._get_docker_clients()
        if not clients:
            return []

        rest_port = self._config.get("daemon", {}).get(
            "rest_port", DEFAULT_REST_PORT
        )

        seen_ids: Dict[str, DaemonTarget] = {}

        for client, engine in clients:
            try:
                label_targets = self._sdk_discover_by_label(
                    client, engine, rest_port
                )
                for t in label_targets:
                    if t.container_id and t.container_id not in seen_ids:
                        seen_ids[t.container_id] = t

                port_targets = self._sdk_discover_by_port(
                    client, engine, rest_port
                )
                for t in port_targets:
                    if t.container_id and t.container_id not in seen_ids:
                        seen_ids[t.container_id] = t
            finally:
                try:
                    client.close()
                except Exception:
                    pass

        return list(seen_ids.values())

    def _get_docker_clients(self) -> List[Tuple]:
        """Return (DockerClient, engine_name) for each reachable socket."""
        clients: List[Tuple] = []
        seen_sockets: set = set()

        docker_host = os.environ.get("DOCKER_HOST")
        if docker_host:
            try:
                client = docker_sdk.DockerClient(
                    base_url=docker_host, timeout=10
                )
                client.ping()
                engine = _detect_engine(client, docker_host)
                clients.append((client, engine))
                seen_sockets.add(docker_host)
            except Exception:
                logger.debug("DOCKER_HOST=%s unreachable", docker_host)

        podman_socket = _get_podman_socket()
        sockets = [
            DOCKER_SOCKET,
        ]
        if podman_socket:
            sockets.append(podman_socket)
        sockets.append(PODMAN_ROOTFUL_SOCKET)

        for sock in sockets:
            if sock in seen_sockets or not os.path.exists(sock):
                continue
            try:
                url = f"unix://{sock}"
                client = docker_sdk.DockerClient(base_url=url, timeout=10)
                client.ping()
                engine = _detect_engine(client, sock)
                clients.append((client, engine))
                seen_sockets.add(sock)
            except Exception:
                logger.debug("Socket %s unreachable", sock)

        return clients

    def _sdk_discover_by_label(self, client, engine, rest_port):
        """Find containers with the ai-guardian.daemon=true label via SDK."""
        try:
            containers = client.containers.list(
                filters={"label": "ai-guardian.daemon=true"}
            )
            return self._sdk_containers_to_targets(
                engine, containers, rest_port
            )
        except Exception as e:
            logger.debug("SDK label discovery error: %s", e)
            return []

    def _sdk_discover_by_port(self, client, engine, rest_port):
        """Find containers with a port mapping to rest_port via SDK."""
        try:
            containers = client.containers.list()
            matching = []
            for c in containers:
                ports = c.ports or {}
                port_key = f"{rest_port}/tcp"
                if port_key in ports and ports[port_key]:
                    matching.append(c)
            return self._sdk_containers_to_targets(
                engine, matching, rest_port
            )
        except Exception as e:
            logger.debug("SDK port discovery error: %s", e)
            return []

    def _sdk_containers_to_targets(self, engine, containers, rest_port):
        """Convert SDK Container objects to DaemonTarget list."""
        targets = []
        for c in containers:
            container_id = c.id
            if not container_id or not _CONTAINER_ID_RE.match(container_id):
                continue

            labels = c.labels or {}

            raw_name = (
                labels.get("ai-guardian.name")
                or c.name
                or container_id[:12]
            )
            name = raw_name[:128]

            label_port = labels.get("ai-guardian.rest-port")
            try:
                target_rest_port = int(label_port) if label_port else rest_port
            except (ValueError, TypeError):
                target_rest_port = rest_port

            host_port = self._sdk_find_host_port(c, target_rest_port)

            status = "unknown"
            if host_port:
                api_data = self._probe_daemon(host_port)
                if api_data:
                    status = "paused" if api_data.get("paused") else "running"
                    if not labels.get("ai-guardian.name") and api_data.get("name"):
                        name = api_data["name"]

            if not labels.get("ai-guardian.name") and status not in (
                "running", "paused"
            ):
                exec_name = self._sdk_exec_instance_name(c)
                if exec_name:
                    name = exec_name

            target = DaemonTarget(
                name=name,
                runtime="container",
                status=status,
                host="127.0.0.1",
                port=host_port,
                container_id=container_id,
                container_engine=engine,
                last_seen=time.monotonic(),
            )
            targets.append(target)

        return targets

    @staticmethod
    def _sdk_find_host_port(container, container_port):
        """Find the host-side port for a container port via SDK."""
        ports = container.ports or {}
        port_key = f"{container_port}/tcp"
        bindings = ports.get(port_key)
        if bindings and isinstance(bindings, list) and bindings:
            hp = bindings[0].get("HostPort")
            if hp:
                return int(hp)
        return 0

    @staticmethod
    def _sdk_exec_instance_name(container, timeout=3):
        """Read daemon name from container config via SDK exec_run."""
        try:
            exit_code, output = container.exec_run(
                ["python3", "-c",
                 "import json; "
                 "f=open('/etc/ai-guardian/ai-guardian.json'); "
                 "c=json.load(f); "
                 "n=c.get('daemon',{}).get('name',''); "
                 "print(n)"],
                demux=False,
            )
            if exit_code == 0:
                name = output.decode("utf-8", errors="replace").strip()
                if name:
                    return name
        except Exception:
            pass

        try:
            exit_code, output = container.exec_run(
                ["ai-guardian", "show-config", "--json"],
                demux=False,
            )
            if exit_code == 0:
                data = json.loads(output.decode("utf-8", errors="replace"))
                return data.get("daemon", {}).get("name")
        except Exception:
            pass

        return None

    @staticmethod
    def _parse_container_json(output):
        """Parse container JSON output (handles both array and line-delimited)."""
        output = output.strip()
        if not output:
            return []

        try:
            parsed = json.loads(output)
            if isinstance(parsed, list):
                return parsed
            return [parsed]
        except json.JSONDecodeError:
            pass

        results = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    @staticmethod
    def _has_port_mapping(container, rest_port):
        """Check if a container has a port mapping to the given port."""
        ports = container.get("Ports", [])
        if isinstance(ports, list):
            for p in ports:
                if isinstance(p, dict):
                    if p.get("container_port") == rest_port:
                        return True
                    if p.get("containerPort") == rest_port:
                        return True
        elif isinstance(ports, str):
            if str(rest_port) in ports:
                return True
        return False

    def _containers_to_targets(self, engine, containers, rest_port):
        """Convert container dicts to DaemonTarget list."""
        targets = []
        for c in containers:
            container_id = (
                c.get("Id") or c.get("ID") or c.get("id") or ""
            )
            if not container_id or not _CONTAINER_ID_RE.match(container_id):
                continue

            labels = c.get("Labels", {})
            if isinstance(labels, str):
                labels = self._parse_label_string(labels)

            raw_name = (
                labels.get("ai-guardian.name")
                or self._get_container_name(c)
                or container_id[:12]
            )
            name = raw_name[:128]

            label_port = labels.get("ai-guardian.rest-port")
            try:
                target_rest_port = int(label_port) if label_port else rest_port
            except (ValueError, TypeError):
                target_rest_port = rest_port

            host_port = self._find_host_port(c, target_rest_port)

            status = "unknown"
            if host_port:
                api_data = self._probe_daemon(host_port)
                if api_data:
                    status = "paused" if api_data.get("paused") else "running"
                    if not labels.get("ai-guardian.name") and api_data.get("name"):
                        name = api_data["name"]

            if not labels.get("ai-guardian.name") and status not in (
                "running", "paused"
            ):
                exec_name = self._exec_instance_name(engine, container_id)
                if exec_name:
                    name = exec_name

            target = DaemonTarget(
                name=name,
                runtime="container",
                status=status,
                host="127.0.0.1",
                port=host_port,
                container_id=container_id,
                container_engine=engine,
                last_seen=time.monotonic(),
            )
            targets.append(target)

        return targets

    @staticmethod
    def _exec_instance_name(engine, container_id, timeout=3):
        """Read daemon name from container config via podman/docker exec."""
        try:
            result = subprocess.run(
                [engine, "exec", container_id,
                 "python3", "-c",
                 "import json; "
                 "f=open('/etc/ai-guardian/ai-guardian.json'); "
                 "c=json.load(f); "
                 "n=c.get('daemon',{}).get('name',''); "
                 "print(n)"
                 ],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode == 0:
                name = result.stdout.strip()
                if name:
                    return name
        except (subprocess.TimeoutExpired, OSError):
            pass

        try:
            result = subprocess.run(
                [engine, "exec", container_id,
                 "ai-guardian", "show-config", "--json"],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return data.get("daemon", {}).get("name")
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
            pass

        return None

    @staticmethod
    def _probe_daemon(port, host="127.0.0.1", timeout=1.0):
        """Probe a daemon's REST API. Returns status dict or None if unreachable."""
        import socket as _socket
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
        except (OSError, _socket.timeout):
            return None

        try:
            from urllib.request import urlopen
            import json as json_mod
            url = f"http://{host}:{port}/api/status"
            with urlopen(url, timeout=timeout) as resp:
                return json_mod.loads(resp.read().decode("utf-8"))
        except Exception:
            return None

    @staticmethod
    def _parse_label_string(labels_str):
        """Parse comma-separated label string into dict."""
        result = {}
        for pair in labels_str.split(","):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                result[k.strip()] = v.strip()
        return result

    @staticmethod
    def _get_container_name(container):
        """Extract display name from container info."""
        names = container.get("Names", container.get("Name", ""))
        if isinstance(names, list):
            return names[0].lstrip("/") if names else ""
        return str(names).lstrip("/")

    @staticmethod
    def _find_host_port(container, container_port):
        """Find the host-side port mapped to the given container port."""
        ports = container.get("Ports", [])

        if isinstance(ports, list):
            for p in ports:
                if isinstance(p, dict):
                    cp = p.get("container_port") or p.get("containerPort", 0)
                    hp = p.get("host_port") or p.get("hostPort", 0)
                    if int(cp) == container_port and hp:
                        return int(hp)

        elif isinstance(ports, str):
            pattern = rf"(?:[\d.]+:)?(\d+)->{container_port}/tcp"
            match = re.search(pattern, ports)
            if match:
                return int(match.group(1))

        return 0

    def discover_kubernetes(self) -> List[DaemonTarget]:
        """Discover Kubernetes pod daemons via kubectl."""
        if not shutil.which("kubectl"):
            return []

        daemon_cfg = self._config.get("daemon", {})
        tray_cfg = daemon_cfg.get("tray", {})
        k8s_cfg = tray_cfg.get("kubernetes", {})

        namespace = k8s_cfg.get("namespace", "ai-sdlc")
        if not re.fullmatch(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?', namespace):
            logger.debug("Invalid Kubernetes namespace: %s", namespace)
            return []

        label_selector = k8s_cfg.get(
            "label_selector", "app=ai-guardian"
        )

        user = os.environ.get("USER", os.environ.get("USERNAME", ""))
        user = re.sub(r'[^a-zA-Z0-9._-]', '', user)
        if user:
            label_selector = f"{label_selector},user={user}"

        rest_port = daemon_cfg.get("rest_port", DEFAULT_REST_PORT)

        try:
            result = subprocess.run(
                [
                    "kubectl", "get", "pods",
                    "-l", label_selector,
                    "-n", namespace,
                    "-o", "json",
                ],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                logger.debug("Kubernetes discovery failed: %s", result.stderr)
                return []

            data = json.loads(result.stdout)
            items = data.get("items", [])

            targets = []
            for pod in items:
                metadata = pod.get("metadata", {})
                status = pod.get("status", {})
                phase = status.get("phase", "Unknown")

                pod_name = metadata.get("name", "")
                if not pod_name:
                    continue

                labels = metadata.get("labels", {})
                name = labels.get("ai-guardian.name", pod_name)

                pod_status = "running" if phase == "Running" else "unknown"

                target = DaemonTarget(
                    name=name,
                    runtime="kubernetes",
                    status=pod_status,
                    port=rest_port,
                    pod_name=pod_name,
                    namespace=namespace,
                    last_seen=time.monotonic(),
                )
                targets.append(target)

            return targets
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
            logger.debug("Kubernetes discovery error: %s", e)
            return []

    def discover_manual(self) -> List[DaemonTarget]:
        """Load manually configured daemon targets from tray-targets.json."""
        targets_path = get_tray_targets_path()
        if not targets_path.exists():
            return []

        try:
            data = json.loads(targets_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.debug("Failed to load tray targets: %s", e)
            return []

        targets = []
        for entry in data.get("daemons", []):
            name = entry.get("name", "manual")
            url = entry.get("url", "")
            token = entry.get("token")

            host = "127.0.0.1"
            port = 0
            if url:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname or host
                port = parsed.port or 0

            target = DaemonTarget(
                name=name,
                runtime="manual",
                status="unknown",
                host=host,
                port=port,
                url=url,
                auth_token=token,
            )
            targets.append(target)

        return targets

    def get_container_engines(self) -> List[str]:
        """Return all available container engines (podman and/or docker)."""
        if self._container_engines is not None:
            return self._container_engines

        self._container_engines = [
            engine for engine in ("podman", "docker")
            if shutil.which(engine)
        ]
        return self._container_engines

    def start_background_discovery(self, callback: Callable):
        """Start background discovery thread (event-driven, not periodic).

        Discovery runs on demand via request_refresh(), not on a timer.
        An initial discovery runs immediately on start.

        Args:
            callback: Called with updated targets list after each discovery cycle
        """
        if self._running:
            return

        self._running = True
        self._callback = callback
        self._refresh_event = threading.Event()
        self._last_refresh = 0.0
        self._pending_done: List[threading.Event] = []
        self._done_lock = threading.Lock()

        def _loop():
            try:
                targets = self.discover_all()
                callback(targets)
                self._last_refresh = time.monotonic()
            except Exception as e:
                logger.debug("Initial discovery error: %s", e)

            while self._running:
                self._refresh_event.wait()
                if not self._running:
                    break
                self._refresh_event.clear()

                try:
                    targets = self.discover_all()
                    callback(targets)
                    self._last_refresh = time.monotonic()
                except Exception as e:
                    logger.debug("Background discovery error: %s", e)
                finally:
                    with self._done_lock:
                        for evt in self._pending_done:
                            evt.set()
                        self._pending_done.clear()

        self._thread = threading.Thread(
            target=_loop, daemon=True, name="daemon-discovery"
        )
        self._thread.start()

    def request_refresh(self, wait=False, timeout=2.0):
        """Request an immediate discovery refresh.

        Args:
            wait: If True, block until discovery completes (up to timeout)
            timeout: Max seconds to wait when wait=True
        """
        if not self._running or not hasattr(self, '_refresh_event'):
            return

        done = None
        if wait:
            done = threading.Event()
            with self._done_lock:
                self._pending_done.append(done)

        self._refresh_event.set()

        if done:
            done.wait(timeout=timeout)

    def stop(self):
        """Stop background discovery."""
        self._running = False
        if hasattr(self, '_refresh_event'):
            self._refresh_event.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
