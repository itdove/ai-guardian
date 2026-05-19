"""
Multi-daemon client that routes tray actions to the correct daemon transport.

Supports local (Unix socket), container (REST + podman/docker exec),
Kubernetes (REST + kubectl exec), and manual (REST) targets.
"""

import json
import logging
import os
import platform
import shlex
import shutil
import subprocess
import sys
from typing import List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from ai_guardian.daemon.discovery import DaemonTarget

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 5.0


def _launch_in_terminal(cmd_parts):
    """Launch a command in a new terminal window with auto-close on exit."""
    cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)
    try:
        system = platform.system()
        if system == "Darwin":
            script = (
                'tell application "Terminal"\n'
                '    set currentTab to do script ""\n'
                '    delay 2\n'
                f'    do script "{cmd_str}" in currentTab\n'
                '    activate\n'
                '    set zoomed of front window to true\n'
                '    repeat\n'
                '        delay 1\n'
                '        if not busy of currentTab then\n'
                '            close (every window whose tabs contains currentTab)\n'
                '            exit repeat\n'
                '        end if\n'
                '    end repeat\n'
                'end tell'
            )
            subprocess.Popen(["osascript", "-e", script])
        elif system == "Windows":
            subprocess.Popen(["cmd", "/c", "start", "/max"] + cmd_parts)
        else:
            for term, args in [
                ("gnome-terminal", ["--maximize", "--"]),
                ("kgx", ["-e"]),
                ("konsole", ["--fullscreen", "-e"]),
                ("xfce4-terminal", ["--maximize", "-e"]),
                ("xterm", ["-maximized", "-e"]),
            ]:
                if shutil.which(term):
                    subprocess.Popen([term] + args + cmd_parts)
                    break
    except OSError as e:
        logger.debug("Failed to launch terminal: %s", e)


class MultiDaemonClient:
    """Routes tray actions to the appropriate daemon transport."""

    def get_status(self, target: DaemonTarget) -> Optional[dict]:
        """Get daemon status/stats."""
        if target.runtime == "local":
            return self._local_status(target)
        return self._rest_request(target, "GET", "/api/stats")

    def send_pause(self, target: DaemonTarget, minutes: int) -> bool:
        """Pause daemon scanning."""
        if target.runtime == "local":
            return self._local_pause(target, minutes)
        result = self._rest_request(
            target, "POST", "/api/pause", {"minutes": minutes}
        )
        return result is not None

    def send_resume(self, target: DaemonTarget) -> bool:
        """Resume daemon scanning."""
        if target.runtime == "local":
            return self._local_resume(target)
        result = self._rest_request(target, "POST", "/api/resume")
        return result is not None

    def send_stop(self, target: DaemonTarget) -> bool:
        """Stop daemon."""
        if target.runtime == "local":
            from ai_guardian.daemon.client import send_shutdown
            return send_shutdown()
        return self._send_daemon_command(target, "stop")

    def send_restart(self, target: DaemonTarget) -> bool:
        """Restart daemon."""
        if target.runtime == "local":
            return self._local_restart()
        return self._send_daemon_command(target, "restart")

    def _send_daemon_command(self, target: DaemonTarget, command: str) -> bool:
        """Send a daemon subcommand via exec to a remote target."""
        cmd = ["ai-guardian", "daemon", command]
        if target.runtime == "container":
            return self._container_exec(target, cmd) is not None
        if target.runtime == "kubernetes":
            return self._kubectl_exec(target, cmd) is not None
        return False

    def open_console(self, target: DaemonTarget, panel: Optional[str] = None):
        """Open console for the target daemon."""
        cmd = ["ai-guardian", "console"]
        if panel:
            cmd.extend(["--panel", panel])

        if target.runtime == "local":
            self._local_console(cmd)
        elif target.runtime == "container":
            self._container_console(target, cmd)
        elif target.runtime == "kubernetes":
            self._kubectl_console(target, cmd)

    def export_support(self, target: DaemonTarget) -> Optional[str]:
        """Export support bundle."""
        cmd = ["ai-guardian", "support", "prepare"]
        if target.runtime == "local":
            return self._local_exec(cmd)
        if target.runtime == "container":
            return self._container_exec(target, cmd)
        if target.runtime == "kubernetes":
            return self._kubectl_exec(target, cmd)
        return None

    # --- Local transport ---

    @staticmethod
    def _local_status(target: DaemonTarget) -> Optional[dict]:
        from ai_guardian.daemon.client import send_status_request
        return send_status_request()

    @staticmethod
    def _local_socket_send(msg: dict) -> bool:
        import socket as socket_mod
        from ai_guardian.daemon import get_socket_path
        from ai_guardian.daemon.protocol import encode_message, decode_message

        try:
            sock = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
            sock.settimeout(REQUEST_TIMEOUT)
            sock.connect(str(get_socket_path()))
            sock.sendall(encode_message(msg))
            decode_message(sock, timeout=REQUEST_TIMEOUT)
            sock.close()
            return True
        except Exception:
            return False

    @staticmethod
    def _local_pause(target: DaemonTarget, minutes: int) -> bool:
        return MultiDaemonClient._local_socket_send(
            {"version": 1, "type": "pause", "data": {"minutes": minutes}}
        )

    @staticmethod
    def _local_resume(target: DaemonTarget) -> bool:
        return MultiDaemonClient._local_socket_send(
            {"version": 1, "type": "resume"}
        )

    @staticmethod
    def _local_restart() -> bool:
        from ai_guardian.daemon import get_executable_command
        cmd = get_executable_command() + ["daemon", "restart"]
        try:
            subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except OSError:
            return False

    @staticmethod
    def _local_console(cmd: List[str]):
        """Launch console locally in a new terminal window."""
        from ai_guardian.daemon import get_executable_command
        cmd_parts = get_executable_command() + cmd[1:]
        _launch_in_terminal(cmd_parts)

    @staticmethod
    def _local_exec(cmd: List[str]) -> Optional[str]:
        from ai_guardian.daemon import get_executable_command
        full_cmd = get_executable_command() + cmd[1:]
        try:
            result = subprocess.run(
                full_cmd, capture_output=True, text=True, timeout=30
            )
            return result.stdout
        except (subprocess.TimeoutExpired, OSError):
            return None

    # --- REST transport ---

    @staticmethod
    def _rest_request(
        target: DaemonTarget,
        method: str,
        path: str,
        body: Optional[dict] = None,
    ) -> Optional[dict]:
        """Send HTTP request to daemon REST API."""
        if target.url:
            base = target.url.rstrip("/")
        elif target.port:
            base = f"http://{target.host}:{target.port}"
        else:
            return None

        url = f"{base}{path}"
        data = json.dumps(body).encode("utf-8") if body else None

        req = Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if target.auth_token:
            req.add_header("Authorization", f"Bearer {target.auth_token}")

        try:
            with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (URLError, OSError, json.JSONDecodeError, ValueError) as e:
            logger.debug("REST request failed (%s %s): %s", method, url, e)
            return None

    # --- Container transport ---

    @staticmethod
    def _container_exec(
        target: DaemonTarget, cmd: List[str]
    ) -> Optional[str]:
        """Execute command inside container (non-interactive)."""
        import re
        if not target.container_id or not re.match(r'^[a-fA-F0-9]{12,64}$', target.container_id):
            logger.warning("Refusing exec: invalid container ID format")
            return None
        engine = target.container_engine or "podman"
        full_cmd = [engine, "exec", target.container_id] + cmd
        try:
            result = subprocess.run(
                full_cmd, capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                logger.debug("Container exec failed: %s", result.stderr)
                return None
            return result.stdout
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug("Container exec error: %s", e)
            return None

    @staticmethod
    def _container_console(target: DaemonTarget, cmd: List[str]):
        """Open interactive console inside container in a new terminal."""
        engine = target.container_engine or "podman"
        exec_cmd = [engine, "exec", "-it", target.container_id] + cmd
        _launch_in_terminal(exec_cmd)

    # --- Kubernetes transport ---

    @staticmethod
    def _kubectl_exec(
        target: DaemonTarget, cmd: List[str]
    ) -> Optional[str]:
        """Execute command inside K8s pod (non-interactive)."""
        full_cmd = [
            "kubectl", "exec", target.pod_name,
            "-n", target.namespace or "default",
            "--",
        ] + cmd
        try:
            result = subprocess.run(
                full_cmd, capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                logger.debug("kubectl exec failed: %s", result.stderr)
                return None
            return result.stdout
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug("kubectl exec error: %s", e)
            return None

    @staticmethod
    def _kubectl_console(target: DaemonTarget, cmd: List[str]):
        """Open interactive console inside K8s pod in a new terminal."""
        exec_cmd = [
            "kubectl", "exec", "-it", target.pod_name,
            "-n", target.namespace or "default",
            "--",
        ] + cmd
        _launch_in_terminal(exec_cmd)
