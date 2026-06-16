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


def _launch_in_terminal(cmd_parts, keep_open=False, clear=False, cwd=None):
    """Launch a command in a new terminal window.

    Args:
        cmd_parts: Command and arguments to run.
        keep_open: If True, keep the terminal open after the command
            finishes so the user can read the output.
        clear: If True, clear the terminal before running the command.
        cwd: If set, cd to this directory before running the command.

    Returns:
        True if a terminal was launched, False otherwise.
    """
    cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)
    if cwd:
        cmd_str = f"cd {shlex.quote(cwd)}; {cmd_str}"
    if clear:
        cmd_str = "clear; " + cmd_str
    try:
        system = platform.system()
        if system == "Darwin":
            if keep_open:
                auto_close = ""
            else:
                auto_close = (
                    '    repeat\n'
                    '        delay 1\n'
                    '        if not busy of currentTab then\n'
                    '            close (every window whose tabs contains '
                    'currentTab)\n'
                    '            exit repeat\n'
                    '        end if\n'
                    '    end repeat\n'
                )
            cmd_escaped = cmd_str.replace("\\", "\\\\").replace('"', '\\"')
            script = (
                'tell application "Terminal"\n'
                '    set currentTab to do script ""\n'
                '    delay 2\n'
                f'    do script "{cmd_escaped}" in currentTab\n'
                '    activate\n'
                '    set zoomed of front window to true\n'
                f'{auto_close}'
                'end tell'
            )
            subprocess.Popen(["osascript", "-e", script])
            return True
        elif system == "Windows":
            flag = "/k" if keep_open else "/c"
            win_parts = (["cls", "&&"] if clear else []) + cmd_parts
            if cwd:
                win_parts = ["cd", "/d", cwd, "&&"] + win_parts
            subprocess.Popen(["cmd", flag, "start", "/max"] + win_parts)
            return True
        else:
            if keep_open:
                shell_cmd = cmd_str + '; echo; read -rp "Press Enter to close..."'
                cmd_parts = ["bash", "-c", shell_cmd]
            for term, args in [
                ("gnome-terminal", ["--maximize", "--"]),
                ("kgx", ["-e"]),
                ("konsole", ["--fullscreen", "-e"]),
                ("xfce4-terminal", ["--maximize", "-e"]),
                ("xterm", ["-maximized", "-e"]),
            ]:
                if shutil.which(term):
                    subprocess.Popen([term] + args + cmd_parts)
                    return True
            else:
                logger.warning(
                    "No supported terminal emulator found. "
                    "Tried: gnome-terminal, kgx, konsole, "
                    "xfce4-terminal, xterm. Install one of these to use "
                    "Console/Terminal/Doctor from the tray."
                )
                return False
    except OSError as e:
        logger.warning("Failed to launch terminal: %s", e)
        return False


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

    def send_pause_dir(
        self, target: DaemonTarget, directory: str, minutes: int,
    ) -> bool:
        """Pause scanning for a specific directory."""
        if target.runtime == "local":
            return MultiDaemonClient._local_socket_send(
                {"version": 1, "type": "pause_dir",
                 "data": {"dir": directory, "minutes": minutes}}
            )
        result = self._rest_request(
            target, "POST", "/api/pause_dir",
            {"dir": directory, "minutes": minutes},
        )
        return result is not None

    def send_resume_dir(self, target: DaemonTarget, directory: str) -> bool:
        """Resume scanning for a specific directory."""
        if target.runtime == "local":
            return MultiDaemonClient._local_socket_send(
                {"version": 1, "type": "resume_dir",
                 "data": {"dir": directory}}
            )
        result = self._rest_request(
            target, "POST", "/api/resume_dir", {"dir": directory},
        )
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

    # --- Upgrade transport ---

    def check_pip_available(self, target: DaemonTarget) -> bool:
        """Check whether pip is available on the target."""
        try:
            if target.runtime == "local":
                result = subprocess.run(
                    ["python", "-m", "pip", "--version"],
                    capture_output=True, text=True, timeout=10,
                )
                return result.returncode == 0
            cmd = ["pip", "--version"]
            if target.runtime == "container":
                return self._container_exec(target, cmd, timeout=10) is not None
            if target.runtime == "kubernetes":
                return self._kubectl_exec(target, cmd, timeout=10) is not None
        except (subprocess.TimeoutExpired, OSError):
            pass
        return False

    @staticmethod
    def check_pypi_version() -> Optional[str]:
        """Fetch the latest ai-guardian version from PyPI."""
        try:
            url = "https://pypi.org/pypi/ai-guardian/json"
            req = Request(url, headers={"Accept": "application/json"})
            with urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                return data.get("info", {}).get("version")
        except Exception:
            return None

    def run_pip_upgrade(
        self, target: DaemonTarget, version: Optional[str] = None, timeout: int = 120
    ) -> tuple:
        """Sync daemon to a specific version or upgrade to latest.

        Args:
            target: The daemon target to upgrade
            version: Specific version to install (e.g., "1.12.0"), or None for latest
            timeout: Command timeout in seconds

        Returns:
            (success, output): Tuple of success boolean and command output
        """
        try:
            # Build pip install command
            if version:
                pkg_spec = f"ai-guardian=={version}"
            else:
                pkg_spec = "ai-guardian"

            if target.runtime == "local":
                python_exe = shutil.which("python") or shutil.which("python3") or "python"
                cmd = [python_exe, "-m", "pip", "install"]
                if not version:
                    cmd.append("--upgrade")
                cmd.append(pkg_spec)
                result = subprocess.run(
                    cmd,
                    capture_output=True, text=True, timeout=timeout,
                )
                output = result.stdout + result.stderr
                return (result.returncode == 0, output)

            # Remote targets (container/kubernetes)
            cmd = ["pip", "install"]
            if not version:
                cmd.append("--upgrade")
            cmd.append(pkg_spec)
            if target.runtime == "container":
                out = self._container_exec(target, cmd, timeout=timeout)
                return (out is not None, out or "")
            if target.runtime == "kubernetes":
                out = self._kubectl_exec(target, cmd, timeout=timeout)
                return (out is not None, out or "")
        except subprocess.TimeoutExpired:
            return (False, "Version sync timed out")
        except OSError as e:
            return (False, str(e))
        return (False, "Unsupported runtime")

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

    def open_shell(self, target: DaemonTarget):
        """Open an interactive shell for the target daemon."""
        if target.runtime == "local":
            self._local_shell(cwd=getattr(target, "working_dir", None))
        elif target.runtime == "container":
            self._container_shell(target)
        elif target.runtime == "kubernetes":
            self._kubectl_shell(target)

    def open_doctor(self, target: DaemonTarget):
        """Open doctor for the target daemon in a new terminal."""
        cmd = ["ai-guardian", "doctor"]
        if target.runtime == "local":
            from ai_guardian.daemon import get_executable_command
            cmd_parts = get_executable_command() + cmd[1:]
            _launch_in_terminal(cmd_parts, keep_open=True)
        elif target.runtime == "container":
            engine = target.container_engine or "podman"
            exec_cmd = [engine, "exec", "-it", target.container_id] + cmd
            _launch_in_terminal(exec_cmd, keep_open=True)
        elif target.runtime == "kubernetes":
            exec_cmd = [
                "kubectl", "exec", "-it", target.pod_name,
                "-n", target.namespace or "default",
                "--",
            ] + cmd
            _launch_in_terminal(exec_cmd, keep_open=True)

    def get_plugins(self, target: DaemonTarget) -> Optional[dict]:
        """Get tray plugin definitions from a daemon."""
        if target.runtime == "local":
            return self._local_plugins(
                working_dir=getattr(target, "working_dir", None),
            )
        return self._rest_request(target, "GET", "/api/tray-plugins")

    @staticmethod
    def _local_plugins(working_dir: Optional[str] = None) -> dict:
        from ai_guardian.daemon.tray_plugins import load_merged_plugins, plugins_to_dict
        return plugins_to_dict(load_merged_plugins(working_dir))

    def get_about(self, target: DaemonTarget) -> Optional[dict]:
        """Get about info from a daemon."""
        if target.runtime == "local":
            return self._local_about()
        return self._rest_request(target, "GET", "/api/about")

    @staticmethod
    def _local_about() -> dict:
        from ai_guardian.daemon.about import get_about_info
        return get_about_info()

    def get_config(self, target: DaemonTarget) -> Optional[dict]:
        """Get feature configuration flags from a daemon."""
        if target.runtime == "local":
            return self._local_config()
        return self._rest_request(target, "GET", "/api/config")

    @staticmethod
    def _local_config() -> dict:
        from ai_guardian.config_loaders import _load_config_file
        from ai_guardian.config_utils import get_feature_flags, is_feature_enabled
        cfg, _ = _load_config_file()
        if not cfg:
            cfg = {}
        features = get_feature_flags(cfg)
        si_section = cfg.get("security_instructions")
        features["security_instructions"] = is_feature_enabled(
            si_section.get("inject_on_prompt")
            if isinstance(si_section, dict) else None,
            default=True,
        )
        mcp_cfg = cfg.get("mcp_server", {})
        features["mcp_server"] = bool(mcp_cfg) if mcp_cfg is not None else True
        action = cfg.get("action", "block")
        if isinstance(action, dict):
            action = action.get("mode", "block")
        features["action_mode"] = action
        if isinstance(mcp_cfg, dict):
            features["proactive_level"] = mcp_cfg.get("proactive_level", "low")
        else:
            features["proactive_level"] = "low"
        return {"features": features}

    def get_violations(
        self,
        target: DaemonTarget,
        limit: int = 50,
        violation_type: Optional[str] = None,
    ) -> Optional[dict]:
        """Get recent violations from a daemon."""
        if target.runtime == "local":
            return self._local_violations(limit, violation_type)
        params = f"?limit={limit}"
        if violation_type:
            params += f"&type={violation_type}"
        return self._rest_request(target, "GET", f"/api/violations{params}")

    @staticmethod
    def _local_violations(limit: int, violation_type: Optional[str]) -> dict:
        from ai_guardian.violation_logger import ViolationLogger
        vl = ViolationLogger()
        entries = vl.get_recent_violations(
            limit=limit, violation_type=violation_type
        )
        violations = []
        for entry in entries:
            ctx = entry.get("context", {})
            v = {
                "timestamp": entry.get("timestamp", ""),
                "type": entry.get("violation_type", ""),
                "severity": entry.get("severity", ""),
                "tool": ctx.get("tool", ""),
                "file": ctx.get("file", ""),
                "action": "blocked" if entry.get("blocked") else "logged",
                "suggestion": "",
            }
            sug = entry.get("suggestion")
            if isinstance(sug, dict):
                v["suggestion"] = sug.get("text", "")
            elif isinstance(sug, str):
                v["suggestion"] = sug
            line = ctx.get("line")
            if line is not None:
                v["line"] = line
            violations.append(v)
        return {"violations": violations, "count": len(violations)}

    def get_violation_context(
        self,
        target: DaemonTarget,
        file_path: str,
        line_number: int,
        violation_type: str,
        secret_type: str = "",
    ) -> Optional[dict]:
        """Rescan a file on the daemon to get matched text for allowlisting."""
        body = {
            "file_path": file_path,
            "line_number": line_number,
            "violation_type": violation_type,
            "secret_type": secret_type,
        }
        if target.runtime == "local":
            from ai_guardian.daemon.violation_rescan import rescan_violation
            return rescan_violation(**body)
        return self._rest_request(target, "POST", "/api/violation-context", body)

    def get_metrics(
        self,
        target: DaemonTarget,
        since_days: Optional[int] = None,
    ) -> Optional[dict]:
        """Get violation metrics from a daemon."""
        if target.runtime == "local":
            return self._local_metrics(since_days)
        params = f"?since_days={since_days}" if since_days else ""
        return self._rest_request(target, "GET", f"/api/metrics{params}")

    @staticmethod
    def _local_metrics(since_days: Optional[int]) -> dict:
        from ai_guardian.metrics import MetricsComputer
        mc = MetricsComputer(since_days=since_days)
        report = mc.compute()
        return {
            "total_violations": report.total_violations,
            "by_type": report.by_type,
            "by_severity": report.by_severity,
            "resolved": report.resolved_count,
            "unresolved": report.unresolved_count,
            "cumulative_total": report.cumulative_total,
            "cumulative_by_type": report.cumulative_by_type,
            "cumulative_since": report.cumulative_since,
        }

    def get_audit(
        self,
        target: DaemonTarget,
        since: str = "30d",
        until: Optional[str] = None,
        violation_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Optional[dict]:
        """Get audit report from a daemon."""
        if target.runtime == "local":
            return self._local_audit(since, until, violation_type, severity)
        params = f"?since={since}"
        if until:
            params += f"&until={until}"
        if violation_type:
            params += f"&type={violation_type}"
        if severity:
            params += f"&severity={severity}"
        return self._rest_request(target, "GET", f"/api/audit{params}")

    @staticmethod
    def _local_audit(
        since: str = "30d",
        until: Optional[str] = None,
        violation_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> dict:
        import json as _json
        from ai_guardian.audit import AuditComputer, format_audit_json
        computer = AuditComputer(
            since=since, until=until,
            violation_type=violation_type, severity=severity,
        )
        report = computer.compute()
        return _json.loads(format_audit_json(report))

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
    def _local_shell(cwd=None):
        """Open default shell in a new terminal window."""
        shell = os.environ.get("SHELL", "/bin/sh")
        _launch_in_terminal([shell], keep_open=True, cwd=cwd)

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
    def _tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
        """Fast TCP connect check. Returns True if host:port accepts connections."""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return True
        except (OSError, socket.timeout):
            return False

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

        from urllib.parse import urlparse
        parsed = urlparse(base)
        check_host = parsed.hostname or target.host
        check_port = parsed.port or target.port
        if check_host and check_port and not MultiDaemonClient._tcp_reachable(
            check_host, check_port
        ):
            logger.debug(
                "TCP unreachable (%s:%s), skipping REST request",
                check_host, check_port,
            )
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
        target: DaemonTarget, cmd: List[str], timeout: int = 30
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
                full_cmd, capture_output=True, text=True, timeout=timeout
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

    @staticmethod
    def _container_shell(target: DaemonTarget):
        """Open interactive shell inside container in a new terminal."""
        engine = target.container_engine or "podman"
        exec_cmd = [engine, "exec", "-it", target.container_id, "/bin/sh"]
        _launch_in_terminal(exec_cmd, keep_open=True)

    # --- Kubernetes transport ---

    @staticmethod
    def _kubectl_exec(
        target: DaemonTarget, cmd: List[str], timeout: int = 30
    ) -> Optional[str]:
        """Execute command inside K8s pod (non-interactive)."""
        full_cmd = [
            "kubectl", "exec", target.pod_name,
            "-n", target.namespace or "default",
            "--",
        ] + cmd
        try:
            result = subprocess.run(
                full_cmd, capture_output=True, text=True, timeout=timeout
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

    @staticmethod
    def _kubectl_shell(target: DaemonTarget):
        """Open interactive shell inside K8s pod in a new terminal."""
        exec_cmd = [
            "kubectl", "exec", "-it", target.pod_name,
            "-n", target.namespace or "default",
            "--", "/bin/sh",
        ]
        _launch_in_terminal(exec_cmd, keep_open=True)
