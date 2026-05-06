"""
Daemon panel for the AI Guardian Console.

Shows daemon status, configuration, and provides controls for
starting/stopping the daemon and changing the mode.
"""

import json
import logging

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Static, Select, Button, Label, Input
from textual.reactive import reactive

from ai_guardian.config_utils import get_config_dir, get_state_dir
from ai_guardian.tui.schema_defaults import SchemaDefaults

logger = logging.getLogger(__name__)

DAEMON_MODES = [
    ("auto — daemon with fallback to direct", "auto"),
    ("local — always per-process (CI/CD)", "local"),
    ("daemon — require daemon, log errors (testing)", "daemon"),
]


class DaemonPanelContent(Static):
    """Daemon configuration and status panel."""

    daemon_status = reactive("checking...")

    def compose(self) -> ComposeResult:
        sd = SchemaDefaults.get()
        config = self._load_daemon_config()
        current_mode = config.get("mode", "auto")
        idle_timeout = config.get("idle_timeout_minutes", 30)
        client_timeout = config.get("client_timeout_seconds", 2.0)
        tray_enabled = config.get("tray", {}).get("enabled", True)

        yield Static("[bold]Daemon Configuration[/bold]\n", classes="section-header")

        with Vertical(classes="form-group"):
            yield Static("Mode")
            yield Select(
                DAEMON_MODES,
                value=current_mode,
                id="daemon-mode",
                allow_blank=False,
            )
            yield Static(
                "[dim]Override with AI_GUARDIAN_DAEMON_MODE env var[/dim]",
                classes="help-text",
            )

        with Vertical(classes="form-group"):
            yield Static("Idle Timeout (minutes)")
            yield Input(
                str(idle_timeout),
                id="daemon-idle-timeout",
                type="integer",
            )
            default_idle = sd.get_default("daemon.idle_timeout_minutes")
            yield Static(
                f"[dim]0 = never auto-stop (default: {default_idle})[/dim]",
                classes="help-text",
            )

        with Vertical(classes="form-group"):
            yield Static("Client Timeout (seconds)")
            yield Input(
                str(client_timeout),
                id="daemon-client-timeout",
                type="number",
            )
            default_client = sd.get_default("daemon.client_timeout_seconds")
            yield Static(
                f"[dim]Max wait for daemon response before fallback (default: {default_client})[/dim]",
                classes="help-text",
            )

        with Vertical(classes="form-group"):
            yield Static("System Tray")
            yield Select(
                [("Enabled", True), ("Disabled", False)],
                value=tray_enabled,
                id="daemon-tray-enabled",
                allow_blank=False,
            )

        # --- Proxy Configuration ---
        yield Static("")
        yield Static("[bold]Proxy Configuration[/bold]\n", classes="section-header")

        proxy_config = config.get("proxy", {})
        proxy_enabled = proxy_config.get("enabled", False)
        proxy_port = proxy_config.get("listen_port", 63152)
        proxy_backend = proxy_config.get("backend_url", "https://api.anthropic.com")
        proxy_tls_verify = proxy_config.get("tls", {}).get("verify_backend", True)
        proxy_auth = proxy_config.get("auth", {}).get("mode", "pass-through")

        with Vertical(classes="form-group"):
            yield Static("Proxy Enabled")
            yield Select(
                [("Enabled", True), ("Disabled", False)],
                value=proxy_enabled,
                id="daemon-proxy-enabled",
                allow_blank=False,
            )
            yield Static(
                "[dim]HTTP reverse proxy for scanning IDE-to-API traffic[/dim]",
                classes="help-text",
            )

        with Vertical(classes="form-group"):
            yield Static("Listen Port")
            yield Input(
                str(proxy_port),
                id="daemon-proxy-port",
                type="integer",
            )
            yield Static(
                "[dim]Default: 63152 (dynamic range). Set ANTHROPIC_BASE_URL=http://localhost:<port>/v1[/dim]",
                classes="help-text",
            )

        with Vertical(classes="form-group"):
            yield Static("Backend URL")
            yield Input(
                proxy_backend,
                id="daemon-proxy-backend-url",
            )

        with Vertical(classes="form-group"):
            yield Static("TLS Verify Backend")
            yield Select(
                [("Enabled", True), ("Disabled", False)],
                value=proxy_tls_verify,
                id="daemon-proxy-tls-verify",
                allow_blank=False,
            )
            yield Static(
                "[dim]Disable for self-signed corporate certificates[/dim]",
                classes="help-text",
            )

        with Vertical(classes="form-group"):
            yield Static("Auth Mode")
            yield Select(
                [
                    ("pass-through — forward IDE auth headers", "pass-through"),
                    ("credential-injection — proxy injects API key", "credential-injection"),
                    ("oauth — proxy manages OAuth tokens", "oauth"),
                    ("user-auth — SSO authentication", "user-auth"),
                ],
                value=proxy_auth,
                id="daemon-proxy-auth-mode",
                allow_blank=False,
            )

        yield Static("")

        with Horizontal(classes="button-group"):
            yield Button("Save", id="daemon-save", variant="primary")
            yield Button("Start", id="daemon-start-btn", variant="success")
            yield Button("Stop", id="daemon-stop-btn", variant="error")
            yield Button("Status", id="daemon-status-btn", variant="default")

        yield Static("")
        yield Static("[bold]Daemon Status[/bold]", classes="section-header")
        yield Label(self.daemon_status, id="daemon-status-label")

    def on_mount(self) -> None:
        self._refresh_status()

    def watch_daemon_status(self, value: str) -> None:
        try:
            self.query_one("#daemon-status-label", Label).update(value)
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "daemon-save":
            self._save_config()
        elif event.button.id == "daemon-start-btn":
            self._start_daemon()
        elif event.button.id == "daemon-stop-btn":
            self._stop_daemon()
        elif event.button.id == "daemon-status-btn":
            self._refresh_status()

    def _start_daemon(self):
        try:
            from ai_guardian.daemon.client import is_daemon_running, start_daemon_background

            if is_daemon_running():
                self.app.notify("Daemon is already running", severity="warning")
                return

            self._update_mode_in_config("auto")
            if start_daemon_background():
                self.app.notify("Daemon started (mode set to 'auto')", severity="information")
            else:
                self.app.notify("Failed to start daemon", severity="error")
        except Exception as e:
            self.app.notify(f"Start failed: {e}", severity="error")
        self._refresh_status()

    def _stop_daemon(self):
        try:
            from ai_guardian.daemon.client import is_daemon_running, send_shutdown

            self._update_mode_in_config("local")
            if not is_daemon_running():
                self.app.notify("Daemon is not running (mode set to 'local')", severity="information")
            elif send_shutdown():
                self.app.notify("Daemon stopped (mode set to 'local')", severity="information")
            else:
                self.app.notify("Failed to stop daemon", severity="error")
        except Exception as e:
            self.app.notify(f"Stop failed: {e}", severity="error")
        self._refresh_status()

    def _update_mode_in_config(self, mode):
        config_path = get_config_dir() / "ai-guardian.json"
        if config_path.exists():
            config = json.loads(config_path.read_text(encoding="utf-8"))
        else:
            config = {}
        if "daemon" not in config:
            config["daemon"] = {}
        config["daemon"]["mode"] = mode
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

        # Update the mode dropdown
        try:
            self.query_one("#daemon-mode", Select).value = mode
        except Exception:
            pass

    def _save_config(self):
        try:
            mode_select = self.query_one("#daemon-mode", Select)
            idle_input = self.query_one("#daemon-idle-timeout", Input)
            client_input = self.query_one("#daemon-client-timeout", Input)
            tray_select = self.query_one("#daemon-tray-enabled", Select)

            config_path = get_config_dir() / "ai-guardian.json"
            if config_path.exists():
                full_config = json.loads(config_path.read_text(encoding="utf-8"))
            else:
                full_config = {}

            # Read proxy widget values
            proxy_enabled = self.query_one("#daemon-proxy-enabled", Select).value
            proxy_port = self.query_one("#daemon-proxy-port", Input).value
            proxy_backend = self.query_one("#daemon-proxy-backend-url", Input).value
            proxy_tls = self.query_one("#daemon-proxy-tls-verify", Select).value
            proxy_auth = self.query_one("#daemon-proxy-auth-mode", Select).value

            # Preserve any existing proxy keys not shown in UI
            existing_proxy = full_config.get("daemon", {}).get("proxy", {})
            existing_tls = existing_proxy.get("tls", {})

            proxy_cfg = {
                "enabled": proxy_enabled,
                "listen_port": int(proxy_port or 63152),
                "backend_url": proxy_backend or "",
                "tls": {
                    "verify_backend": proxy_tls,
                    "client_cert": existing_tls.get("client_cert"),
                    "client_key": existing_tls.get("client_key"),
                },
                "auth": {
                    "mode": proxy_auth,
                },
            }

            # Validate proxy config when proxy is enabled
            if proxy_enabled:
                from ai_guardian.daemon.proxy import validate_proxy_config
                errors = validate_proxy_config(proxy_cfg)
                if errors:
                    self.app.notify(
                        "Proxy config invalid:\n" + "\n".join(errors),
                        severity="error",
                    )
                    return

            full_config["daemon"] = {
                "mode": mode_select.value,
                "idle_timeout_minutes": int(idle_input.value or 30),
                "client_timeout_seconds": float(client_input.value or 2.0),
                "tray": {
                    "enabled": tray_select.value,
                },
                "proxy": proxy_cfg,
            }

            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                json.dumps(full_config, indent=2) + "\n", encoding="utf-8"
            )
            self.app.notify("Daemon config saved", severity="information")
        except Exception as e:
            self.app.notify(f"Save failed: {e}", severity="error")

    def _refresh_status(self):
        try:
            from ai_guardian.daemon.client import is_daemon_running, send_status_request
            from ai_guardian.daemon.server import get_socket_path, get_pid_path

            if not is_daemon_running():
                self.daemon_status = "[red]Not running[/red]"
                return

            stats = send_status_request()
            if stats:
                uptime = stats.get("uptime_seconds", 0)
                hours = int(uptime // 3600)
                minutes = int((uptime % 3600) // 60)
                uptime_str = f"{hours}h {minutes}m" if hours else f"{minutes}m"
                paused = " [yellow](PAUSED)[/yellow]" if stats.get("paused") else ""

                pid_path = get_pid_path()
                pid = "?"
                try:
                    pid_info = json.loads(pid_path.read_text())
                    pid = pid_info.get("pid", "?")
                except Exception:
                    pass

                lines = [
                    f"[green]Running[/green] (pid {pid}){paused}",
                    f"Uptime: {uptime_str}",
                    f"Requests: {stats.get('request_count', 0)}",
                    f"Blocked: {stats.get('blocked_count', 0)}",
                    f"Warnings: {stats.get('warning_count', 0)}",
                    f"Log-only: {stats.get('log_only_count', 0)}",
                    f"Violations: {stats.get('violation_count', 0)}",
                    f"Socket: {get_socket_path()}",
                ]

                proxy_port = stats.get("proxy_port", 0)
                if proxy_port:
                    proxy_reqs = stats.get("proxy_request_count", 0)
                    proxy_viols = stats.get("proxy_violations_count", 0)
                    proxy_blocked = stats.get("proxy_blocked_count", 0)
                    lines.append(f"Proxy: port {proxy_port} ({proxy_reqs} reqs, {proxy_viols} violations, {proxy_blocked} blocked)")
                self.daemon_status = "\n".join(lines)
            else:
                self.daemon_status = "[yellow]Running but could not fetch stats[/yellow]"
        except Exception as e:
            self.daemon_status = f"[red]Error: {e}[/red]"

    @staticmethod
    def _load_daemon_config():
        try:
            config_path = get_config_dir() / "ai-guardian.json"
            if config_path.exists():
                config = json.loads(config_path.read_text(encoding="utf-8"))
                return config.get("daemon", {})
        except Exception:
            pass
        return {}
