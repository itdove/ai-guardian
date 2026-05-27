"""
Web Console Application (NiceGUI).

Provides a browser-based dashboard for AI Guardian, connecting to daemons
via their REST APIs. Binds to localhost only for security.

Each daemon gets its own URL namespace: /{daemon_name}/...
Multiple browser tabs can view different daemons simultaneously.
"""

import atexit
import base64
import logging
import socket
from pathlib import Path

from nicegui import app, ui

from ai_guardian.web.services.daemon_service import DaemonService

logger = logging.getLogger(__name__)


def _get_port_file():
    from ai_guardian.config_utils import get_state_dir
    return get_state_dir() / "web-console.port"


def _cleanup_port_file():
    try:
        _get_port_file().unlink(missing_ok=True)
    except OSError:
        pass


def _write_port(port: int):
    try:
        port_file = _get_port_file()
        port_file.parent.mkdir(parents=True, exist_ok=True)
        port_file.write_text(str(port))
        logger.info("Web console on port %d", port)
    except OSError as e:
        logger.debug("Failed to write port file: %s", e)


class WebConsole:
    """Browser-based AI Guardian console powered by NiceGUI."""

    def __init__(self):
        self._service = DaemonService()

    def run(self, host: str = "127.0.0.1", port: int = 0, show: bool = True):
        if host != "127.0.0.1":
            logger.warning(
                "Web console binding to %s — exposed on network.", host
            )

        if port == 0:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((host, 0))
            port = sock.getsockname()[1]
            sock.close()

        self._register_pages()
        atexit.register(_cleanup_port_file)
        _write_port(port)

        pkg_dir = Path(__file__).resolve().parent.parent
        images_dir = pkg_dir / "images"
        if not images_dir.is_dir():
            images_dir = pkg_dir.parent.parent / "images"
        if images_dir.is_dir():
            app.add_static_files("/images", str(images_dir))

        favicon_path = images_dir / "ai-guardian-320.png"
        favicon_value = "🛡️"
        if favicon_path.exists():
            try:
                b64 = base64.b64encode(favicon_path.read_bytes()).decode()
                favicon_value = f"data:image/png;base64,{b64}"
            except OSError:
                pass

        ui.run(
            host=host,
            port=port,
            title="AI Guardian Web Console",
            dark=True,
            reload=False,
            show=show,
            favicon=favicon_value,
        )

    def _register_pages(self):
        service = self._service

        @ui.page("/")
        def index_page():
            from ai_guardian.web.pages.daemon_picker import (
                create_daemon_picker_page,
            )
            create_daemon_picker_page(service)

        @ui.page("/{daemon_name}")
        def dashboard_page(daemon_name: str):
            from ai_guardian.web.pages.dashboard import create_dashboard_page
            create_dashboard_page(service, daemon_name)

        @ui.page("/{daemon_name}/settings")
        def settings_page(daemon_name: str):
            from ai_guardian.web.pages.global_settings import (
                create_global_settings_page,
            )
            create_global_settings_page(service, daemon_name)

        @ui.page("/{daemon_name}/violations")
        def violations_page(daemon_name: str):
            from ai_guardian.web.pages.violations import (
                create_violations_page,
            )
            create_violations_page(service, daemon_name)

        @ui.page("/{daemon_name}/violation-logging")
        def violation_logging_page(daemon_name: str):
            from ai_guardian.web.pages.violation_logging import (
                create_violation_logging_page,
            )
            create_violation_logging_page(service, daemon_name)

        @ui.page("/{daemon_name}/metrics")
        def metrics_page(daemon_name: str):
            from ai_guardian.web.pages.metrics import create_metrics_page
            create_metrics_page(service, daemon_name)

        @ui.page("/{daemon_name}/logs")
        def logs_page(daemon_name: str):
            from ai_guardian.web.pages.logs import create_logs_page
            create_logs_page(service, daemon_name)

        @ui.page("/{daemon_name}/skills")
        def skills_page(daemon_name: str):
            from ai_guardian.web.pages.skills import create_skills_page
            create_skills_page(service, daemon_name)

        @ui.page("/{daemon_name}/mcp-servers")
        def mcp_servers_page(daemon_name: str):
            from ai_guardian.web.pages.mcp_servers import (
                create_mcp_servers_page,
            )
            create_mcp_servers_page(service, daemon_name)

        @ui.page("/{daemon_name}/mcp-security")
        def mcp_security_page(daemon_name: str):
            from ai_guardian.web.pages.mcp_security import (
                create_mcp_security_page,
            )
            create_mcp_security_page(service, daemon_name)

        @ui.page("/{daemon_name}/permissions-discovery")
        def permissions_discovery_page(daemon_name: str):
            from ai_guardian.web.pages.permissions_discovery import (
                create_permissions_discovery_page,
            )
            create_permissions_discovery_page(service, daemon_name)

        @ui.page("/{daemon_name}/directory-rules")
        def directory_rules_page(daemon_name: str):
            from ai_guardian.web.pages.directory_rules import (
                create_directory_rules_page,
            )
            create_directory_rules_page(service, daemon_name)

        @ui.page("/{daemon_name}/secrets")
        def secrets_page(daemon_name: str):
            from ai_guardian.web.pages.secrets import create_secrets_page
            create_secrets_page(service, daemon_name)

        @ui.page("/{daemon_name}/secret-engines")
        def secret_engines_page(daemon_name: str):
            from ai_guardian.web.pages.secret_engines import (
                create_secret_engines_page,
            )
            create_secret_engines_page(service, daemon_name)

        @ui.page("/{daemon_name}/secret-redaction")
        def secret_redaction_page(daemon_name: str):
            from ai_guardian.web.pages.secret_redaction import (
                create_secret_redaction_page,
            )
            create_secret_redaction_page(service, daemon_name)

        @ui.page("/{daemon_name}/pi-detection")
        def pi_detection_page(daemon_name: str):
            from ai_guardian.web.pages.pi_detection import (
                create_pi_detection_page,
            )
            create_pi_detection_page(service, daemon_name)

        @ui.page("/{daemon_name}/pi-patterns")
        def pi_patterns_page(daemon_name: str):
            from ai_guardian.web.pages.pi_patterns import (
                create_pi_patterns_page,
            )
            create_pi_patterns_page(service, daemon_name)

        @ui.page("/{daemon_name}/pi-jailbreak")
        def pi_jailbreak_page(daemon_name: str):
            from ai_guardian.web.pages.pi_jailbreak import (
                create_pi_jailbreak_page,
            )
            create_pi_jailbreak_page(service, daemon_name)

        @ui.page("/{daemon_name}/pi-unicode")
        def pi_unicode_page(daemon_name: str):
            from ai_guardian.web.pages.pi_unicode import (
                create_pi_unicode_page,
            )
            create_pi_unicode_page(service, daemon_name)

        @ui.page("/{daemon_name}/ssrf")
        def ssrf_page(daemon_name: str):
            from ai_guardian.web.pages.ssrf import create_ssrf_page
            create_ssrf_page(service, daemon_name)

        @ui.page("/{daemon_name}/config-scanner")
        def config_scanner_page(daemon_name: str):
            from ai_guardian.web.pages.config_scanner import (
                create_config_scanner_page,
            )
            create_config_scanner_page(service, daemon_name)

        @ui.page("/{daemon_name}/scan-pii")
        def scan_pii_page(daemon_name: str):
            from ai_guardian.web.pages.scan_pii import (
                create_scan_pii_page,
            )
            create_scan_pii_page(service, daemon_name)

        @ui.page("/{daemon_name}/annotations")
        def annotations_page(daemon_name: str):
            from ai_guardian.web.pages.annotations import (
                create_annotations_page,
            )
            create_annotations_page(service, daemon_name)

        @ui.page("/{daemon_name}/daemon")
        def daemon_detail_page(daemon_name: str):
            from ai_guardian.web.pages.daemon_detail import (
                create_daemon_detail_page,
            )
            create_daemon_detail_page(service, daemon_name)
