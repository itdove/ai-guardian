"""
Web Console Application (NiceGUI).

Provides a browser-based dashboard for AI Guardian, connecting to daemons
via their REST APIs. Binds to localhost only for security.

Each daemon gets its own URL namespace: /{daemon_name}/...
Multiple browser tabs can view different daemons simultaneously.
"""

import atexit
import logging
import socket

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

        ui.run(
            host=host,
            port=port,
            title="AI Guardian Web Console",
            dark=True,
            reload=False,
            show=show,
            favicon="🛡️",
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

        @ui.page("/{daemon_name}/daemon")
        def daemon_detail_page(daemon_name: str):
            from ai_guardian.web.pages.daemon_detail import (
                create_daemon_detail_page,
            )
            create_daemon_detail_page(service, daemon_name)
