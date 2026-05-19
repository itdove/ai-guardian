"""
Lightweight REST API for daemon tray-to-daemon communication.

Provides HTTP endpoints for status queries and control actions,
enabling cross-network communication with container and remote daemons.
Uses only stdlib http.server — no additional dependencies.
"""

import json
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)


class _RestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for daemon REST API."""

    def log_message(self, format, *args):
        logger.debug(format, *args)

    def do_GET(self):
        if self.path == "/api/status":
            self._send_json(self._get_status())
        elif self.path == "/api/stats":
            self._send_json(self._get_stats())
        elif self.path == "/api/health":
            self._send_json({"status": "ok"})
        else:
            self._send_error(404, "Not found")

    def do_POST(self):
        if self.path == "/api/pause":
            body = self._read_body()
            if body is None:
                return
            minutes = body.get("minutes", 0)
            self.server.daemon_state.pause(minutes)
            self._send_json({"status": "paused", "minutes": minutes})
        elif self.path == "/api/resume":
            self.server.daemon_state.resume()
            self._send_json({"status": "resumed"})
        else:
            self._send_error(404, "Not found")

    def _get_status(self):
        state = self.server.daemon_state
        stats = state.get_stats()
        return {
            "running": True,
            "paused": stats.get("paused", False),
            "uptime_seconds": stats.get("uptime_seconds", 0),
            "version": self._get_version(),
            "name": getattr(self.server, 'instance_name', None) or "ai-guardian",
        }

    def _get_stats(self):
        stats = self.server.daemon_state.get_stats()
        name = getattr(self.server, 'instance_name', None)
        if name:
            stats["name"] = name
        return stats

    @staticmethod
    def _get_version():
        try:
            from ai_guardian import __version__
            return __version__
        except ImportError:
            return "unknown"

    _MAX_BODY_SIZE = 64 * 1024

    def _read_body(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self._send_error(400, "Invalid Content-Length")
            return None
        if content_length == 0:
            return {}
        if content_length > self._MAX_BODY_SIZE:
            self._send_error(413, "Request body too large")
            return None
        try:
            raw = self.rfile.read(content_length)
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_error(400, "Invalid JSON")
            return None  # callers must check for None before using result

    def _send_json(self, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code, message):
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DaemonRestAPI:
    """Minimal REST API for tray-to-daemon communication."""

    def __init__(self, state, host="127.0.0.1", port=0, name=None):
        """Initialize REST API server.

        Args:
            state: DaemonState instance for querying stats and controlling pause
            host: Bind address (127.0.0.1 for local, 0.0.0.0 for containers)
            port: Port to bind (0 for OS-assigned)
            name: Human-friendly name for this daemon
        """
        self._state = state
        self._host = host
        self._port = port
        self._name = name
        self._server = None
        self._thread = None

    def start(self) -> int:
        """Start HTTP server in background thread. Returns bound port."""
        self._server = HTTPServer((self._host, self._port), _RestHandler)
        self._server.daemon_state = self._state
        self._server.instance_name = self._name
        actual_port = self._server.server_address[1]

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="rest-api",
        )
        self._thread.start()

        logger.info(
            "REST API listening on %s:%d", self._host, actual_port
        )
        return actual_port

    def stop(self):
        """Stop HTTP server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    @property
    def port(self) -> int:
        """Return the bound port (0 if not started)."""
        if self._server:
            return self._server.server_address[1]
        return 0
