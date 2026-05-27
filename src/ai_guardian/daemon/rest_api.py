"""
Lightweight REST API for daemon tray-to-daemon communication.

Provides HTTP endpoints for status queries and control actions,
enabling cross-network communication with container and remote daemons.
Uses only stdlib http.server — no additional dependencies.
"""

import json
import logging
import threading
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)


class _RestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for daemon REST API."""

    def log_message(self, format, *args):
        logger.debug(format, *args)

    def do_GET(self):
        if self.path == "/api/health":
            self._send_json({"status": "ok"})
            return
        if not self._check_auth():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/status":
            self._send_json(self._get_status())
        elif path == "/api/stats":
            self._send_json(self._get_stats())
        elif path == "/api/about":
            self._send_json(self._get_about())
        elif path == "/api/tray-plugins":
            self._send_json(self._get_tray_plugins())
        elif path == "/api/config":
            self._send_json(self._get_config())
        elif path == "/api/violations":
            qs = urllib.parse.parse_qs(parsed.query)
            limit = int(qs.get("limit", ["50"])[0])
            vtype = qs.get("type", [None])[0]
            self._send_json(self._get_violations(limit, vtype))
        elif path == "/api/metrics":
            qs = urllib.parse.parse_qs(parsed.query)
            since_str = qs.get("since_days", [None])[0]
            since_days = int(since_str) if since_str else None
            self._send_json(self._get_metrics(since_days))
        else:
            self._send_error(404, "Not found")

    def _check_auth(self):
        """Check bearer token if the server has one configured."""
        token = getattr(self.server, 'auth_token', None)
        if not token:
            return True
        auth_header = self.headers.get("Authorization", "")
        if auth_header == f"Bearer {token}":
            return True
        self._send_error(401, "Unauthorized")
        return False

    def do_POST(self):
        if not self._check_auth():
            return
        if self.path == "/api/pause":
            body = self._read_body()
            if body is None:
                return
            minutes = body.get("minutes", 0)
            if not isinstance(minutes, (int, float)) or minutes < 0 or minutes > 1440:
                self._send_error(400, "minutes must be a number between 0 and 1440")
                return
            self.server.daemon_state.pause(minutes)
            self._send_json({"status": "paused", "minutes": minutes})
        elif self.path == "/api/resume":
            self.server.daemon_state.resume()
            self._send_json({"status": "resumed"})
        elif self.path == "/api/reload":
            self.server.daemon_state.force_reload_config()
            self._send_json({"status": "config_reloaded"})
        else:
            self._send_error(404, "Not found")

    def _get_status(self):
        state = self.server.daemon_state
        stats = state.get_stats()
        result = {
            "running": True,
            "paused": stats.get("paused", False),
            "uptime_seconds": stats.get("uptime_seconds", 0),
            "version": self._get_version(),
            "name": self._get_instance_name(),
            "mcp_installed": stats.get("mcp_installed", False),
        }
        menu_tags = self._get_menu_tags()
        if menu_tags:
            result["menu_tags"] = menu_tags
        return result

    def _get_stats(self):
        stats = self.server.daemon_state.get_stats()
        name = self._get_instance_name()
        if name:
            stats["name"] = name
        menu_tags = self._get_menu_tags()
        if menu_tags:
            stats["menu_tags"] = menu_tags
        return stats

    def _get_instance_name(self):
        """Get instance name from current config, falling back to startup value."""
        try:
            from ai_guardian.config_loaders import _load_config_file
            cfg, _ = _load_config_file()
            if cfg:
                name = cfg.get("name")
                if name:
                    return name
        except Exception:
            pass
        return getattr(self.server, 'instance_name', None) or "ai-guardian"

    @staticmethod
    def _get_menu_tags():
        """Get menu_tags from current config for plugin filtering."""
        from ai_guardian.daemon import get_local_menu_tags
        return get_local_menu_tags()

    @staticmethod
    def _get_about():
        try:
            from ai_guardian.daemon.about import get_about_info
            return get_about_info()
        except Exception as e:
            logger.debug("Failed to get about info: %s", e)
            return {}

    def _get_tray_plugins(self):
        try:
            from ai_guardian.daemon.tray_plugins import load_merged_plugins, plugins_to_dict
            from ai_guardian.daemon.working_dir import get_working_dir
            name = self._get_instance_name()
            working_dir = get_working_dir(name)
            return plugins_to_dict(load_merged_plugins(working_dir))
        except Exception as e:
            logger.debug("Failed to load tray plugins: %s", e)
            return {"plugins": []}

    @staticmethod
    def _get_config():
        try:
            from ai_guardian.daemon.multi_client import MultiDaemonClient
            return MultiDaemonClient._local_config()
        except Exception as e:
            logger.debug("Failed to get config: %s", e)
            return {"features": {}}

    @staticmethod
    def _get_violations(limit, violation_type):
        try:
            from ai_guardian.daemon.multi_client import MultiDaemonClient
            return MultiDaemonClient._local_violations(limit, violation_type)
        except Exception as e:
            logger.debug("Failed to get violations: %s", e)
            return {"violations": [], "count": 0}

    @staticmethod
    def _get_metrics(since_days):
        try:
            from ai_guardian.daemon.multi_client import MultiDaemonClient
            return MultiDaemonClient._local_metrics(since_days)
        except Exception as e:
            logger.debug("Failed to get metrics: %s", e)
            return {
                "total_violations": 0,
                "by_type": {},
                "by_severity": {},
                "resolved": 0,
                "unresolved": 0,
            }

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

    def __init__(self, state, host="127.0.0.1", port=0, name=None, auth_token=None):
        """Initialize REST API server.

        Args:
            state: DaemonState instance for querying stats and controlling pause
            host: Bind address (127.0.0.1 for local, 0.0.0.0 for containers)
            port: Port to bind (0 for OS-assigned)
            name: Human-friendly name for this daemon
            auth_token: Optional bearer token for POST endpoint authentication
        """
        self._state = state
        self._host = host
        self._port = port
        self._name = name
        self._auth_token = auth_token
        self._server = None
        self._thread = None

    def start(self) -> int:
        """Start HTTP server in background thread. Returns bound port."""
        self._server = HTTPServer((self._host, self._port), _RestHandler)
        self._server.daemon_state = self._state
        self._server.instance_name = self._name
        self._server.auth_token = self._auth_token
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
