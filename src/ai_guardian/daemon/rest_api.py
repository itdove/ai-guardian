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


_VALID_CHECKS = frozenset({
    "secrets", "pii", "injection", "ssrf", "context_poisoning",
})

_ALL_CHECKS = list(_VALID_CHECKS)


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
            try:
                limit = int(qs.get("limit", ["50"])[0])
            except ValueError:
                limit = 50
            vtype = qs.get("type", [None])[0]
            self._send_json(self._get_violations(limit, vtype))
        elif path == "/api/metrics":
            qs = urllib.parse.parse_qs(parsed.query)
            since_str = qs.get("since_days", [None])[0]
            try:
                since_days = int(since_str) if since_str else None
            except ValueError:
                since_days = None
            self._send_json(self._get_metrics(since_days))
        elif path == "/api/audit":
            qs = urllib.parse.parse_qs(parsed.query)
            since = qs.get("since", ["30d"])[0]
            until = qs.get("until", [None])[0]
            vtype = qs.get("type", [None])[0]
            severity = qs.get("severity", [None])[0]
            self._send_json(self._get_audit(since, until, vtype, severity))
        elif path == "/api/ml-status":
            self._send_json(self.server.daemon_state.get_ml_status())
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
        elif self.path == "/api/pause_dir":
            body = self._read_body()
            if body is None:
                return
            directory = body.get("dir", "")
            if not directory:
                self._send_error(400, "dir is required")
                return
            minutes = body.get("minutes", 0)
            if not isinstance(minutes, (int, float)) or minutes < 0 or minutes > 1440:
                self._send_error(400, "minutes must be a number between 0 and 1440")
                return
            self.server.daemon_state.pause_dir(directory, minutes)
            self._send_json({"status": "dir_paused", "dir": directory, "minutes": minutes})
        elif self.path == "/api/resume_dir":
            body = self._read_body()
            if body is None:
                return
            directory = body.get("dir", "")
            if not directory:
                self._send_error(400, "dir is required")
                return
            self.server.daemon_state.resume_dir(directory)
            self._send_json({"status": "dir_resumed", "dir": directory})
        elif self.path == "/api/reload":
            self.server.daemon_state.force_reload_config()
            self._send_json({"status": "config_reloaded"})
        elif self.path == "/api/ml-detect":
            body = self._read_body()
            if body is None:
                return
            content = body.get("content", "")
            if not content:
                self._send_error(400, "content is required")
                return
            manager = self.server.daemon_state.get_ml_engine_manager()
            if manager is None:
                ml_status = self.server.daemon_state.get_ml_status()
                self._send_json({
                    "available": False,
                    "error": ml_status.get(
                        "ml_load_error", "ML model not available"
                    ),
                })
            else:
                result = manager.detect(content)
                self._send_json(result)
        elif self.path == "/api/violation-context":
            body = self._read_body(max_size=self._MAX_CONTENT_SIZE)
            if body is None:
                return
            self._handle_violation_context(body)
        elif self.path == "/api/prompt":
            body = self._read_body(max_size=self._MAX_CONTENT_SIZE)
            if body is None:
                return
            self._handle_prompt(body)
        elif self.path == "/api/check":
            body = self._read_body(max_size=self._MAX_CONTENT_SIZE)
            if body is None:
                return
            self._handle_check(body)
        elif self.path == "/api/redact":
            body = self._read_body(max_size=self._MAX_CONTENT_SIZE)
            if body is None:
                return
            self._handle_redact(body)
        else:
            self._send_error(404, "Not found")

    def _get_status(self):
        state = self.server.daemon_state
        stats = state.get_stats()
        paused_dirs = stats.get("paused_dirs", {})
        result = {
            "running": True,
            "paused": stats.get("paused", False),
            "paused_dirs": len(paused_dirs),
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
    def _get_audit(since, until, violation_type, severity):
        try:
            from ai_guardian.daemon.multi_client import MultiDaemonClient
            return MultiDaemonClient._local_audit(since, until, violation_type, severity)
        except Exception as e:
            logger.debug("Failed to get audit: %s", e)
            return {"summary": {"total": 0}, "security_posture": "UNKNOWN"}

    @staticmethod
    def _get_version():
        try:
            from ai_guardian import __version__
            return __version__
        except ImportError:
            return "unknown"

    _MAX_BODY_SIZE = 64 * 1024
    _MAX_CONTENT_SIZE = 1024 * 1024

    def _handle_check(self, body):
        """Handle POST /api/check — content security scanning."""
        import time as _time
        content = body.get("content", "")
        if not content:
            self._send_error(400, "content is required")
            return

        checks = body.get("checks") or _ALL_CHECKS
        if not isinstance(checks, list):
            self._send_error(400, "checks must be an array")
            return
        invalid = set(checks) - _VALID_CHECKS
        if invalid:
            self._send_error(
                400, f"Invalid checks: {', '.join(sorted(invalid))}. "
                     f"Valid: {', '.join(sorted(_VALID_CHECKS))}"
            )
            return

        action = body.get("action", "block")
        if action not in ("block", "warn", "log"):
            self._send_error(400, "action must be 'block', 'warn', or 'log'")
            return

        t0 = _time.monotonic()

        try:
            from ai_guardian.sdk import _DirectSession
            cfg = self.server.daemon_state.get_config()
            session = _DirectSession(action="log", config=cfg)

            findings = []

            if "secrets" in checks or "pii" in checks:
                result = session.check_content(content, filename="input")
                if result.detected:
                    findings.append({
                        "type": result.violation_type,
                        "message": result.message,
                        "action_taken": action,
                    })

            if "injection" in checks:
                pi_cfg = cfg.get("prompt_injection", {})
                if pi_cfg.get("enabled", True):
                    try:
                        from ai_guardian.prompt_injection import (
                            check_prompt_injection,
                        )
                        should_block, msg, detected = check_prompt_injection(
                            content, cfg,
                        )
                        if detected and not any(
                            f["type"] == "prompt_injection" for f in findings
                        ):
                            findings.append({
                                "type": "prompt_injection",
                                "message": msg,
                                "action_taken": action,
                            })
                    except Exception as e:
                        logger.debug("Prompt injection check failed: %s", e)

            if "context_poisoning" in checks:
                cp_cfg = cfg.get("context_poisoning", {})
                if cp_cfg.get("enabled", True):
                    try:
                        from ai_guardian.context_poisoning import (
                            check_context_poisoning,
                        )
                        should_block, msg, detected = check_context_poisoning(
                            content, cfg,
                        )
                        if detected and not any(
                            f["type"] == "context_poisoning" for f in findings
                        ):
                            findings.append({
                                "type": "context_poisoning",
                                "message": msg,
                                "action_taken": action,
                            })
                    except Exception as e:
                        logger.debug("Context poisoning check failed: %s", e)

            redacted = None
            if findings:
                try:
                    from ai_guardian.sanitizer import sanitize_text
                    san_result = sanitize_text(content)
                    redacted = san_result.get("sanitized_text") or san_result.get("redacted")
                    if redacted is None:
                        redacted = content
                except Exception as e:
                    logger.debug("Sanitization failed: %s", e)
                    redacted = content

            elapsed = (_time.monotonic() - t0) * 1000

            self._send_json({
                "clean": len(findings) == 0,
                "findings": findings,
                "redacted": redacted,
                "elapsed_ms": round(elapsed, 1),
            })
        except Exception as e:
            logger.error("Check endpoint failed: %s", e)
            self._send_error(500, "Internal error")

    def _handle_violation_context(self, body):
        """Handle POST /api/violation-context — rescan file for matched text."""
        file_path = body.get("file_path", "")
        violation_type = body.get("violation_type", "")
        if not violation_type:
            self._send_error(400, "violation_type is required")
            return

        line_number = int(body.get("line_number", 0))
        sub_type = body.get("secret_type", "")

        try:
            from ai_guardian.daemon.violation_rescan import rescan_violation
        except ImportError as e:
            logger.warning("Rescan module not available: %s", e)
            self._send_error(503, "Rescan module not available")
            return

        cfg = self.server.daemon_state.get_config()
        result = rescan_violation(
            file_path=file_path,
            line_number=line_number,
            violation_type=violation_type,
            sub_type=sub_type,
            config=cfg,
        )
        self._send_json(result)

    def _handle_prompt(self, body):
        """Handle POST /api/prompt — delegate ask dialog to subprocess.

        Spawns 'ai-guardian prompt --mode ask' as a subprocess instead of
        running tkinter in-process. On macOS, tk.Tk() MUST run on the main
        thread — calling it in a background thread hangs/crashes the daemon.
        """
        mode = body.get("mode", "ask")
        if mode != "ask":
            self._send_error(400, "Only mode=ask is supported via REST")
            return

        violation_data = body.get("violation")
        if not violation_data or not isinstance(violation_data, dict):
            self._send_error(400, "violation object is required")
            return

        fallback = body.get("fallback", "block")
        timeout = int(body.get("timeout", 300))

        try:
            from ai_guardian.tui.ask_dialog import (
                AskViolationInfo,
                _show_via_subprocess,
                _map_fallback_to_decision,
                AskDecision,
            )
        except ImportError as e:
            logger.warning("Prompt UI dependencies not available: %s", e)
            self._send_error(503, "UI dependencies not available")
            return

        violation = AskViolationInfo(
            violation_type=violation_data.get("violation_type", ""),
            summary=violation_data.get("summary", ""),
            matched_text=violation_data.get("matched_text", ""),
            config_section=violation_data.get("config_section", ""),
            error_message=violation_data.get("error_message", ""),
            matched_pattern=violation_data.get("matched_pattern", ""),
            file_path=violation_data.get("file_path"),
            line_number=violation_data.get("line_number"),
        )

        result = _show_via_subprocess(violation, fallback, timeout)

        if result is None:
            decision = _map_fallback_to_decision(fallback)
            self._send_json({
                "decision": decision.value,
                "allowlist_pattern": None,
                "config_saved": False,
                "source": "fallback",
            })
        else:
            self._send_json({
                "decision": result.decision.value,
                "allowlist_pattern": result.allowlist_pattern,
                "config_saved": getattr(result, 'config_saved', False),
                "source": "daemon",
            })

    def _handle_redact(self, body):
        """Handle POST /api/redact — text sanitization."""
        content = body.get("content", "")
        if not content:
            self._send_error(400, "content is required")
            return
        try:
            from ai_guardian.sanitizer import sanitize_text
            result = sanitize_text(content)
            redacted = result.get("sanitized_text") or result.get("redacted")
            if redacted is None:
                logger.error("Sanitizer returned unexpected structure: %s", list(result.keys()))
                self._send_error(500, "Internal error")
                return
            stats = result.get("stats", {})
            count = stats.get("total", 0) if isinstance(stats, dict) else 0
            if count == 0:
                redactions = result.get("redactions", [])
                if isinstance(redactions, list):
                    count = len(redactions)
            self._send_json({
                "redacted": redacted,
                "redaction_count": count,
            })
        except Exception as e:
            logger.error("Redact endpoint failed: %s", e)
            self._send_error(500, "Internal error")

    def _read_body(self, max_size=None):
        limit = max_size or self._MAX_BODY_SIZE
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self._send_error(400, "Invalid Content-Length")
            return None
        if content_length == 0:
            return {}
        if content_length > limit:
            self._send_error(413, "Request body too large")
            return None
        try:
            raw = self.rfile.read(content_length)
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_error(400, "Invalid JSON")
            return None

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
