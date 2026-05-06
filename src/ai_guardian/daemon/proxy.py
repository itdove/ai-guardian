"""
HTTP reverse proxy for scanning IDE-to-API traffic.

Sits between the IDE and the AI backend API (e.g., Anthropic). Applies
all enabled ai-guardian scans (secrets, PII, prompt injection, etc.)
to both outgoing requests and incoming responses, using the same
configuration as the hook-based scanning pipeline.
"""

import dataclasses
import http.server
import json
import logging
import ssl
import threading
import time
import urllib.error
import urllib.request
from typing import List, Optional

logger = logging.getLogger(__name__)

MAX_BODY_SIZE = 50 * 1024 * 1024  # 50 MB
DEFAULT_PORT = 63152
DEFAULT_BACKEND_URL = "https://api.anthropic.com"

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}

SKIP_RESPONSE_HEADERS = {"transfer-encoding", "connection"}


@dataclasses.dataclass
class ScanResult:
    """Result from scanning proxied content."""
    violations: List[dict]
    action: str  # "allow", "warn", "block"
    modified_body: Optional[bytes] = None
    scan_time_ms: float = 0.0


class ProxyScanner:
    """Applies all enabled ai-guardian scans to extracted text.

    Uses the same config loading and scanning functions as the hook
    pipeline, so scan toggles and actions are inherited automatically.
    """

    def __init__(self, daemon_state=None):
        self._daemon_state = daemon_state

    def scan_text(self, text, direction="request"):
        """Run all enabled scans on text.

        Args:
            text: Text content extracted from API payload
            direction: "request" (outgoing to AI) or "response" (incoming from AI)

        Returns:
            ScanResult with aggregated violations and strictest action
        """
        if not text or not text.strip():
            return ScanResult(violations=[], action="allow")

        start = time.monotonic()
        violations = []
        strictest = "allow"
        action_rank = {"allow": 0, "log-only": 1, "warn": 2, "redact": 3, "block": 4}

        def _update_strictest(action):
            nonlocal strictest
            if action_rank.get(action, 0) > action_rank.get(strictest, 0):
                strictest = action

        # Secret scanning (returns redacted text if secrets found)
        redacted_text = None
        try:
            redacted_text = self._scan_secrets(text, direction, violations, _update_strictest)
        except Exception as e:
            logger.warning(f"Proxy secret scan error (fail-open): {e}")

        # PII scanning
        try:
            self._scan_pii(text, direction, violations, _update_strictest)
        except Exception as e:
            logger.warning(f"Proxy PII scan error (fail-open): {e}")

        # Prompt injection (request direction only)
        if direction == "request":
            try:
                self._scan_prompt_injection(text, violations, _update_strictest)
            except Exception as e:
                logger.warning(f"Proxy prompt injection scan error (fail-open): {e}")

        # Normalize action for proxy response
        if strictest in ("redact", "log-only"):
            strictest = "warn"

        elapsed = (time.monotonic() - start) * 1000
        modified = redacted_text.encode("utf-8") if redacted_text else None
        return ScanResult(violations=violations, action=strictest,
                          modified_body=modified, scan_time_ms=elapsed)

    def _scan_secrets(self, text, direction, violations, update_strictest):
        from ai_guardian import _load_secret_scanning_config, check_secrets_with_gitleaks
        from ai_guardian.config_utils import is_feature_enabled

        config, _ = _load_secret_scanning_config()
        if config and not is_feature_enabled(config.get("enabled", True), config.get("disabled_until")):
            return None

        has_secrets, error_msg = check_secrets_with_gitleaks(
            text, f"proxy_{direction}",
            context={"hook_event": f"proxy_{direction}"},
            allowlist_patterns=config.get("allowlist_patterns", []) if config else [],
        )
        if has_secrets:
            violations.append({
                "type": "secret_detected",
                "direction": direction,
                "detail": error_msg or "Secret detected in proxied content",
            })
            update_strictest("block")
        return None

    def _scan_pii(self, text, direction, violations, update_strictest):
        from ai_guardian import _load_pii_config, _scan_for_pii
        from ai_guardian.config_utils import is_feature_enabled
        from datetime import datetime, timezone

        config, _ = _load_pii_config()
        if not config or not is_feature_enabled(config.get("enabled"), datetime.now(timezone.utc), default=True):
            return

        has_pii, _, redactions, warning = _scan_for_pii(text, config)
        if has_pii:
            pii_types = list(set(r["type"] for r in redactions))
            violations.append({
                "type": "pii_detected",
                "direction": direction,
                "detail": f"PII detected: {', '.join(pii_types)}",
                "pii_types": pii_types,
                "count": len(redactions),
            })
            update_strictest(config.get("action", "block"))

    def _scan_prompt_injection(self, text, violations, update_strictest):
        from ai_guardian import _load_prompt_injection_config
        from ai_guardian.config_utils import is_feature_enabled
        from datetime import datetime, timezone

        config, _ = _load_prompt_injection_config()
        if not config or not is_feature_enabled(config.get("enabled"), datetime.now(timezone.utc), default=True):
            return

        try:
            from ai_guardian.prompt_injection import PromptInjectionDetector
            detector = PromptInjectionDetector(config)
            should_block, error_msg, detected = detector.detect(text, source_type="user_prompt")
            if detected:
                violations.append({
                    "type": "prompt_injection",
                    "direction": "request",
                    "detail": error_msg or "Prompt injection detected",
                })
                if should_block:
                    update_strictest("block")
                else:
                    update_strictest("warn")
        except ImportError:
            pass


def _extract_text_from_payload(body, direction="request"):
    """Extract scannable text from API payload.

    Handles Anthropic Messages API format. Falls back to recursive
    string extraction for unknown formats.

    Args:
        body: Parsed JSON body dict
        direction: "request" or "response"

    Returns:
        str: Concatenated text content for scanning
    """
    if not isinstance(body, dict):
        return ""

    parts = []

    if direction == "request":
        # Anthropic Messages API request format
        # Only scan the LAST user message (new content), not the full
        # conversation history. Previous messages were already sent in
        # prior requests -- blocking because of history doesn't help.
        messages = body.get("messages", [])
        if messages:
            last_msg = messages[-1]
            content = last_msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
                    elif isinstance(block, str):
                        parts.append(block)
    else:
        # Anthropic Messages API response format
        for block in body.get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif isinstance(block, dict) and block.get("type") == "tool_use":
                inp = block.get("input", {})
                if isinstance(inp, dict):
                    parts.extend(_recursive_extract_strings(inp))

    if not parts:
        parts = _recursive_extract_strings(body, max_depth=5)

    return "\n".join(p for p in parts if p)


def _apply_redacted_text(original_body, redacted_text_bytes):
    """Replace the last message content in the JSON body with redacted text.

    Args:
        original_body: Original request body bytes
        redacted_text_bytes: Redacted text as bytes

    Returns:
        bytes: Modified JSON body with redacted last message
    """
    try:
        body_dict = json.loads(original_body)
        redacted = redacted_text_bytes.decode("utf-8")
        messages = body_dict.get("messages", [])
        if messages:
            last_msg = messages[-1]
            content = last_msg.get("content", "")
            if isinstance(content, str):
                last_msg["content"] = redacted
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        block["text"] = redacted
                        break
            return json.dumps(body_dict, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except Exception as e:
        logger.warning(f"Failed to apply redacted text: {e}")
    return original_body


def _recursive_extract_strings(obj, max_depth=3, _depth=0):
    """Recursively extract string values from a nested structure."""
    if _depth >= max_depth:
        return []
    results = []
    if isinstance(obj, str):
        if len(obj) > 10:
            results.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            results.extend(_recursive_extract_strings(v, max_depth, _depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(_recursive_extract_strings(item, max_depth, _depth + 1))
    return results


class ProxyRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that proxies to backend with scanning."""

    proxy_config = {}
    daemon_state = None
    scanner = None

    def do_POST(self):
        self._proxy_request()

    def do_GET(self):
        self._proxy_request()

    def do_PUT(self):
        self._proxy_request()

    def do_DELETE(self):
        self._proxy_request()

    def do_PATCH(self):
        self._proxy_request()

    def do_OPTIONS(self):
        self._proxy_request()

    def _proxy_request(self):
        if self.daemon_state:
            self.daemon_state.record_proxy_request()

        try:
            body = self._read_body()
            backend_url = self.proxy_config.get("backend_url", DEFAULT_BACKEND_URL)
            target_url = f"{backend_url.rstrip('/')}{self.path}"

            # Parse and scan request body
            scan_result = self._scan_body(body, "request")
            if scan_result and scan_result.action == "block":
                self._send_blocked_response(scan_result, 403)
                return

            # Apply redacted content to the request body before forwarding
            forward_body = body
            if scan_result and scan_result.modified_body:
                forward_body = _apply_redacted_text(body, scan_result.modified_body)

            # Forward request to backend
            status, resp_headers, resp_body = self._forward_request(
                self.command, target_url, forward_body
            )

            # Scan response body
            resp_scan = self._scan_body(resp_body, "response")
            if resp_scan and resp_scan.action == "block":
                self._send_blocked_response(resp_scan, 502)
                return

            # Send response back to client
            self.send_response(status)
            for key, val in resp_headers:
                if key.lower() not in SKIP_RESPONSE_HEADERS:
                    self.send_header(key, val)

            # Add warning header if violations detected
            if scan_result and scan_result.violations:
                self.send_header("X-AI-Guardian-Warnings",
                                 str(len(scan_result.violations)))
            if resp_scan and resp_scan.violations:
                self.send_header("X-AI-Guardian-Response-Warnings",
                                 str(len(resp_scan.violations)))

            if resp_body:
                self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            if resp_body:
                self.wfile.write(resp_body)

        except urllib.error.HTTPError as e:
            error_body = e.read() if hasattr(e, "read") else b""
            self.send_response(e.code)
            for key, val in e.headers.items():
                if key.lower() not in SKIP_RESPONSE_HEADERS:
                    self.send_header(key, val)
            if error_body:
                self.send_header("Content-Length", str(len(error_body)))
            self.end_headers()
            if error_body:
                self.wfile.write(error_body)
        except Exception as e:
            logger.error(f"Proxy request error: {e}")
            self._send_error_response(502, str(e))

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return b""
        if length > MAX_BODY_SIZE:
            logger.warning(f"Request body too large ({length} bytes), passing through unscanned")
            return self.rfile.read(length)
        return self.rfile.read(length)

    def _scan_body(self, body, direction):
        if not body or not self.scanner:
            return None
        # Skip scanning when daemon is paused (proxy still forwards)
        if self.daemon_state and self.daemon_state.paused:
            return None
        if len(body) > MAX_BODY_SIZE:
            return None

        try:
            body_dict = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

        # Streaming: scan the request body (it's normal JSON), but skip
        # scanning the response (SSE chunks need buffering — Phase 2)
        if direction == "response" and body_dict.get("type") == "message_start":
            logger.info("Streaming response detected, passing through unscanned (Phase 2)")
            return None

        text = _extract_text_from_payload(body_dict, direction)
        if not text:
            return None

        # Log message structure for debugging
        msg_count = len(body_dict.get("messages", []))
        last_role = body_dict.get("messages", [{}])[-1].get("role", "?") if msg_count else "?"
        logger.info(f"Proxy {direction}: {msg_count} messages, last={last_role}")

        text_preview = text[:200].replace('\n', ' ')
        logger.info(f"Proxy scanning {direction} ({len(text)} chars): {text_preview}...")

        result = self.scanner.scan_text(text, direction)

        if result.violations:
            if self.daemon_state:
                for _ in result.violations:
                    self.daemon_state.record_proxy_violation()
            if result.action == "block" and self.daemon_state:
                self.daemon_state.record_proxy_blocked()
            logger.warning(
                f"Proxy {direction}: {len(result.violations)} violation(s), action={result.action}"
            )
            self._log_violations(result.violations, direction)

        return result

    def _forward_request(self, method, url, body):
        headers = {}
        for key in self.headers:
            lk = key.lower()
            # Skip hop-by-hop, host (urllib sets it), accept-encoding,
            # and content-length (recalculated from actual body)
            if lk not in HOP_BY_HOP_HEADERS and lk not in ("host", "accept-encoding", "content-length"):
                headers[key] = self.headers[key]
        if body:
            headers["Content-Length"] = str(len(body))

        tls_config = self.proxy_config.get("tls", {})
        ctx = None
        if url.startswith("https://"):
            if not tls_config.get("verify_backend", True):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            else:
                ctx = ssl.create_default_context()
            client_cert = tls_config.get("client_cert")
            client_key = tls_config.get("client_key")
            if client_cert and client_key:
                ctx.load_cert_chain(client_cert, client_key)

        req = urllib.request.Request(
            url, data=body if body else None, headers=headers, method=method
        )

        resp = urllib.request.urlopen(req, context=ctx, timeout=120)
        status = resp.status
        resp_headers = resp.getheaders()
        resp_body = resp.read()

        # Decompress if backend sent compressed despite no Accept-Encoding
        content_encoding = resp.headers.get("Content-Encoding", "")
        if content_encoding == "gzip":
            import gzip
            resp_body = gzip.decompress(resp_body)
            resp_headers = [
                (k, v) for k, v in resp_headers if k.lower() != "content-encoding"
            ]

        return status, resp_headers, resp_body

    def _send_blocked_response(self, scan_result, status_code):
        violation_types = [v.get("type", "unknown") for v in scan_result.violations]
        details = [v.get("detail", "") for v in scan_result.violations]
        detail_text = "; ".join(d for d in details if d)

        # Format as Anthropic API error response so Claude Code displays it
        message = (
            "\n" + "=" * 70 + "\n"
            "\U0001f6e1️  AI GUARDIAN PROXY - REQUEST BLOCKED\n"
            + "=" * 70 + "\n"
            f"Violation(s): {', '.join(violation_types)}\n"
        )
        if detail_text:
            message += f"\n{detail_text}\n"
        message += (
            "\n" + "=" * 70 + "\n"
        )

        body = json.dumps({
            "type": "error",
            "error": {
                "type": "invalid_request_error",
                "message": message,
            },
        }).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_response(self, status_code, message):
        body = json.dumps({
            "error": {"type": "proxy_error", "message": message}
        }).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _log_violations(self, violations, direction):
        try:
            from ai_guardian.violation_logger import ViolationLogger
            vlogger = ViolationLogger()
            for v in violations:
                vlogger.log_violation(
                    violation_type=v.get("type", "proxy_violation"),
                    blocked={"direction": direction, "detail": v.get("detail", "")},
                    context={"source": "proxy", "direction": direction},
                )
        except Exception as e:
            logger.debug(f"Violation logging error: {e}")

    def log_message(self, format, *args):
        logger.info(f"Proxy: {format % args}")


def validate_proxy_config(proxy_config):
    """Validate proxy configuration and return list of errors.

    Args:
        proxy_config: Proxy config dict

    Returns:
        list: Error message strings (empty if valid)
    """
    errors = []
    if not isinstance(proxy_config, dict):
        return ["proxy config must be a dict"]

    backend_url = proxy_config.get("backend_url")
    if not backend_url or not isinstance(backend_url, str) or not backend_url.strip():
        errors.append("proxy.backend_url is required (e.g., 'https://api.anthropic.com')")
    elif not backend_url.startswith(("http://", "https://")):
        errors.append(f"proxy.backend_url must start with http:// or https:// (got '{backend_url}')")

    port = proxy_config.get("listen_port", DEFAULT_PORT)
    if not isinstance(port, int) or (port != 0 and (port < 1024 or port > 65535)):
        errors.append(f"proxy.listen_port must be 0 (auto-assign) or an integer between 1024 and 65535 (got {port!r})")

    tls = proxy_config.get("tls")
    if tls and isinstance(tls, dict):
        client_cert = tls.get("client_cert")
        client_key = tls.get("client_key")
        if client_cert and not client_key:
            errors.append("proxy.tls.client_key is required when client_cert is set")
        if client_key and not client_cert:
            errors.append("proxy.tls.client_cert is required when client_key is set")
        if client_cert and isinstance(client_cert, str):
            from pathlib import Path
            if not Path(client_cert).expanduser().exists():
                errors.append(f"proxy.tls.client_cert file not found: {client_cert}")
        if client_key and isinstance(client_key, str):
            from pathlib import Path
            if not Path(client_key).expanduser().exists():
                errors.append(f"proxy.tls.client_key file not found: {client_key}")

    auth = proxy_config.get("auth")
    if auth and isinstance(auth, dict):
        mode = auth.get("mode", "pass-through")
        valid_modes = ("pass-through", "credential-injection", "oauth", "user-auth")
        if mode not in valid_modes:
            errors.append(f"proxy.auth.mode must be one of {valid_modes} (got '{mode}')")

    return errors


class _ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer with allow_reuse_address."""
    allow_reuse_address = True
    daemon_threads = True


class ProxyServer:
    """HTTP reverse proxy server for ai-guardian daemon."""

    def __init__(self, proxy_config, daemon_state=None):
        errors = validate_proxy_config(proxy_config)
        if errors:
            msg = "Proxy configuration invalid:\n  - " + "\n  - ".join(errors)
            raise ValueError(msg)

        self._config = proxy_config
        self._daemon_state = daemon_state
        self._httpd = None
        self._thread = None
        self._port = proxy_config.get("listen_port", DEFAULT_PORT)
        self._scanner = ProxyScanner(daemon_state=daemon_state)

    def start(self):
        """Start the proxy HTTP server in a background thread."""
        ProxyRequestHandler.proxy_config = self._config
        ProxyRequestHandler.daemon_state = self._daemon_state
        ProxyRequestHandler.scanner = self._scanner

        try:
            self._httpd = _ThreadingHTTPServer(
                ("127.0.0.1", self._port), ProxyRequestHandler
            )
        except OSError as e:
            logger.error(f"Failed to bind proxy to port {self._port}: {e}")
            raise

        actual_port = self._httpd.server_address[1]
        self._port = actual_port

        if self._daemon_state:
            self._daemon_state.set_proxy_port(actual_port)

        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            daemon=True,
            name="proxy-server",
        )
        self._thread.start()
        logger.info(f"Proxy server started on 127.0.0.1:{actual_port}")

    def stop(self):
        """Stop the proxy server."""
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        logger.info("Proxy server stopped")

    @property
    def is_running(self):
        return self._httpd is not None and self._thread is not None and self._thread.is_alive()

    @property
    def port(self):
        return self._port
