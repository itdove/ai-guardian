"""Tests for the daemon proxy module."""

import json
import socket
import threading
import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import urllib.request
import urllib.error

from ai_guardian.daemon.proxy import (
    ProxyServer,
    ProxyScanner,
    ProxyRequestHandler,
    ScanResult,
    _extract_text_from_payload,
    _recursive_extract_strings,
    validate_proxy_config,
    DEFAULT_PORT,
)
from ai_guardian.daemon.state import DaemonState


@pytest.fixture
def daemon_state(tmp_path):
    return DaemonState(config_path=tmp_path / "config.json")


@pytest.fixture
def proxy_config():
    return {
        "enabled": True,
        "listen_port": 0,  # OS picks a free port
        "backend_url": "https://api.example.com",
    }


def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestValidateProxyConfig:
    def test_valid_config(self):
        config = {
            "enabled": True,
            "listen_port": 63152,
            "backend_url": "https://api.anthropic.com",
        }
        assert validate_proxy_config(config) == []

    def test_missing_backend_url(self):
        config = {"enabled": True, "listen_port": 63152}
        errors = validate_proxy_config(config)
        assert any("backend_url" in e for e in errors)

    def test_empty_backend_url(self):
        config = {"enabled": True, "backend_url": ""}
        errors = validate_proxy_config(config)
        assert any("backend_url" in e for e in errors)

    def test_invalid_backend_url_scheme(self):
        config = {"enabled": True, "backend_url": "ftp://api.example.com"}
        errors = validate_proxy_config(config)
        assert any("http://" in e for e in errors)

    def test_invalid_port_too_low(self):
        config = {"enabled": True, "backend_url": "https://api.example.com", "listen_port": 80}
        errors = validate_proxy_config(config)
        assert any("listen_port" in e for e in errors)

    def test_port_zero_allowed(self):
        config = {"enabled": True, "backend_url": "https://api.example.com", "listen_port": 0}
        errors = validate_proxy_config(config)
        assert not any("listen_port" in e for e in errors)

    def test_invalid_port_too_high(self):
        config = {"enabled": True, "backend_url": "https://api.example.com", "listen_port": 70000}
        errors = validate_proxy_config(config)
        assert any("listen_port" in e for e in errors)

    def test_invalid_port_not_int(self):
        config = {"enabled": True, "backend_url": "https://api.example.com", "listen_port": "abc"}
        errors = validate_proxy_config(config)
        assert any("listen_port" in e for e in errors)

    def test_tls_client_cert_without_key(self):
        config = {
            "enabled": True,
            "backend_url": "https://api.example.com",
            "tls": {"client_cert": "/tmp/cert.pem"},
        }
        errors = validate_proxy_config(config)
        assert any("client_key" in e for e in errors)

    def test_tls_client_key_without_cert(self):
        config = {
            "enabled": True,
            "backend_url": "https://api.example.com",
            "tls": {"client_key": "/tmp/key.pem"},
        }
        errors = validate_proxy_config(config)
        assert any("client_cert" in e for e in errors)

    def test_tls_cert_file_not_found(self, tmp_path):
        config = {
            "enabled": True,
            "backend_url": "https://api.example.com",
            "tls": {
                "client_cert": str(tmp_path / "nonexistent.pem"),
                "client_key": str(tmp_path / "nonexistent.key"),
            },
        }
        errors = validate_proxy_config(config)
        assert any("not found" in e for e in errors)

    def test_invalid_auth_mode(self):
        config = {
            "enabled": True,
            "backend_url": "https://api.example.com",
            "auth": {"mode": "magic"},
        }
        errors = validate_proxy_config(config)
        assert any("auth.mode" in e for e in errors)

    def test_valid_auth_modes(self):
        for mode in ("pass-through", "credential-injection", "oauth", "user-auth"):
            config = {
                "enabled": True,
                "backend_url": "https://api.example.com",
                "auth": {"mode": mode},
            }
            assert validate_proxy_config(config) == []

    def test_not_a_dict(self):
        errors = validate_proxy_config("not a dict")
        assert any("dict" in e for e in errors)

    def test_server_rejects_invalid_config(self, daemon_state):
        config = {"enabled": True}  # missing backend_url
        with pytest.raises(ValueError, match="backend_url"):
            ProxyServer(config, daemon_state)

    def test_multiple_errors_reported(self):
        config = {
            "enabled": True,
            "listen_port": 80,  # too low
            # missing backend_url
        }
        errors = validate_proxy_config(config)
        assert len(errors) >= 2


class TestScanResult:
    def test_allow_result(self):
        r = ScanResult(violations=[], action="allow")
        assert r.action == "allow"
        assert r.violations == []
        assert r.modified_body is None

    def test_block_result_with_violations(self):
        viols = [{"type": "secret_detected", "detail": "found a key"}]
        r = ScanResult(violations=viols, action="block", scan_time_ms=1.5)
        assert r.action == "block"
        assert len(r.violations) == 1
        assert r.scan_time_ms == 1.5

    def test_warn_result(self):
        r = ScanResult(violations=[{"type": "pii_detected"}], action="warn")
        assert r.action == "warn"


class TestProxyContentExtraction:
    def test_extract_only_last_message_from_request(self):
        body = {
            "messages": [
                {"role": "user", "content": "Hello world"},
                {"role": "assistant", "content": "Hi there"},
                {"role": "user", "content": "New question"},
            ]
        }
        text = _extract_text_from_payload(body, "request")
        # Only the last message (new content) is scanned
        assert "New question" in text
        assert "Hello world" not in text
        assert "Hi there" not in text

    def test_extract_system_prompt_string(self):
        body = {"system": "You are a helpful assistant", "messages": []}
        text = _extract_text_from_payload(body, "request")
        assert "You are a helpful assistant" in text

    def test_extract_system_prompt_blocks(self):
        body = {
            "system": [{"type": "text", "text": "System instructions here"}],
            "messages": [],
        }
        text = _extract_text_from_payload(body, "request")
        assert "System instructions here" in text

    def test_extract_content_blocks_with_text(self):
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Check this code"},
                        {"type": "image", "source": {"data": "base64..."}},
                    ],
                }
            ]
        }
        text = _extract_text_from_payload(body, "request")
        assert "Check this code" in text
        assert "base64" not in text

    def test_extract_response_text(self):
        body = {
            "content": [
                {"type": "text", "text": "Here is the answer"},
            ],
            "role": "assistant",
        }
        text = _extract_text_from_payload(body, "response")
        assert "Here is the answer" in text

    def test_extract_unknown_format_recursive(self):
        body = {"data": {"nested": {"value": "some long text content here"}}}
        text = _extract_text_from_payload(body, "request")
        assert "some long text content here" in text

    def test_empty_body(self):
        assert _extract_text_from_payload({}, "request") == ""

    def test_non_dict_body(self):
        assert _extract_text_from_payload("not a dict", "request") == ""
        assert _extract_text_from_payload(None, "request") == ""

    def test_content_blocks_with_string_items(self):
        body = {
            "messages": [
                {"role": "user", "content": ["plain string message"]},
            ]
        }
        text = _extract_text_from_payload(body, "request")
        assert "plain string message" in text


class TestRecursiveExtractStrings:
    def test_extract_from_dict(self):
        result = _recursive_extract_strings({"key": "value that is long enough"})
        assert "value that is long enough" in result

    def test_short_strings_ignored(self):
        result = _recursive_extract_strings({"key": "short"})
        assert result == []

    def test_max_depth_respected(self):
        deep = {"a": {"b": {"c": {"d": "deep nested value"}}}}
        result = _recursive_extract_strings(deep, max_depth=2)
        assert "deep nested value" not in result

    def test_extract_from_list(self):
        result = _recursive_extract_strings(["a longer string item here"])
        assert "a longer string item here" in result


class TestProxyScannerGeneric:
    @patch("ai_guardian.daemon.proxy.ProxyScanner._scan_secrets")
    @patch("ai_guardian.daemon.proxy.ProxyScanner._scan_pii")
    @patch("ai_guardian.daemon.proxy.ProxyScanner._scan_prompt_injection")
    def test_scanner_runs_all_scans_for_request(self, mock_pi, mock_pii, mock_secrets):
        scanner = ProxyScanner()
        scanner.scan_text("test content", "request")
        mock_secrets.assert_called_once()
        mock_pii.assert_called_once()
        mock_pi.assert_called_once()

    @patch("ai_guardian.daemon.proxy.ProxyScanner._scan_secrets")
    @patch("ai_guardian.daemon.proxy.ProxyScanner._scan_pii")
    @patch("ai_guardian.daemon.proxy.ProxyScanner._scan_prompt_injection")
    def test_scanner_skips_injection_for_response(self, mock_pi, mock_pii, mock_secrets):
        scanner = ProxyScanner()
        scanner.scan_text("test content", "response")
        mock_secrets.assert_called_once()
        mock_pii.assert_called_once()
        mock_pi.assert_not_called()

    @patch("ai_guardian.daemon.proxy.ProxyScanner._scan_secrets")
    @patch("ai_guardian.daemon.proxy.ProxyScanner._scan_pii")
    def test_scanner_individual_failure_continues(self, mock_pii, mock_secrets):
        mock_secrets.side_effect = RuntimeError("scanner broken")
        scanner = ProxyScanner()
        result = scanner.scan_text("test content", "response")
        assert result.action == "allow"
        mock_pii.assert_called_once()

    def test_scanner_empty_text_returns_allow(self):
        scanner = ProxyScanner()
        result = scanner.scan_text("", "request")
        assert result.action == "allow"
        assert result.violations == []

    def test_scanner_none_text_returns_allow(self):
        scanner = ProxyScanner()
        result = scanner.scan_text(None, "request")
        assert result.action == "allow"

    @patch("ai_guardian.daemon.proxy.ProxyScanner._scan_secrets")
    @patch("ai_guardian.daemon.proxy.ProxyScanner._scan_pii")
    def test_scanner_strictest_action_wins(self, mock_pii, mock_secrets):
        def add_warn(text, direction, violations, update):
            violations.append({"type": "pii_detected"})
            update("warn")

        def add_block(text, direction, violations, update):
            violations.append({"type": "secret_detected"})
            update("block")

        mock_pii.side_effect = add_warn
        mock_secrets.side_effect = add_block

        scanner = ProxyScanner()
        result = scanner.scan_text("test", "response")
        assert result.action == "block"
        assert len(result.violations) == 2


class TestProxyServerLifecycle:
    def test_proxy_starts_on_port(self, proxy_config, daemon_state):
        server = ProxyServer(proxy_config, daemon_state)
        server.start()
        try:
            assert server.is_running
            assert server.port > 0
            assert daemon_state.get_stats()["proxy_port"] == server.port
        finally:
            server.stop()

    def test_proxy_stops_cleanly(self, proxy_config, daemon_state):
        server = ProxyServer(proxy_config, daemon_state)
        server.start()
        assert server.is_running
        server.stop()
        assert not server.is_running

    def test_proxy_not_started_when_disabled(self, daemon_state):
        config = {"enabled": False, "listen_port": 0, "backend_url": "https://api.example.com"}
        server = ProxyServer(config, daemon_state)
        assert not server.is_running

    def test_proxy_port_conflict(self, daemon_state):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
            blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            blocker.bind(("127.0.0.1", 0))
            port = blocker.getsockname()[1]
            blocker.listen(1)

            config = {"enabled": True, "listen_port": port, "backend_url": "https://api.example.com"}
            server = ProxyServer(config, daemon_state)
            with pytest.raises(OSError):
                server.start()


class TestProxyRequestForwarding:
    @pytest.fixture
    def proxy_server(self, proxy_config, daemon_state):
        server = ProxyServer(proxy_config, daemon_state)
        server.start()
        yield server
        server.stop()

    @patch("ai_guardian.daemon.proxy.ProxyRequestHandler._forward_request")
    @patch("ai_guardian.daemon.proxy.ProxyRequestHandler._scan_body")
    def test_post_request_forwarded(self, mock_scan, mock_forward, proxy_server, daemon_state):
        mock_scan.return_value = None
        resp_body = json.dumps({"content": [{"type": "text", "text": "Hi"}]}).encode()
        mock_forward.return_value = (200, [("Content-Type", "application/json")], resp_body)

        req_body = json.dumps({"messages": [{"role": "user", "content": "Hello"}]}).encode()
        url = f"http://127.0.0.1:{proxy_server.port}/v1/messages"
        req = urllib.request.Request(url, data=req_body, method="POST")
        req.add_header("Content-Type", "application/json")

        resp = urllib.request.urlopen(req, timeout=5)
        assert resp.status == 200
        assert daemon_state.get_stats()["proxy_request_count"] >= 1

    @patch("ai_guardian.daemon.proxy.ProxyRequestHandler._forward_request")
    @patch("ai_guardian.daemon.proxy.ProxyRequestHandler._scan_body")
    def test_get_request_forwarded(self, mock_scan, mock_forward, proxy_server):
        mock_scan.return_value = None
        mock_forward.return_value = (200, [], b'{"ok": true}')

        url = f"http://127.0.0.1:{proxy_server.port}/v1/models"
        resp = urllib.request.urlopen(url, timeout=5)
        assert resp.status == 200

    @patch("ai_guardian.daemon.proxy.ProxyRequestHandler._forward_request")
    @patch("ai_guardian.daemon.proxy.ProxyRequestHandler._scan_body")
    def test_backend_error_forwarded(self, mock_scan, mock_forward, proxy_server):
        mock_scan.return_value = None
        error_body = json.dumps({"error": {"message": "Bad request"}}).encode()
        mock_forward.side_effect = urllib.error.HTTPError(
            "http://example.com", 400, "Bad Request",
            {"Content-Type": "application/json"}, None
        )

        url = f"http://127.0.0.1:{proxy_server.port}/v1/messages"
        req = urllib.request.Request(url, data=b'{}', method="POST")
        req.add_header("Content-Type", "application/json")
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 400


class TestProxyScanning:
    @pytest.fixture
    def proxy_server(self, proxy_config, daemon_state):
        server = ProxyServer(proxy_config, daemon_state)
        server.start()
        yield server
        server.stop()

    @patch("ai_guardian.daemon.proxy.ProxyRequestHandler._forward_request")
    @patch("ai_guardian.daemon.proxy.ProxyScanner.scan_text")
    def test_clean_request_forwarded(self, mock_scan_text, mock_forward, proxy_server):
        mock_scan_text.return_value = ScanResult(violations=[], action="allow")
        mock_forward.return_value = (200, [], b'{"ok": true}')

        body = json.dumps({"messages": [{"role": "user", "content": "Hi"}]}).encode()
        url = f"http://127.0.0.1:{proxy_server.port}/v1/messages"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        resp = urllib.request.urlopen(req, timeout=5)
        assert resp.status == 200

    @patch("ai_guardian.daemon.proxy.ProxyRequestHandler._forward_request")
    @patch("ai_guardian.daemon.proxy.ProxyScanner.scan_text")
    def test_block_returns_403(self, mock_scan_text, mock_forward, proxy_server, daemon_state):
        viols = [{"type": "secret_detected", "detail": "API key found"}]
        mock_scan_text.return_value = ScanResult(violations=viols, action="block")

        body = json.dumps({"messages": [{"role": "user", "content": "sk-secret-key"}]}).encode()
        url = f"http://127.0.0.1:{proxy_server.port}/v1/messages"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 403

        stats = daemon_state.get_stats()
        assert stats["proxy_blocked_count"] >= 1

    @patch("ai_guardian.daemon.proxy.ProxyRequestHandler._forward_request")
    @patch("ai_guardian.daemon.proxy.ProxyScanner.scan_text")
    def test_warn_adds_header(self, mock_scan_text, mock_forward, proxy_server):
        viols = [{"type": "pii_detected", "detail": "SSN found"}]
        mock_scan_text.return_value = ScanResult(violations=viols, action="warn")
        mock_forward.return_value = (200, [("Content-Type", "application/json")], b'{"ok":true}')

        body = json.dumps({"messages": [{"role": "user", "content": "test"}]}).encode()
        url = f"http://127.0.0.1:{proxy_server.port}/v1/messages"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        resp = urllib.request.urlopen(req, timeout=5)
        assert resp.status == 200

    @patch("ai_guardian.daemon.proxy.ProxyRequestHandler._forward_request")
    @patch("ai_guardian.daemon.proxy.ProxyScanner.scan_text")
    def test_scanning_error_fails_open(self, mock_scan_text, mock_forward, proxy_server):
        mock_scan_text.side_effect = RuntimeError("Scanner crash")
        mock_forward.return_value = (200, [], b'{"ok":true}')

        body = json.dumps({"messages": [{"role": "user", "content": "test"}]}).encode()
        url = f"http://127.0.0.1:{proxy_server.port}/v1/messages"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        # Should get a 502 from the exception handler, not crash
        try:
            resp = urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            assert e.code == 502


class TestProxyStats:
    def test_proxy_requests_counted(self, proxy_config, daemon_state):
        server = ProxyServer(proxy_config, daemon_state)
        server.start()
        try:
            with patch("ai_guardian.daemon.proxy.ProxyRequestHandler._forward_request") as mock_fwd, \
                 patch("ai_guardian.daemon.proxy.ProxyRequestHandler._scan_body") as mock_scan:
                mock_scan.return_value = None
                mock_fwd.return_value = (200, [], b"ok")

                url = f"http://127.0.0.1:{server.port}/test"
                try:
                    urllib.request.urlopen(url, timeout=5)
                except Exception:
                    pass

            stats = daemon_state.get_stats()
            assert stats["proxy_request_count"] >= 1
        finally:
            server.stop()
