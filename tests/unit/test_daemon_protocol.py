"""Tests for daemon wire protocol."""

import json
import socket
import struct
import threading

import pytest

from ai_guardian.daemon.protocol import (
    HEADER_SIZE,
    MAX_MESSAGE_SIZE,
    PROTOCOL_VERSION,
    decode_message,
    encode_message,
    make_hook_request,
    make_ping,
    make_pong,
    make_reload_config,
    make_response,
    make_shutdown,
    make_status_request,
)


class TestEncodeMessage:
    def test_encode_simple_dict(self):
        data = {"type": "ping"}
        result = encode_message(data)
        assert len(result) > HEADER_SIZE
        length = struct.unpack("!I", result[:HEADER_SIZE])[0]
        payload = result[HEADER_SIZE:]
        assert len(payload) == length
        assert json.loads(payload) == data

    def test_encode_nested_dict(self):
        data = {"type": "hook", "data": {"tool_name": "Bash", "input": "ls"}}
        result = encode_message(data)
        length = struct.unpack("!I", result[:HEADER_SIZE])[0]
        payload = result[HEADER_SIZE:]
        assert json.loads(payload) == data

    def test_encode_empty_dict(self):
        data = {}
        result = encode_message(data)
        assert len(result) > HEADER_SIZE

    def test_encode_rejects_oversized_message(self):
        data = {"data": "x" * (MAX_MESSAGE_SIZE + 1)}
        with pytest.raises(ValueError, match="too large"):
            encode_message(data)


class TestDecodeMessage:
    def _make_socket_pair(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", port))
        peer, _ = server.accept()
        server.close()
        return client, peer

    def test_roundtrip(self):
        client, peer = self._make_socket_pair()
        try:
            data = {"type": "pong", "version": 1}
            encoded = encode_message(data)
            client.sendall(encoded)
            result = decode_message(peer, timeout=2.0)
            assert result == data
        finally:
            client.close()
            peer.close()

    def test_roundtrip_large_payload(self):
        client, peer = self._make_socket_pair()
        try:
            data = {"data": "x" * 100000}
            client.sendall(encode_message(data))
            result = decode_message(peer, timeout=2.0)
            assert result == data
        finally:
            client.close()
            peer.close()

    def test_decode_connection_closed(self):
        client, peer = self._make_socket_pair()
        client.close()
        with pytest.raises(ConnectionError):
            decode_message(peer, timeout=1.0)
        peer.close()

    def test_decode_oversized_header(self):
        client, peer = self._make_socket_pair()
        try:
            header = struct.pack("!I", MAX_MESSAGE_SIZE + 1)
            client.sendall(header)
            with pytest.raises(ValueError, match="too large"):
                decode_message(peer, timeout=1.0)
        finally:
            client.close()
            peer.close()

    def test_decode_empty_message(self):
        client, peer = self._make_socket_pair()
        try:
            header = struct.pack("!I", 0)
            client.sendall(header)
            with pytest.raises(ValueError, match="Empty"):
                decode_message(peer, timeout=1.0)
        finally:
            client.close()
            peer.close()

    def test_decode_timeout(self):
        client, peer = self._make_socket_pair()
        try:
            with pytest.raises((socket.timeout, OSError)):
                decode_message(peer, timeout=0.1)
        finally:
            client.close()
            peer.close()


class TestMessageFactories:
    def test_make_hook_request(self):
        data = {"tool_name": "Bash"}
        msg = make_hook_request(data)
        assert msg["version"] == PROTOCOL_VERSION
        assert msg["type"] == "hook"
        assert msg["data"] == data

    def test_make_response(self):
        data = {"output": None, "exit_code": 0}
        msg = make_response(data)
        assert msg["version"] == PROTOCOL_VERSION
        assert msg["type"] == "response"
        assert msg["data"] == data

    def test_make_ping(self):
        msg = make_ping()
        assert msg["type"] == "ping"
        assert msg["version"] == PROTOCOL_VERSION

    def test_make_pong(self):
        msg = make_pong()
        assert msg["type"] == "pong"

    def test_make_shutdown(self):
        msg = make_shutdown()
        assert msg["type"] == "shutdown"

    def test_make_status_request(self):
        msg = make_status_request()
        assert msg["type"] == "status"

    def test_make_reload_config(self):
        msg = make_reload_config()
        assert msg["type"] == "reload_config"
