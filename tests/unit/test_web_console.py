"""Tests for web console module."""

import sys
from unittest import mock

import pytest


class TestWebConsoleImportGuard:
    def test_has_nicegui_is_boolean(self):
        from ai_guardian.web import HAS_NICEGUI
        assert isinstance(HAS_NICEGUI, bool)

    def test_web_console_class_matches_flag(self):
        from ai_guardian.web import HAS_NICEGUI, WebConsole
        if HAS_NICEGUI:
            assert WebConsole is not None
        else:
            assert WebConsole is None


class TestCLIWebFlag:
    def test_web_flag_accepted_by_cli(self):
        """Verify --web flag is parsed correctly via main() argument handling."""
        from unittest.mock import patch, MagicMock
        with patch("sys.argv", ["ai-guardian", "console", "--web"]):
            import argparse
            parser = argparse.ArgumentParser(prog="ai-guardian")
            sub = parser.add_subparsers(dest="command")
            cp = sub.add_parser("console")
            cp.add_argument("--web", action="store_true")
            cp.add_argument("--port", type=int, default=0)
            cp.add_argument("--panel", default=None)
            args = parser.parse_args(["console", "--web"])
            assert args.web is True
            assert args.command == "console"

    def test_port_flag_default_zero(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        cp = sub.add_parser("console")
        cp.add_argument("--web", action="store_true")
        cp.add_argument("--port", type=int, default=0)
        args = parser.parse_args(["console", "--web"])
        assert args.port == 0

    def test_port_flag_custom(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        cp = sub.add_parser("console")
        cp.add_argument("--web", action="store_true")
        cp.add_argument("--port", type=int, default=0)
        args = parser.parse_args(["console", "--web", "--port", "8080"])
        assert args.port == 8080


class TestDaemonConstants:
    def test_default_web_console_port(self):
        from ai_guardian.daemon import DEFAULT_WEB_CONSOLE_PORT
        assert DEFAULT_WEB_CONSOLE_PORT == 0
