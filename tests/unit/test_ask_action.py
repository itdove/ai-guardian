"""Tests for the ask action mode (Issue #1115).

Covers: parse_ask_action(), pattern editor validation, config writer,
ask dialog headless fallback, and hook_processing integration.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from ai_guardian.constants import ActionMode, parse_ask_action


class TestParseAskAction:
    """Tests for parse_ask_action() compound syntax parsing."""

    def test_plain_ask(self):
        primary, fallback = parse_ask_action("ask")
        assert primary == ActionMode.ASK
        assert fallback == ActionMode.BLOCK

    def test_ask_with_block_fallback(self):
        primary, fallback = parse_ask_action("ask:block")
        assert primary == ActionMode.ASK
        assert fallback == ActionMode.BLOCK

    def test_ask_with_warn_fallback(self):
        primary, fallback = parse_ask_action("ask:warn")
        assert primary == ActionMode.ASK
        assert fallback == ActionMode.WARN

    def test_ask_with_log_only_fallback(self):
        primary, fallback = parse_ask_action("ask:log-only")
        assert primary == ActionMode.ASK
        assert fallback == ActionMode.LOG_ONLY

    def test_ask_with_invalid_fallback(self):
        primary, fallback = parse_ask_action("ask:invalid")
        assert primary == ActionMode.ASK
        assert fallback == ActionMode.BLOCK

    def test_non_ask_action_block(self):
        primary, fallback = parse_ask_action("block")
        assert primary == "block"
        assert fallback == "block"

    def test_non_ask_action_warn(self):
        primary, fallback = parse_ask_action("warn")
        assert primary == "warn"
        assert fallback == "warn"

    def test_non_ask_action_log_only(self):
        primary, fallback = parse_ask_action("log-only")
        assert primary == "log-only"
        assert fallback == "log-only"

    def test_empty_string(self):
        primary, fallback = parse_ask_action("")
        assert primary == ActionMode.BLOCK
        assert fallback == ActionMode.BLOCK

    def test_none(self):
        primary, fallback = parse_ask_action(None)
        assert primary == ActionMode.BLOCK
        assert fallback == ActionMode.BLOCK

    def test_whitespace(self):
        primary, fallback = parse_ask_action("  ask:warn  ")
        assert primary == ActionMode.ASK
        assert fallback == ActionMode.WARN


class TestActionModeEnum:
    """Tests for ASK value in ActionMode enum."""

    def test_ask_value(self):
        assert ActionMode.ASK == "ask"
        assert ActionMode.ASK.value == "ask"

    def test_ask_in_enum(self):
        assert "ask" in [m.value for m in ActionMode]


class TestPatternEditor:
    """Tests for pattern_editor.py validation and conversion."""

    def test_validate_regex_pattern_valid(self):
        from ai_guardian.tui.pattern_editor import validate_pattern
        valid, msg = validate_pattern(r"CARBONITE_IMAGE\s*=", "regex", "CARBONITE_IMAGE=quay.io/foo")
        assert valid is True

    def test_validate_regex_pattern_no_match(self):
        from ai_guardian.tui.pattern_editor import validate_pattern
        valid, msg = validate_pattern(r"DOES_NOT_EXIST", "regex", "CARBONITE_IMAGE=quay.io/foo")
        assert valid is False
        assert "does not match" in msg.lower()

    def test_validate_empty_pattern(self):
        from ai_guardian.tui.pattern_editor import validate_pattern
        valid, msg = validate_pattern("", "regex", "test")
        assert valid is False

    def test_validate_dangerous_pattern(self):
        from ai_guardian.tui.pattern_editor import validate_pattern
        valid, msg = validate_pattern(".*", "regex", "anything")
        assert valid is False
        assert "too broad" in msg.lower()

    def test_validate_string_pattern(self):
        from ai_guardian.tui.pattern_editor import validate_pattern
        valid, msg = validate_pattern("CARBONITE_IMAGE=", "string", "CARBONITE_IMAGE=quay.io/foo")
        assert valid is True

    def test_validate_glob_pattern(self):
        from ai_guardian.tui.pattern_editor import validate_pattern
        valid, msg = validate_pattern("CARBONITE_IMAGE*", "glob", "CARBONITE_IMAGE=quay.io/foo")
        assert valid is True

    def test_convert_to_regex_string(self):
        from ai_guardian.tui.pattern_editor import convert_to_regex
        result = convert_to_regex("hello.world", "string")
        assert result == r"hello\.world"

    def test_convert_to_regex_glob(self):
        from ai_guardian.tui.pattern_editor import convert_to_regex
        import re
        result = convert_to_regex("CARB*IMAGE", "glob")
        assert re.match(result, "CARBONITE_IMAGE")

    def test_convert_to_regex_passthrough(self):
        from ai_guardian.tui.pattern_editor import convert_to_regex
        result = convert_to_regex(r"CARB\w+IMAGE", "regex")
        assert result == r"CARB\w+IMAGE"

    def test_generate_config_preview(self):
        from ai_guardian.tui.pattern_editor import generate_config_preview
        result = generate_config_preview(r"CARB\w+", "secret_scanning")
        parsed = json.loads(result)
        assert "secret_scanning" in parsed
        assert r"CARB\w+" in parsed["secret_scanning"]["allowlist_patterns"]

    def test_suggest_pattern(self):
        from ai_guardian.tui.pattern_editor import suggest_pattern
        result = suggest_pattern("hello.world")
        assert result == r"hello\.world"


class TestConfigWriter:
    """Tests for config_writer.py safe config file writing."""

    def test_add_pattern_to_empty_config(self):
        from ai_guardian.config_writer import add_allowlist_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            result = add_allowlist_pattern(
                "secret_scanning", r"CARB\w+", config_path=config_path
            )
            assert result is True
            with open(config_path) as f:
                config = json.load(f)
            assert r"CARB\w+" in config["secret_scanning"]["allowlist_patterns"]

    def test_add_pattern_to_existing_config(self):
        from ai_guardian.config_writer import add_allowlist_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({
                "secret_scanning": {"enabled": True, "allowlist_patterns": ["existing"]}
            }))
            result = add_allowlist_pattern(
                "secret_scanning", r"new_pattern", config_path=config_path
            )
            assert result is True
            with open(config_path) as f:
                config = json.load(f)
            assert "existing" in config["secret_scanning"]["allowlist_patterns"]
            assert "new_pattern" in config["secret_scanning"]["allowlist_patterns"]

    def test_add_duplicate_pattern(self):
        from ai_guardian.config_writer import add_allowlist_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({
                "secret_scanning": {"allowlist_patterns": ["existing"]}
            }))
            result = add_allowlist_pattern(
                "secret_scanning", "existing", config_path=config_path
            )
            assert result is True
            with open(config_path) as f:
                config = json.load(f)
            assert config["secret_scanning"]["allowlist_patterns"].count("existing") == 1

    def test_add_pattern_with_expiration(self):
        from ai_guardian.config_writer import add_allowlist_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            result = add_allowlist_pattern(
                "prompt_injection", r"test\w+",
                valid_until="2027-01-01T00:00:00Z",
                config_path=config_path,
            )
            assert result is True
            with open(config_path) as f:
                config = json.load(f)
            entry = config["prompt_injection"]["allowlist_patterns"][0]
            assert isinstance(entry, dict)
            assert entry["pattern"] == r"test\w+"
            assert entry["valid_until"] == "2027-01-01T00:00:00Z"

    def test_reject_dangerous_pattern(self):
        from ai_guardian.config_writer import add_allowlist_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            result = add_allowlist_pattern(
                "secret_scanning", ".*", config_path=config_path
            )
            assert result is False

    def test_reject_empty_inputs(self):
        from ai_guardian.config_writer import add_allowlist_pattern
        assert add_allowlist_pattern("", "pattern") is False
        assert add_allowlist_pattern("section", "") is False

    def test_new_section_created(self):
        from ai_guardian.config_writer import add_allowlist_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text("{}")
            result = add_allowlist_pattern(
                "prompt_injection", r"test\w+", config_path=config_path
            )
            assert result is True
            with open(config_path) as f:
                config = json.load(f)
            assert "prompt_injection" in config
            assert r"test\w+" in config["prompt_injection"]["allowlist_patterns"]


class TestAskDialogHeadlessFallback:
    """Tests for headless fallback behavior."""

    def test_fallback_block(self):
        from ai_guardian.tui.ask_dialog import _map_fallback_to_decision, AskDecision
        assert _map_fallback_to_decision("block") == AskDecision.BLOCK

    def test_fallback_warn(self):
        from ai_guardian.tui.ask_dialog import _map_fallback_to_decision, AskDecision
        assert _map_fallback_to_decision("warn") == AskDecision.ALLOW_ONCE

    def test_fallback_log_only(self):
        from ai_guardian.tui.ask_dialog import _map_fallback_to_decision, AskDecision
        assert _map_fallback_to_decision("log-only") == AskDecision.ALLOW_ONCE

    def test_fallback_unknown(self):
        from ai_guardian.tui.ask_dialog import _map_fallback_to_decision, AskDecision
        assert _map_fallback_to_decision("unknown") == AskDecision.BLOCK

    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    def test_show_ask_dialog_headless_block(self, _mock_sub):
        from ai_guardian.tui.ask_dialog import show_ask_dialog, AskViolationInfo, AskDecision
        violation = AskViolationInfo(
            violation_type="secret_detected",
            summary="Test secret",
            matched_text="FAKE_TOKEN=abc123",
            config_section="secret_scanning",
        )
        result = show_ask_dialog(violation, fallback_action="block")
        assert result.decision == AskDecision.BLOCK

    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    def test_show_ask_dialog_headless_warn(self, _mock_sub):
        from ai_guardian.tui.ask_dialog import show_ask_dialog, AskViolationInfo, AskDecision
        violation = AskViolationInfo(
            violation_type="secret_detected",
            summary="Test secret",
            matched_text="FAKE_TOKEN=abc123",
            config_section="secret_scanning",
        )
        result = show_ask_dialog(violation, fallback_action="warn")
        assert result.decision == AskDecision.ALLOW_ONCE


class TestHandleAskMode:
    """Tests for _handle_ask_mode() in hook_processing."""

    def test_non_ask_action_returns_none(self):
        from ai_guardian.hook_processing import _handle_ask_mode
        result = _handle_ask_mode(
            "block", "secret_detected", "text", "secret_scanning", "error"
        )
        assert result is None

    def test_non_ask_warn_returns_none(self):
        from ai_guardian.hook_processing import _handle_ask_mode
        result = _handle_ask_mode(
            "warn", "secret_detected", "text", "secret_scanning", "error"
        )
        assert result is None

    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    def test_ask_headless_block_fallback(self, _mock_sub):
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskDecision
        result = _handle_ask_mode(
            "ask", "secret_detected", "FAKE_TOKEN", "secret_scanning", "error"
        )
        assert result is not None
        assert result.decision == AskDecision.BLOCK

    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    def test_ask_warn_headless_fallback(self, _mock_sub):
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskDecision
        result = _handle_ask_mode(
                "ask:warn", "secret_detected", "FAKE_TOKEN", "secret_scanning", "error"
            )
        assert result is not None
        assert result.decision == AskDecision.ALLOW_ONCE

    @patch("ai_guardian.tui.ask_dialog.show_ask_dialog")
    def test_ask_allow_always_writes_pattern(self, mock_dialog):
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskResult, AskDecision
        mock_dialog.return_value = AskResult(
            decision=AskDecision.ALLOW_ALWAYS,
            allowlist_pattern=r"FAKE\w+"
        )
        with patch("ai_guardian.config_writer.add_allowlist_pattern") as mock_write:
            mock_write.return_value = True
            result = _handle_ask_mode(
                "ask", "secret_detected", "FAKE_TOKEN", "secret_scanning", "error"
            )
        assert result.decision == AskDecision.ALLOW_ALWAYS
        mock_write.assert_called_once_with("secret_scanning", r"FAKE\w+")
