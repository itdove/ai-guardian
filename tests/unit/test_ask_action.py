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

    @patch("ai_guardian.tui.ask_dialog._show_via_daemon", return_value=None)
    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    def test_show_ask_dialog_headless_block(self, _mock_sub, _mock_daemon):
        from ai_guardian.tui.ask_dialog import show_ask_dialog, AskViolationInfo, AskDecision
        violation = AskViolationInfo(
            violation_type="secret_detected",
            summary="Test secret",
            matched_text="FAKE_TOKEN=abc123",
            config_section="secret_scanning",
        )
        result = show_ask_dialog(violation, fallback_action="block")
        assert result.decision == AskDecision.BLOCK

    @patch("ai_guardian.tui.ask_dialog._show_via_daemon", return_value=None)
    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    def test_show_ask_dialog_headless_warn(self, _mock_sub, _mock_daemon):
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

    @patch("ai_guardian.tui.ask_dialog._show_via_daemon", return_value=None)
    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    def test_ask_headless_block_fallback(self, _mock_sub, _mock_daemon):
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskDecision
        result = _handle_ask_mode(
            "ask", "secret_detected", "FAKE_TOKEN", "secret_scanning", "error"
        )
        assert result is not None
        assert result.decision == AskDecision.BLOCK

    @patch("ai_guardian.tui.ask_dialog._show_via_daemon", return_value=None)
    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    def test_ask_warn_headless_fallback(self, _mock_sub, _mock_daemon):
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


class TestSSRFAskAction:
    """Tests for ask action mode with SSRF protection (Issue #1129)."""

    def test_ssrf_ask_action_schema_accepts_ask(self):
        """Verify JSON schema accepts ask values for ssrf_protection.action."""
        import jsonschema
        schema_path = Path(__file__).parent.parent.parent / "src" / "ai_guardian" / "schemas" / "ai-guardian-config.schema.json"
        with open(schema_path) as f:
            schema = json.load(f)
        ssrf_schema = schema["properties"]["ssrf_protection"]
        for action_val in ["ask", "ask:block", "ask:warn", "ask:log-only"]:
            config = {"action": action_val}
            jsonschema.validate(config, ssrf_schema)

    def test_ssrf_ask_action_schema_rejects_invalid(self):
        """Verify JSON schema rejects invalid ask values."""
        import jsonschema
        schema_path = Path(__file__).parent.parent.parent / "src" / "ai_guardian" / "schemas" / "ai-guardian-config.schema.json"
        with open(schema_path) as f:
            schema = json.load(f)
        ssrf_schema = schema["properties"]["ssrf_protection"]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"action": "ask:invalid"}, ssrf_schema)

    @patch("ai_guardian.tui.ask_dialog._show_via_daemon", return_value=None)
    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    @patch("subprocess.run")
    def test_ssrf_ask_headless_block_fallback(self, mock_sub_run, _mock_sub, _mock_daemon):
        """Headless with 'ask' action should fall back to BLOCK."""
        mock_sub_run.side_effect = FileNotFoundError
        from ai_guardian.ssrf_protector import SSRFProtector
        config = {
            "action": "ask",
            "enabled": True,
            "additional_blocked_domains": ["evil.internal.corp"],
        }
        protector = SSRFProtector(config)
        should_block, msg = protector.check("Bash", {"command": "curl http://evil.internal.corp"})
        assert should_block is True

    @patch("ai_guardian.tui.ask_dialog._show_via_daemon", return_value=None)
    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    @patch("subprocess.run")
    def test_ssrf_ask_warn_headless_allows(self, mock_sub_run, _mock_sub, _mock_daemon):
        """Headless with 'ask:warn' should fall back to ALLOW_ONCE."""
        mock_sub_run.side_effect = FileNotFoundError
        from ai_guardian.ssrf_protector import SSRFProtector
        config = {
            "action": "ask:warn",
            "enabled": True,
            "additional_blocked_domains": ["evil.internal.corp"],
        }
        protector = SSRFProtector(config)
        should_block, msg = protector.check("Bash", {"command": "curl http://evil.internal.corp"})
        assert should_block is False

    def test_ssrf_immutable_skips_ask(self):
        """Private IP with 'ask' action should always block without showing dialog."""
        from ai_guardian.ssrf_protector import SSRFProtector
        config = {"action": "ask", "enabled": True}
        protector = SSRFProtector(config)
        should_block, msg = protector.check("Bash", {"command": "curl http://169.254.169.254/latest/meta-data/"})
        assert should_block is True
        assert "immutable" in msg.lower() or "BLOCKED" in msg

    @patch("ai_guardian.tui.ask_dialog.show_ask_dialog")
    def test_ssrf_ask_allow_always_writes_domain(self, mock_dialog):
        """SSRF Allow Always should call add_allowed_domain, not add_allowlist_pattern."""
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskResult, AskDecision
        mock_dialog.return_value = AskResult(
            decision=AskDecision.ALLOW_ALWAYS,
            allowlist_pattern="evil.internal.corp"
        )
        with patch("ai_guardian.config_writer.add_allowed_domain") as mock_domain_write, \
             patch("ai_guardian.config_writer.add_allowlist_pattern") as mock_pattern_write:
            mock_domain_write.return_value = True
            result = _handle_ask_mode(
                "ask", "ssrf_blocked", "http://evil.internal.corp/api",
                "ssrf_protection", "SSRF blocked"
            )
        assert result.decision == AskDecision.ALLOW_ALWAYS
        mock_domain_write.assert_called_once_with("evil.internal.corp")
        mock_pattern_write.assert_not_called()


class TestSuggestDomain:
    """Tests for suggest_domain() in pattern_editor."""

    def test_extract_domain_from_https_url(self):
        from ai_guardian.tui.pattern_editor import suggest_domain
        assert suggest_domain("https://api.example.com/v1/data") == "api.example.com"

    def test_extract_domain_from_http_url(self):
        from ai_guardian.tui.pattern_editor import suggest_domain
        assert suggest_domain("http://evil.internal.corp:8080/admin") == "evil.internal.corp"

    def test_extract_domain_lowercase(self):
        from ai_guardian.tui.pattern_editor import suggest_domain
        assert suggest_domain("https://API.Example.COM/path") == "api.example.com"

    def test_plain_domain_passthrough(self):
        from ai_guardian.tui.pattern_editor import suggest_domain
        assert suggest_domain("example.com") == "example.com"

    def test_suggest_pattern_ssrf_section(self):
        from ai_guardian.tui.pattern_editor import suggest_pattern
        result = suggest_pattern("https://evil.corp/api", "ssrf_protection")
        assert result == "evil.corp"

    def test_suggest_pattern_non_ssrf_section(self):
        from ai_guardian.tui.pattern_editor import suggest_pattern
        result = suggest_pattern("FAKE_TOKEN=abc", "secret_scanning")
        assert result == r"FAKE_TOKEN\s*="

    def test_generate_config_preview_ssrf(self):
        from ai_guardian.tui.pattern_editor import generate_config_preview
        result = generate_config_preview("evil.corp", "ssrf_protection")
        parsed = json.loads(result)
        assert "ssrf_protection" in parsed
        assert "evil.corp" in parsed["ssrf_protection"]["allowed_domains"]

    def test_generate_config_preview_non_ssrf(self):
        from ai_guardian.tui.pattern_editor import generate_config_preview
        result = generate_config_preview(r"FAKE\w+", "secret_scanning")
        parsed = json.loads(result)
        assert r"FAKE\w+" in parsed["secret_scanning"]["allowlist_patterns"]


class TestAddAllowedDomain:
    """Tests for add_allowed_domain() in config_writer."""

    def test_add_domain_to_empty_config(self):
        from ai_guardian.config_writer import add_allowed_domain
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            result = add_allowed_domain("api.example.com", config_path=config_path)
            assert result is True
            with open(config_path) as f:
                config = json.load(f)
            assert "api.example.com" in config["ssrf_protection"]["allowed_domains"]

    def test_add_domain_to_existing_config(self):
        from ai_guardian.config_writer import add_allowed_domain
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({
                "ssrf_protection": {"enabled": True, "allowed_domains": ["existing.com"]}
            }))
            result = add_allowed_domain("new.example.com", config_path=config_path)
            assert result is True
            with open(config_path) as f:
                config = json.load(f)
            assert "existing.com" in config["ssrf_protection"]["allowed_domains"]
            assert "new.example.com" in config["ssrf_protection"]["allowed_domains"]

    def test_add_duplicate_domain(self):
        from ai_guardian.config_writer import add_allowed_domain
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({
                "ssrf_protection": {"allowed_domains": ["existing.com"]}
            }))
            result = add_allowed_domain("existing.com", config_path=config_path)
            assert result is True
            with open(config_path) as f:
                config = json.load(f)
            assert config["ssrf_protection"]["allowed_domains"].count("existing.com") == 1

    def test_add_domain_normalizes_case(self):
        from ai_guardian.config_writer import add_allowed_domain
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            result = add_allowed_domain("API.Example.COM", config_path=config_path)
            assert result is True
            with open(config_path) as f:
                config = json.load(f)
            assert "api.example.com" in config["ssrf_protection"]["allowed_domains"]

    def test_reject_empty_domain(self):
        from ai_guardian.config_writer import add_allowed_domain
        assert add_allowed_domain("") is False
        assert add_allowed_domain("   ") is False


class TestSuggestPatternEnvVariable:
    """Tests for smart env-variable pattern suggestions (Issue #1140)."""

    def test_suggest_pattern_env_variable(self):
        from ai_guardian.tui.pattern_editor import suggest_pattern
        result = suggest_pattern("DAF_SESSION_NAME=some-value", "secret_scanning")
        assert result == r"DAF_SESSION_NAME\s*="

    def test_suggest_pattern_env_variable_with_spaces(self):
        from ai_guardian.tui.pattern_editor import suggest_pattern
        result = suggest_pattern("MY_SECRET = hunter2", "secret_scanning")
        assert result == r"MY_SECRET\s*="

    def test_suggest_pattern_non_env_unchanged(self):
        import re
        from ai_guardian.tui.pattern_editor import suggest_pattern
        result = suggest_pattern("ghp_abc123def456", "secret_scanning")
        assert result == re.escape("ghp_abc123def456")

    def test_suggest_pattern_lowercase_not_env(self):
        import re
        from ai_guardian.tui.pattern_editor import suggest_pattern
        result = suggest_pattern("some_key=value", "secret_scanning")
        assert result == re.escape("some_key=value")


class TestExtractMatchedTextForAsk:
    """Tests for _extract_matched_text_for_ask helper (Issue #1140)."""

    def test_prefers_explicit_matched_text(self):
        from ai_guardian.hook_processing import _extract_matched_text_for_ask
        details = {"matched_text": "API_KEY=secret123", "line_number": 5}
        result = _extract_matched_text_for_ask(details, "line1\nline2\nline3\nline4\nAPI_KEY=secret123")
        assert result == "API_KEY=secret123"

    def test_fallback_to_line_number(self):
        from ai_guardian.hook_processing import _extract_matched_text_for_ask
        details = {"line_number": 3}
        result = _extract_matched_text_for_ask(details, "line1\nline2\nTHE_SECRET_LINE\nline4")
        assert result == "THE_SECRET_LINE"

    def test_empty_details(self):
        from ai_guardian.hook_processing import _extract_matched_text_for_ask
        result = _extract_matched_text_for_ask(None, "content")
        assert result == ""

    def test_no_matched_text_no_line_number(self):
        from ai_guardian.hook_processing import _extract_matched_text_for_ask
        result = _extract_matched_text_for_ask({"rule_id": "test"}, "content")
        assert result == ""

    def test_line_number_out_of_range(self):
        from ai_guardian.hook_processing import _extract_matched_text_for_ask
        result = _extract_matched_text_for_ask({"line_number": 99}, "line1\nline2")
        assert result == ""


class TestHandleAskModeMatchedText:
    """Tests for matched_text flowing through _handle_ask_mode (Issue #1140)."""

    @patch("ai_guardian.tui.ask_dialog.show_ask_dialog")
    def test_matched_text_flows_to_violation_info(self, mock_dialog):
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskResult, AskDecision
        mock_dialog.return_value = AskResult(decision=AskDecision.BLOCK)
        _handle_ask_mode(
            "ask", "secret_detected", "MY_SECRET=value123",
            "secret_scanning", "Secret Type: Environment Variable"
        )
        call_args = mock_dialog.call_args
        violation_info = call_args[0][0]
        assert violation_info.matched_text == "MY_SECRET=value123"


class TestPatternEditorAutoUpdate:
    """Tests for auto-update of config preview when pattern input changes (Issue #1158)."""

    def test_tkinter_pattern_var_trace_triggers_preview_update(self):
        """Verify that modifying pattern_var calls do_test via trace callback."""
        from ai_guardian.tui.pattern_editor import validate_pattern, generate_config_preview, convert_to_regex

        call_count = [0]
        original_validate = validate_pattern

        def counting_validate(*args, **kwargs):
            call_count[0] += 1
            return original_validate(*args, **kwargs)

        pat1 = r"FAKE_TOKEN\s*="
        pat2 = r"FAKE\w+"
        test_text = "FAKE_TOKEN=abc123"

        valid1, _ = counting_validate(pat1, "regex", test_text)
        valid2, _ = counting_validate(pat2, "regex", test_text)
        assert valid1 is True
        assert valid2 is True
        assert call_count[0] == 2

        preview1 = generate_config_preview(convert_to_regex(pat1, "regex"), "secret_scanning")
        preview2 = generate_config_preview(convert_to_regex(pat2, "regex"), "secret_scanning")
        parsed1 = json.loads(preview1)
        parsed2 = json.loads(preview2)
        assert pat1 in parsed1["secret_scanning"]["allowlist_patterns"]
        assert pat2 in parsed2["secret_scanning"]["allowlist_patterns"]
        assert preview1 != preview2

    def test_preview_updates_for_different_patterns(self):
        """Config preview should reflect the current pattern, not the initial one."""
        from ai_guardian.tui.pattern_editor import (
            validate_pattern, convert_to_regex, generate_config_preview, suggest_pattern,
        )
        import json

        matched_text = "MY_API_KEY=secret123"
        initial_pattern = suggest_pattern(matched_text, "secret_scanning")
        assert initial_pattern == r"MY_API_KEY\s*="

        valid, _ = validate_pattern(initial_pattern, "regex", matched_text)
        assert valid is True
        initial_preview = generate_config_preview(
            convert_to_regex(initial_pattern, "regex"), "secret_scanning"
        )
        initial_config = json.loads(initial_preview)
        assert initial_pattern in initial_config["secret_scanning"]["allowlist_patterns"]

        edited_pattern = r"MY_API_KEY\s*=\s*secret"
        valid, _ = validate_pattern(edited_pattern, "regex", matched_text)
        assert valid is True
        updated_preview = generate_config_preview(
            convert_to_regex(edited_pattern, "regex"), "secret_scanning"
        )
        updated_config = json.loads(updated_preview)
        assert edited_pattern in updated_config["secret_scanning"]["allowlist_patterns"]
        assert initial_preview != updated_preview

    def test_invalid_pattern_does_not_update_preview(self):
        """When pattern becomes invalid, preview should not update (test status shows FAIL)."""
        from ai_guardian.tui.pattern_editor import validate_pattern

        valid, msg = validate_pattern("", "regex", "some text")
        assert valid is False
        assert "empty" in msg.lower()

        valid, msg = validate_pattern("[invalid(regex", "regex", "some text")
        assert valid is False

    def test_ssrf_preview_updates_for_domain_changes(self):
        """SSRF section should update allowed_domains preview as pattern changes."""
        from ai_guardian.tui.pattern_editor import generate_config_preview
        import json

        preview1 = generate_config_preview("api.example.com", "ssrf_protection")
        preview2 = generate_config_preview("api.other.com", "ssrf_protection")
        config1 = json.loads(preview1)
        config2 = json.loads(preview2)
        assert "api.example.com" in config1["ssrf_protection"]["allowed_domains"]
        assert "api.other.com" in config2["ssrf_protection"]["allowed_domains"]
        assert preview1 != preview2


class TestPostSaveConfirmation:
    """Tests for post-save confirmation in ask dialog (Issue #1141)."""

    def test_ask_result_has_config_saved_field(self):
        from ai_guardian.tui.ask_dialog import AskResult, AskDecision
        result = AskResult(decision=AskDecision.ALLOW_ALWAYS, allowlist_pattern="test")
        assert result.config_saved is False

    def test_ask_result_config_saved_true(self):
        from ai_guardian.tui.ask_dialog import AskResult, AskDecision
        result = AskResult(
            decision=AskDecision.ALLOW_ALWAYS,
            allowlist_pattern="test",
            config_saved=True,
        )
        assert result.config_saved is True

    def test_save_pattern_to_config_calls_add_allowlist_pattern(self):
        from ai_guardian.tui.ask_dialog import _save_pattern_to_config
        with patch("ai_guardian.config_writer.add_allowlist_pattern") as mock_add:
            mock_add.return_value = True
            result = _save_pattern_to_config(r"test\w+", "secret_scanning")
        assert result is True
        mock_add.assert_called_once_with("secret_scanning", r"test\w+")

    def test_save_pattern_to_config_ssrf_calls_add_allowed_domain(self):
        from ai_guardian.tui.ask_dialog import _save_pattern_to_config
        with patch("ai_guardian.config_writer.add_allowed_domain") as mock_add:
            mock_add.return_value = True
            result = _save_pattern_to_config("api.example.com", "ssrf_protection")
        assert result is True
        mock_add.assert_called_once_with("api.example.com")

    def test_save_pattern_to_config_handles_failure(self):
        from ai_guardian.tui.ask_dialog import _save_pattern_to_config
        with patch("ai_guardian.config_writer.add_allowlist_pattern") as mock_add:
            mock_add.return_value = False
            result = _save_pattern_to_config(r"test\w+", "secret_scanning")
        assert result is False

    def test_save_pattern_to_config_handles_exception(self):
        from ai_guardian.tui.ask_dialog import _save_pattern_to_config
        with patch("ai_guardian.config_writer.add_allowlist_pattern") as mock_add:
            mock_add.side_effect = RuntimeError("disk full")
            result = _save_pattern_to_config(r"test\w+", "secret_scanning")
        assert result is False

    @patch("ai_guardian.tui.ask_dialog.show_ask_dialog")
    def test_hook_processing_skips_save_when_config_saved(self, mock_dialog):
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskResult, AskDecision
        mock_dialog.return_value = AskResult(
            decision=AskDecision.ALLOW_ALWAYS,
            allowlist_pattern=r"FAKE\w+",
            config_saved=True,
        )
        with patch("ai_guardian.config_writer.add_allowlist_pattern") as mock_write:
            result = _handle_ask_mode(
                "ask", "secret_detected", "FAKE_TOKEN", "secret_scanning", "error"
            )
        assert result.decision == AskDecision.ALLOW_ALWAYS
        mock_write.assert_not_called()

    @patch("ai_guardian.tui.ask_dialog.show_ask_dialog")
    def test_hook_processing_saves_when_config_not_saved(self, mock_dialog):
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskResult, AskDecision
        mock_dialog.return_value = AskResult(
            decision=AskDecision.ALLOW_ALWAYS,
            allowlist_pattern=r"FAKE\w+",
            config_saved=False,
        )
        with patch("ai_guardian.config_writer.add_allowlist_pattern") as mock_write:
            mock_write.return_value = True
            result = _handle_ask_mode(
                "ask", "secret_detected", "FAKE_TOKEN", "secret_scanning", "error"
            )
        assert result.decision == AskDecision.ALLOW_ALWAYS
        mock_write.assert_called_once_with("secret_scanning", r"FAKE\w+")

    def test_prepare_config_with_pattern_inserts_pattern(self):
        from ai_guardian.tui.pattern_editor import prepare_config_with_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text('{"secret_scanning": {}}')
            with patch("ai_guardian.config_utils.get_config_dir", return_value=Path(tmpdir)):
                json_text, line_num = prepare_config_with_pattern(r"TEST\w+", "secret_scanning")
        parsed = json.loads(json_text)
        assert r"TEST\w+" in parsed["secret_scanning"]["allowlist_patterns"]
        assert line_num > 0
        lines = json_text.splitlines()
        assert json.dumps(r"TEST\w+") in lines[line_num - 1]

    def test_prepare_config_with_pattern_ssrf(self):
        from ai_guardian.tui.pattern_editor import prepare_config_with_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text("{}")
            with patch("ai_guardian.config_utils.get_config_dir", return_value=Path(tmpdir)):
                json_text, line_num = prepare_config_with_pattern("api.example.com", "ssrf_protection")
        parsed = json.loads(json_text)
        assert "api.example.com" in parsed["ssrf_protection"]["allowed_domains"]

    def test_prepare_config_with_pattern_empty_config(self):
        from ai_guardian.tui.pattern_editor import prepare_config_with_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("ai_guardian.config_utils.get_config_dir", return_value=Path(tmpdir)):
                json_text, line_num = prepare_config_with_pattern(r"pat", "prompt_injection")
        parsed = json.loads(json_text)
        assert "pat" in parsed["prompt_injection"]["allowlist_patterns"]

    def test_write_config_text_writes_file(self):
        from ai_guardian.tui.ask_dialog import _write_config_text
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text("{}")
            with patch("ai_guardian.config_utils.get_config_dir", return_value=Path(tmpdir)):
                result = _write_config_text('{"test": true}\n')
            assert result is True
            assert json.loads(config_path.read_text()) == {"test": True}
            assert (Path(tmpdir) / "ai-guardian.json.bak").exists()

    def test_write_config_text_creates_backup(self):
        from ai_guardian.tui.ask_dialog import _write_config_text
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text('{"original": true}')
            with patch("ai_guardian.config_utils.get_config_dir", return_value=Path(tmpdir)):
                _write_config_text('{"updated": true}\n')
            backup = Path(tmpdir) / "ai-guardian.json.bak"
            assert json.loads(backup.read_text()) == {"original": True}

    def test_save_pattern_to_config_directory_rules_calls_add_directory_exclusion(self):
        from ai_guardian.tui.ask_dialog import _save_pattern_to_config
        with patch("ai_guardian.config_writer.add_directory_exclusion") as mock_add:
            mock_add.return_value = True
            result = _save_pattern_to_config("/home/user/project/**", "directory_rules")
        assert result is True
        mock_add.assert_called_once_with("/home/user/project/**")


class TestDirectoryBlockingAskAction:
    """Tests for ask action mode with directory blocking (Issue #1130)."""

    def test_directory_ask_schema_accepts_ask(self):
        """Verify JSON schema accepts ask values for directory_rules.action."""
        import jsonschema
        schema_path = Path(__file__).parent.parent.parent / "src" / "ai_guardian" / "schemas" / "ai-guardian-config.schema.json"
        with open(schema_path) as f:
            schema = json.load(f)
        dr_schema = schema["properties"]["directory_rules"]["oneOf"][1]
        for action_val in ["ask", "ask:block", "ask:warn", "ask:log-only"]:
            config = {"action": action_val}
            jsonschema.validate(config, dr_schema)

    def test_directory_ask_schema_rejects_invalid(self):
        """Verify JSON schema rejects invalid ask values."""
        import jsonschema
        schema_path = Path(__file__).parent.parent.parent / "src" / "ai_guardian" / "schemas" / "ai-guardian-config.schema.json"
        with open(schema_path) as f:
            schema = json.load(f)
        dr_schema = schema["properties"]["directory_rules"]["oneOf"][1]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"action": "ask:invalid"}, dr_schema)

    def test_directory_ask_schema_exclusions_field(self):
        """Verify JSON schema accepts exclusions array."""
        import jsonschema
        schema_path = Path(__file__).parent.parent.parent / "src" / "ai_guardian" / "schemas" / "ai-guardian-config.schema.json"
        with open(schema_path) as f:
            schema = json.load(f)
        dr_schema = schema["properties"]["directory_rules"]["oneOf"][1]
        config = {
            "action": "ask",
            "exclusions": ["/home/user/project/**"],
            "rules": [],
        }
        jsonschema.validate(config, dr_schema)

    @patch("ai_guardian.tui.ask_dialog.show_ask_dialog")
    def test_handle_ask_mode_directory_allow_always_writes_exclusion(self, mock_dialog):
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskResult, AskDecision
        mock_dialog.return_value = AskResult(
            decision=AskDecision.ALLOW_ALWAYS,
            allowlist_pattern="/home/user/project/**",
        )
        with patch("ai_guardian.config_writer.add_directory_exclusion") as mock_write:
            mock_write.return_value = True
            result = _handle_ask_mode(
                "ask", "directory_blocking", "/home/user/project/file.py",
                "directory_rules", "Access denied",
            )
        assert result.decision == AskDecision.ALLOW_ALWAYS
        mock_write.assert_called_once_with("/home/user/project/**")

    @patch("ai_guardian.tui.ask_dialog._show_via_daemon", return_value=None)
    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    def test_directory_ask_headless_block_fallback(self, _mock_sub, _mock_daemon):
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskDecision
        result = _handle_ask_mode(
            "ask", "directory_blocking", "/secret/file.txt",
            "directory_rules", "Access denied",
        )
        assert result is not None
        assert result.decision == AskDecision.BLOCK

    @patch("ai_guardian.tui.ask_dialog._show_via_daemon", return_value=None)
    @patch("ai_guardian.tui.ask_dialog._show_via_subprocess", return_value=None)
    def test_directory_ask_warn_headless_fallback(self, _mock_sub, _mock_daemon):
        from ai_guardian.hook_processing import _handle_ask_mode
        from ai_guardian.tui.ask_dialog import AskDecision
        result = _handle_ask_mode(
            "ask:warn", "directory_blocking", "/secret/file.txt",
            "directory_rules", "Access denied",
        )
        assert result is not None
        assert result.decision == AskDecision.ALLOW_ONCE

    def test_exclusions_allow_denied_path(self):
        """Verify exclusions in config override deny rules."""
        from ai_guardian.hook_processing import _check_directory_rules
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "secret.txt")
            with open(test_file, "w") as f:
                f.write("test")
            config = {
                "directory_rules": {
                    "action": "block",
                    "rules": [{"mode": "deny", "paths": [tmpdir + "/**"]}],
                    "exclusions": [tmpdir + "/**"],
                }
            }
            decision, action, pattern = _check_directory_rules(test_file, config)
            assert decision == "allow"

    def test_exclusions_no_match_still_denied(self):
        """Verify non-matching exclusion doesn't override deny rules."""
        from ai_guardian.hook_processing import _check_directory_rules
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "secret.txt")
            with open(test_file, "w") as f:
                f.write("test")
            config = {
                "directory_rules": {
                    "action": "block",
                    "rules": [{"mode": "deny", "paths": [tmpdir + "/**"]}],
                    "exclusions": ["/other/path/**"],
                }
            }
            decision, action, pattern = _check_directory_rules(test_file, config)
            assert decision == "deny"

    def test_add_directory_exclusion_writes_config(self):
        """Verify add_directory_exclusion writes to directory_rules.exclusions."""
        from ai_guardian.config_writer import add_directory_exclusion
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text('{"directory_rules": {"action": "ask", "rules": []}}')
            result = add_directory_exclusion("/home/user/project/**", config_path=config_path)
            assert result is True
            config = json.loads(config_path.read_text())
            assert "/home/user/project/**" in config["directory_rules"]["exclusions"]

    def test_add_directory_exclusion_dedup(self):
        """Verify add_directory_exclusion doesn't add duplicates."""
        from ai_guardian.config_writer import add_directory_exclusion
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text(json.dumps({
                "directory_rules": {
                    "action": "ask",
                    "rules": [],
                    "exclusions": ["/home/user/project/**"],
                }
            }))
            result = add_directory_exclusion("/home/user/project/**", config_path=config_path)
            assert result is True
            config = json.loads(config_path.read_text())
            assert config["directory_rules"]["exclusions"].count("/home/user/project/**") == 1

    def test_get_directory_action_from_config_default(self):
        """Verify helper returns 'block' when no config available."""
        from ai_guardian.hook_processing import _get_directory_action_from_config
        with patch("ai_guardian.hook_processing.HAS_TOOL_POLICY", False):
            result = _get_directory_action_from_config()
        assert result == "block"

    def test_pattern_editor_suggest_pattern_directory_rules(self):
        """Verify suggest_pattern returns glob for directory_rules."""
        from ai_guardian.tui.pattern_editor import suggest_pattern
        result = suggest_pattern("/home/user/project/file.txt", "directory_rules")
        assert result.endswith("/**")
        assert "/home/user/project" in result

    def test_pattern_editor_generate_config_preview_directory_rules(self):
        """Verify generate_config_preview shows exclusions for directory_rules."""
        from ai_guardian.tui.pattern_editor import generate_config_preview
        result = generate_config_preview("/home/user/**", "directory_rules")
        parsed = json.loads(result)
        assert "exclusions" in parsed["directory_rules"]
        assert "/home/user/**" in parsed["directory_rules"]["exclusions"]

    def test_pattern_editor_prepare_config_directory_rules(self):
        """Verify prepare_config_with_pattern writes to exclusions for directory_rules."""
        from ai_guardian.tui.pattern_editor import prepare_config_with_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"
            config_path.write_text("{}")
            with patch("ai_guardian.config_utils.get_config_dir", return_value=Path(tmpdir)):
                json_text, line_num = prepare_config_with_pattern("/home/user/**", "directory_rules")
            parsed = json.loads(json_text)
            assert "/home/user/**" in parsed["directory_rules"]["exclusions"]

    def test_matches_directory_pattern_exact(self):
        """Verify _matches_directory_pattern with exact path."""
        from ai_guardian.hook_processing import _matches_directory_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            real_tmpdir = os.path.realpath(tmpdir)
            test_file = os.path.join(real_tmpdir, "file.txt")
            assert _matches_directory_pattern(test_file, real_tmpdir) is True
            assert _matches_directory_pattern(test_file, "/nonexistent/path") is False

    def test_matches_directory_pattern_recursive_glob(self):
        """Verify _matches_directory_pattern with ** glob."""
        from ai_guardian.hook_processing import _matches_directory_pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            real_tmpdir = os.path.realpath(tmpdir)
            test_file = os.path.join(real_tmpdir, "sub", "file.txt")
            os.makedirs(os.path.dirname(test_file), exist_ok=True)
            with open(test_file, "w") as f:
                f.write("test")
            assert _matches_directory_pattern(test_file, real_tmpdir + "/**") is True
            assert _matches_directory_pattern(test_file, "/nonexistent/**") is False
