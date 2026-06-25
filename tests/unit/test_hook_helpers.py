"""Tests for extracted hook_processing helper functions."""

from unittest.mock import MagicMock


from ai_guardian.hook_processing import (
    _build_secret_detected_message,
    _log_pii_violation,
    HookEvent,
)
from ai_guardian.constants import ViolationType

# ---------------------------------------------------------------------------
# _build_secret_detected_message
# ---------------------------------------------------------------------------


class TestBuildSecretDetectedMessage:

    SAMPLE_DETAILS = {
        "rule_id": "generic-api-key",
        "file": "config.py",
        "line_number": 42,
        "end_line": 42,
        "commit": "abc1234",
        "total_findings": 1,
    }

    def test_basic_message_structure(self):
        msg = _build_secret_detected_message(
            "gitleaks", self.SAMPLE_DETAILS, "Built-in gitleaks rules"
        )
        assert "Secret Detected" in msg
        assert "Protection: Secret Scanning" in msg
        assert "Secret Type: Generic API Key" in msg
        assert "Location: config.py:42" in msg
        assert "Scanner: gitleaks" in msg
        assert "Patterns: Built-in gitleaks rules" in msg
        assert "Move secrets to environment variables" in msg

    def test_custom_protection_label(self):
        msg = _build_secret_detected_message(
            "gitleaks",
            self.SAMPLE_DETAILS,
            "Built-in gitleaks rules",
            protection_label="Secret Scanning (any-match strategy)",
        )
        assert "Protection: Secret Scanning (any-match strategy)" in msg

    def test_no_line_number(self):
        details = {**self.SAMPLE_DETAILS, "line_number": None}
        msg = _build_secret_detected_message("gitleaks", details, "Built-in rules")
        assert "Location: config.py\n" in msg
        assert ":None" not in msg

    def test_no_secret_details(self):
        msg = _build_secret_detected_message("gitleaks", None, "Built-in rules")
        assert "Secret Type: (multiple or unknown)" in msg
        assert "Common secret types:" in msg
        assert "API keys and tokens" in msg

    def test_with_details_no_common_types_section(self):
        msg = _build_secret_detected_message(
            "gitleaks", self.SAMPLE_DETAILS, "Built-in rules"
        )
        assert "Common secret types:" not in msg

    def test_pattern_description_passthrough(self):
        msg = _build_secret_detected_message(
            "betterleaks",
            self.SAMPLE_DETAILS,
            "LeakTK Pattern Server (https://patterns.example.com)",
        )
        assert "Patterns: LeakTK Pattern Server (https://patterns.example.com)" in msg

    def test_separator_lines(self):
        msg = _build_secret_detected_message("gitleaks", self.SAMPLE_DETAILS, "rules")
        assert msg.startswith(f"\n{'='*70}\n")
        assert msg.endswith(f"{'='*70}\n")


# ---------------------------------------------------------------------------
# _log_pii_violation
# ---------------------------------------------------------------------------


class TestLogPiiViolation:

    SAMPLE_REDACTIONS = [
        {"type": "EMAIL", "line_number": 5, "original": "test@example.com"},
        {"type": "PHONE", "line_number": 10, "original": "555-1234"},
        {"type": "EMAIL", "line_number": 15, "original": "other@example.com"},
    ]

    def test_returns_action_and_types(self):
        pii_config = {"action": "warn"}
        action, types = _log_pii_violation(
            None,
            pii_config,
            self.SAMPLE_REDACTIONS,
            "Write",
            "PostToolUse",
            "/tmp/test.py",
            "some text",
            HookEvent.POST_TOOL_USE,
        )
        assert action == "warn"
        assert set(types) == {"EMAIL", "PHONE"}

    def test_default_action_is_block(self):
        action, _ = _log_pii_violation(
            None,
            {},
            self.SAMPLE_REDACTIONS,
            "Write",
            "PostToolUse",
            "/tmp/test.py",
            "text",
            HookEvent.POST_TOOL_USE,
        )
        assert action == "block"

    def test_calls_violation_logger(self):
        mock_logger = MagicMock()
        _log_pii_violation(
            mock_logger,
            {"action": "block"},
            self.SAMPLE_REDACTIONS,
            "Write",
            "PostToolUse",
            "/tmp/test.py",
            "line1\nline2\nline3",
            HookEvent.POST_TOOL_USE,
            hook_tool_use_id="tu-123",
            hook_session_id="sess-456",
        )
        mock_logger.log_violation.assert_called_once()
        call_kwargs = mock_logger.log_violation.call_args[1]
        assert call_kwargs["violation_type"] == ViolationType.PII_DETECTED
        blocked = call_kwargs["blocked"]
        assert blocked["tool"] == "Write"
        assert blocked["hook"] == "PostToolUse"
        assert blocked["file_path"] == "/tmp/test.py"
        assert blocked["pii_count"] == 3
        assert set(blocked["pii_types"]) == {"EMAIL", "PHONE"}
        ctx = call_kwargs["context"]
        assert ctx["action"] == "block"
        assert ctx["tool_use_id"] == "tu-123"
        assert ctx["session_id"] == "sess-456"

    def test_no_logger_does_not_raise(self):
        action, types = _log_pii_violation(
            None,
            {"action": "redact"},
            self.SAMPLE_REDACTIONS,
            "Read",
            "PreToolUse",
            None,
            None,
            HookEvent.PRE_TOOL_USE,
        )
        assert action == "redact"

    def test_bash_command_included(self):
        mock_logger = MagicMock()
        _log_pii_violation(
            mock_logger,
            {"action": "block"},
            self.SAMPLE_REDACTIONS,
            "Bash",
            "PostToolUse",
            None,
            "output",
            HookEvent.POST_TOOL_USE,
            bash_command="cat /etc/passwd",
        )
        blocked = mock_logger.log_violation.call_args[1]["blocked"]
        assert blocked["command"] == "cat /etc/passwd"

    def test_pretool_context_included(self):
        mock_logger = MagicMock()
        pretool = {"file_path": "/some/file.py"}
        _log_pii_violation(
            mock_logger,
            {"action": "block"},
            self.SAMPLE_REDACTIONS,
            "Write",
            "PostToolUse",
            None,
            "text",
            HookEvent.POST_TOOL_USE,
            pretool_ctx=pretool,
        )
        ctx = mock_logger.log_violation.call_args[1]["context"]
        assert ctx["pretool_context"] == pretool

    def test_line_number_from_first_redaction(self):
        mock_logger = MagicMock()
        _log_pii_violation(
            mock_logger,
            {"action": "block"},
            self.SAMPLE_REDACTIONS,
            "Write",
            "PostToolUse",
            "/f.py",
            "text",
            HookEvent.POST_TOOL_USE,
        )
        blocked = mock_logger.log_violation.call_args[1]["blocked"]
        assert blocked["line_number"] == 5
