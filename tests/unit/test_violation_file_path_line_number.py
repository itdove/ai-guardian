"""Tests that all violation log entries include file_path and line_number fields (Issue #349)."""

import json
import os
import tempfile
from unittest import mock

import pytest


class TestToolPermissionViolationFilePath:
    """Test that tool_permission violations include file_path for file-path tools."""

    @mock.patch('ai_guardian.tool_policy.ViolationLogger')
    @mock.patch('ai_guardian.tool_policy.HAS_VIOLATION_LOGGER', True)
    def test_file_path_present_for_read_tool(self, mock_vl_class):
        from ai_guardian.tool_policy import ToolPolicyChecker
        mock_logger = mock.MagicMock()
        mock_vl_class.return_value = mock_logger

        checker = ToolPolicyChecker(config={"permissions": {"enabled": True, "rules": []}})
        checker._log_violation(
            tool_name="Read",
            check_value="/home/user/secret.txt",
            reason="blocked by policy",
            matcher="Read",
            hook_data={}
        )
        mock_logger.log_violation.assert_called_once()
        blocked = mock_logger.log_violation.call_args[1]["blocked"]
        assert blocked["file_path"] == "/home/user/secret.txt"

    @mock.patch('ai_guardian.tool_policy.ViolationLogger')
    @mock.patch('ai_guardian.tool_policy.HAS_VIOLATION_LOGGER', True)
    def test_file_path_present_for_write_tool(self, mock_vl_class):
        from ai_guardian.tool_policy import ToolPolicyChecker
        mock_logger = mock.MagicMock()
        mock_vl_class.return_value = mock_logger

        checker = ToolPolicyChecker(config={"permissions": {"enabled": True, "rules": []}})
        checker._log_violation(
            tool_name="Write",
            check_value="/home/user/config.json",
            reason="blocked by policy",
            matcher="Write",
            hook_data={}
        )
        blocked = mock_logger.log_violation.call_args[1]["blocked"]
        assert blocked["file_path"] == "/home/user/config.json"

    @mock.patch('ai_guardian.tool_policy.ViolationLogger')
    @mock.patch('ai_guardian.tool_policy.HAS_VIOLATION_LOGGER', True)
    def test_file_path_present_for_edit_tool(self, mock_vl_class):
        from ai_guardian.tool_policy import ToolPolicyChecker
        mock_logger = mock.MagicMock()
        mock_vl_class.return_value = mock_logger

        checker = ToolPolicyChecker(config={"permissions": {"enabled": True, "rules": []}})
        checker._log_violation(
            tool_name="Edit",
            check_value="/home/user/main.py",
            reason="blocked by policy",
            matcher="Edit",
            hook_data={}
        )
        blocked = mock_logger.log_violation.call_args[1]["blocked"]
        assert blocked["file_path"] == "/home/user/main.py"

    @mock.patch('ai_guardian.tool_policy.ViolationLogger')
    @mock.patch('ai_guardian.tool_policy.HAS_VIOLATION_LOGGER', True)
    def test_file_path_present_for_notebook_edit_tool(self, mock_vl_class):
        from ai_guardian.tool_policy import ToolPolicyChecker
        mock_logger = mock.MagicMock()
        mock_vl_class.return_value = mock_logger

        checker = ToolPolicyChecker(config={"permissions": {"enabled": True, "rules": []}})
        checker._log_violation(
            tool_name="NotebookEdit",
            check_value="/home/user/notebook.ipynb",
            reason="blocked by policy",
            matcher="NotebookEdit",
            hook_data={}
        )
        blocked = mock_logger.log_violation.call_args[1]["blocked"]
        assert blocked["file_path"] == "/home/user/notebook.ipynb"

    @mock.patch('ai_guardian.tool_policy.ViolationLogger')
    @mock.patch('ai_guardian.tool_policy.HAS_VIOLATION_LOGGER', True)
    def test_file_path_none_for_bash_tool(self, mock_vl_class):
        from ai_guardian.tool_policy import ToolPolicyChecker
        mock_logger = mock.MagicMock()
        mock_vl_class.return_value = mock_logger

        checker = ToolPolicyChecker(config={"permissions": {"enabled": True, "rules": []}})
        checker._log_violation(
            tool_name="Bash",
            check_value="rm -rf /",
            reason="blocked by policy",
            matcher="Bash",
            hook_data={}
        )
        blocked = mock_logger.log_violation.call_args[1]["blocked"]
        assert blocked["file_path"] is None

    @mock.patch('ai_guardian.tool_policy.ViolationLogger')
    @mock.patch('ai_guardian.tool_policy.HAS_VIOLATION_LOGGER', True)
    def test_file_path_none_for_skill_tool(self, mock_vl_class):
        from ai_guardian.tool_policy import ToolPolicyChecker
        mock_logger = mock.MagicMock()
        mock_vl_class.return_value = mock_logger

        checker = ToolPolicyChecker(config={"permissions": {"enabled": True, "rules": []}})
        checker._log_violation(
            tool_name="Skill",
            check_value="some-skill",
            reason="blocked by policy",
            matcher="Skill",
            hook_data={}
        )
        blocked = mock_logger.log_violation.call_args[1]["blocked"]
        assert blocked["file_path"] is None


class TestPromptInjectionViolationFilePath:
    """Test that prompt_injection violations include file_path from context."""

    def test_file_path_from_context(self):
        from ai_guardian.violation_logger import ViolationLogger
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': tmp}):
                with mock.patch('ai_guardian.HAS_VIOLATION_LOGGER', True):
                    from ai_guardian import _log_prompt_injection_violation
                    with mock.patch('ai_guardian.ViolationLogger') as mock_vl_class:
                        mock_logger = mock.MagicMock()
                        mock_vl_class.return_value = mock_logger

                        _log_prompt_injection_violation(
                            "malicious.md",
                            context={"ide_type": "claude_code", "hook_event": "pretooluse", "file_path": "/full/path/malicious.md"},
                            attack_type="injection"
                        )
                        mock_logger.log_violation.assert_called_once()
                        blocked = mock_logger.log_violation.call_args[1]["blocked"]
                        assert blocked["file_path"] == "/full/path/malicious.md"

    def test_file_path_falls_back_to_filename(self):
        with mock.patch('ai_guardian.HAS_VIOLATION_LOGGER', True):
            from ai_guardian import _log_prompt_injection_violation
            with mock.patch('ai_guardian.ViolationLogger') as mock_vl_class:
                mock_logger = mock.MagicMock()
                mock_vl_class.return_value = mock_logger

                _log_prompt_injection_violation(
                    "malicious.md",
                    context={"ide_type": "claude_code", "hook_event": "pretooluse"},
                    attack_type="injection"
                )
                blocked = mock_logger.log_violation.call_args[1]["blocked"]
                assert blocked["file_path"] == "malicious.md"

    def test_file_path_none_for_user_prompt(self):
        with mock.patch('ai_guardian.HAS_VIOLATION_LOGGER', True):
            from ai_guardian import _log_prompt_injection_violation
            with mock.patch('ai_guardian.ViolationLogger') as mock_vl_class:
                mock_logger = mock.MagicMock()
                mock_vl_class.return_value = mock_logger

                _log_prompt_injection_violation(
                    "user_prompt",
                    context={"ide_type": "claude_code", "hook_event": "prompt"},
                    attack_type="injection"
                )
                blocked = mock_logger.log_violation.call_args[1]["blocked"]
                assert blocked["file_path"] is None


class TestJailbreakViolationFilePath:
    """Test that jailbreak_detected violations include file_path from context."""

    def test_file_path_from_context(self):
        with mock.patch('ai_guardian.HAS_VIOLATION_LOGGER', True):
            from ai_guardian import _log_prompt_injection_violation
            with mock.patch('ai_guardian.ViolationLogger') as mock_vl_class:
                mock_logger = mock.MagicMock()
                mock_vl_class.return_value = mock_logger

                _log_prompt_injection_violation(
                    "evil.py",
                    context={"ide_type": "claude_code", "hook_event": "pretooluse", "file_path": "/repo/evil.py"},
                    attack_type="jailbreak"
                )
                call_kwargs = mock_logger.log_violation.call_args[1]
                assert call_kwargs["violation_type"] == "jailbreak_detected"
                assert call_kwargs["blocked"]["file_path"] == "/repo/evil.py"


class TestSecretRedactionViolationFields:
    """Test that secret_redaction violations include file_path and line_number."""

    def test_fields_present(self):
        from ai_guardian.violation_logger import ViolationLogger
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': tmp}):
                vl = ViolationLogger()
                vl.log_violation(
                    violation_type='secret_redaction',
                    blocked={
                        'tool': 'Read',
                        'file_path': None,
                        'line_number': None,
                        'redaction_count': 2,
                        'redacted_types': ['api_key', 'password']
                    },
                    context={'action': 'redacted', 'mode': 'redact'}
                )
                violations = vl.get_recent_violations(limit=10)
                assert len(violations) == 1
                blocked = violations[0]["blocked"]
                assert "file_path" in blocked
                assert "line_number" in blocked


class TestPIIViolationFilePath:
    """Test that pii_detected violations include file_path and line_number."""

    def test_pretooluse_pii_has_file_path(self):
        from ai_guardian.violation_logger import ViolationLogger
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': tmp}):
                vl = ViolationLogger()
                vl.log_violation(
                    violation_type='pii_detected',
                    blocked={
                        'tool': 'Read',
                        'hook': 'PreToolUse',
                        'file_path': '/home/user/data.csv',
                        'line_number': None,
                        'pii_count': 3,
                        'pii_types': ['email', 'phone']
                    },
                    context={'action': 'block', 'hook_event': 'pretooluse'}
                )
                violations = vl.get_recent_violations(limit=10)
                assert len(violations) == 1
                blocked = violations[0]["blocked"]
                assert blocked["file_path"] == "/home/user/data.csv"
                assert "line_number" in blocked

    def test_posttooluse_pii_has_null_file_path(self):
        from ai_guardian.violation_logger import ViolationLogger
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': tmp}):
                vl = ViolationLogger()
                vl.log_violation(
                    violation_type='pii_detected',
                    blocked={
                        'tool': 'Bash',
                        'hook': 'PostToolUse',
                        'file_path': None,
                        'line_number': None,
                        'pii_count': 1,
                        'pii_types': ['ssn']
                    },
                    context={'action': 'block', 'hook_event': 'posttooluse'}
                )
                violations = vl.get_recent_violations(limit=10)
                assert len(violations) == 1
                blocked = violations[0]["blocked"]
                assert blocked["file_path"] is None
                assert blocked["line_number"] is None


class TestConfigFileExfilViolationFields:
    """Test that config_file_exfil violations include line_number field."""

    def test_line_number_present(self):
        from ai_guardian.violation_logger import ViolationLogger
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': tmp}):
                vl = ViolationLogger()
                vl.log_violation(
                    violation_type='config_file_exfil',
                    blocked={
                        'file_path': '/etc/shadow',
                        'line_number': None,
                        'reason': 'config exfiltration',
                        'details': 'sensitive config file'
                    },
                    context={'hook_event': 'pretooluse'},
                    severity='critical'
                )
                violations = vl.get_recent_violations(limit=10)
                assert len(violations) == 1
                blocked = violations[0]["blocked"]
                assert blocked["file_path"] == "/etc/shadow"
                assert "line_number" in blocked


class TestSecretDetectedViolationFieldsUnchanged:
    """Verify that secret_detected violations still work correctly with existing fields."""

    def test_line_number_preserved(self):
        from ai_guardian.violation_logger import ViolationLogger
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': tmp}):
                vl = ViolationLogger()
                vl.log_violation(
                    violation_type='secret_detected',
                    blocked={
                        'file_path': '/repo/config.py',
                        'source': 'file',
                        'secret_type': 'aws-access-key',
                        'reason': 'Gitleaks detected sensitive information',
                        'line_number': 42,
                        'end_line': 42
                    },
                    context={'ide_type': 'claude_code', 'hook_event': 'pretooluse', 'project_path': '/repo'},
                    severity='critical'
                )
                violations = vl.get_recent_violations(limit=10)
                assert len(violations) == 1
                blocked = violations[0]["blocked"]
                assert blocked["file_path"] == "/repo/config.py"
                assert blocked["line_number"] == 42
                assert blocked["end_line"] == 42


class TestAllViolationTypesHaveFilePath:
    """Integration test: every violation type's blocked dict includes file_path."""

    def _log_and_get(self, violation_type, blocked, context=None, severity="warning"):
        from ai_guardian.violation_logger import ViolationLogger
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': tmp}):
                vl = ViolationLogger()
                vl.log_violation(
                    violation_type=violation_type,
                    blocked=blocked,
                    context=context or {},
                    severity=severity
                )
                violations = vl.get_recent_violations(limit=10)
                assert len(violations) == 1
                return violations[0]["blocked"]

    def test_tool_permission_has_file_path_key(self):
        blocked = self._log_and_get("tool_permission", {
            "tool_name": "Read", "tool_value": "/etc/passwd",
            "file_path": "/etc/passwd", "matcher": "Read", "reason": "denied"
        })
        assert "file_path" in blocked

    def test_directory_blocking_has_file_path_key(self):
        blocked = self._log_and_get("directory_blocking", {
            "file_path": "/repo/.secrets/key", "denied_directory": "/repo/.secrets",
            "reason": ".ai-read-deny marker found", "exclusion_overridden": False
        })
        assert "file_path" in blocked

    def test_secret_detected_has_file_path_key(self):
        blocked = self._log_and_get("secret_detected", {
            "file_path": "/repo/config.py", "source": "file",
            "secret_type": "generic", "reason": "detected", "line_number": 10
        }, severity="critical")
        assert "file_path" in blocked
        assert "line_number" in blocked

    def test_prompt_injection_has_file_path_key(self):
        blocked = self._log_and_get("prompt_injection", {
            "file_path": "/repo/readme.md", "source": "file",
            "pattern": "test", "confidence": 0.95, "method": "heuristic", "reason": "detected"
        }, severity="high")
        assert "file_path" in blocked

    def test_jailbreak_detected_has_file_path_key(self):
        blocked = self._log_and_get("jailbreak_detected", {
            "file_path": "/repo/evil.py", "source": "file",
            "pattern": "test", "confidence": 0.95, "method": "heuristic", "reason": "detected"
        }, severity="high")
        assert "file_path" in blocked

    def test_secret_redaction_has_file_path_key(self):
        blocked = self._log_and_get("secret_redaction", {
            "tool": "Read", "file_path": None, "line_number": None,
            "redaction_count": 1, "redacted_types": ["api_key"]
        })
        assert "file_path" in blocked
        assert "line_number" in blocked

    def test_pii_detected_has_file_path_key(self):
        blocked = self._log_and_get("pii_detected", {
            "tool": "Read", "hook": "PreToolUse",
            "file_path": "/repo/data.csv", "line_number": None,
            "pii_count": 1, "pii_types": ["email"]
        })
        assert "file_path" in blocked
        assert "line_number" in blocked

    def test_config_file_exfil_has_file_path_key(self):
        blocked = self._log_and_get("config_file_exfil", {
            "file_path": "/etc/shadow", "line_number": None,
            "reason": "exfil", "details": "sensitive"
        }, severity="critical")
        assert "file_path" in blocked
        assert "line_number" in blocked

    def test_ssrf_blocked_has_file_path_key_via_tool_policy(self):
        blocked = self._log_and_get("ssrf_blocked", {
            "tool_name": "Bash", "tool_value": "curl http://169.254.169.254",
            "file_path": None, "matcher": "Bash", "reason": "SSRF"
        })
        assert "file_path" in blocked
