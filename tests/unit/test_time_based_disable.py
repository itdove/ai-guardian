"""
Tests for time-based temporary disable (disabled_until) for PII, SSRF,
directory rules, and violation logging (Issue #398).

Verifies that is_feature_enabled() is called correctly for all features,
supporting both simple boolean and extended {"value": ..., "disabled_until": ...}
config formats.
"""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest

from ai_guardian.config_utils import is_feature_enabled


FUTURE_TIME = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
PAST_TIME = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()


class TestPIITimeBased:
    """Test PII scanning honors disabled_until."""

    def test_pii_disabled_until_future_skips_scan(self):
        """PII scanning should be skipped when disabled_until is in the future."""
        pii_config = {
            "enabled": {
                "value": False,
                "disabled_until": FUTURE_TIME,
                "reason": "debugging"
            }
        }
        enabled = is_feature_enabled(
            pii_config.get('enabled'),
            datetime.now(timezone.utc),
            default=True
        )
        assert enabled is False

    def test_pii_disabled_until_past_auto_reenables(self):
        """PII scanning should auto re-enable when disabled_until has passed."""
        pii_config = {
            "enabled": {
                "value": False,
                "disabled_until": PAST_TIME,
                "reason": "debugging"
            }
        }
        enabled = is_feature_enabled(
            pii_config.get('enabled'),
            datetime.now(timezone.utc),
            default=True
        )
        assert enabled is True

    def test_pii_simple_bool_true_still_works(self):
        """Backward compat: simple 'enabled': true still works."""
        pii_config = {"enabled": True}
        enabled = is_feature_enabled(
            pii_config.get('enabled'),
            datetime.now(timezone.utc),
            default=True
        )
        assert enabled is True

    def test_pii_simple_bool_false_still_works(self):
        """Backward compat: simple 'enabled': false still works."""
        pii_config = {"enabled": False}
        enabled = is_feature_enabled(
            pii_config.get('enabled'),
            datetime.now(timezone.utc),
            default=True
        )
        assert enabled is False

    def test_pii_missing_enabled_defaults_true(self):
        """When 'enabled' key is missing, PII defaults to enabled."""
        pii_config = {"action": "block"}
        enabled = is_feature_enabled(
            pii_config.get('enabled'),
            datetime.now(timezone.utc),
            default=True
        )
        assert enabled is True

    def test_pii_redactor_disabled_until_future(self):
        """SecretRedactor should not load PII patterns when disabled_until is future."""
        from ai_guardian.secret_redactor import SecretRedactor
        pii_config = {
            "enabled": {
                "value": False,
                "disabled_until": FUTURE_TIME,
                "reason": "testing"
            },
            "pii_types": ["ssn"]
        }
        redactor = SecretRedactor(pii_config=pii_config)
        text = "SSN: 123-45-6789"
        result = redactor.redact(text)
        assert result['redacted_text'] == text

    def test_pii_redactor_disabled_until_past_reenables(self):
        """SecretRedactor should load PII patterns when disabled_until has expired."""
        from ai_guardian.secret_redactor import SecretRedactor
        pii_config = {
            "enabled": {
                "value": False,
                "disabled_until": PAST_TIME,
                "reason": "testing"
            },
            "pii_types": ["ssn"]
        }
        redactor = SecretRedactor(pii_config=pii_config)
        text = "SSN: 123-45-6789"
        result = redactor.redact(text)
        assert "123-45-6789" not in result['redacted_text']


class TestSSRFTimeBased:
    """Test SSRF protection honors disabled_until."""

    def test_ssrf_disabled_until_future(self):
        """SSRF check should be skipped when disabled_until is in the future."""
        ssrf_config = {
            "enabled": {
                "value": False,
                "disabled_until": FUTURE_TIME,
                "reason": "debugging"
            }
        }
        enabled = is_feature_enabled(
            ssrf_config.get("enabled"),
            datetime.now(timezone.utc),
            default=True
        )
        assert enabled is False

    def test_ssrf_disabled_until_past_auto_reenables(self):
        """SSRF check should auto re-enable when disabled_until has passed."""
        ssrf_config = {
            "enabled": {
                "value": False,
                "disabled_until": PAST_TIME,
                "reason": "debugging"
            }
        }
        enabled = is_feature_enabled(
            ssrf_config.get("enabled"),
            datetime.now(timezone.utc),
            default=True
        )
        assert enabled is True

    def test_ssrf_simple_bool_true_still_works(self):
        """Backward compat: simple 'enabled': true still works."""
        ssrf_config = {"enabled": True}
        enabled = is_feature_enabled(
            ssrf_config.get("enabled"),
            datetime.now(timezone.utc),
            default=True
        )
        assert enabled is True

    def test_ssrf_simple_bool_false_still_works(self):
        """Backward compat: simple 'enabled': false still works."""
        ssrf_config = {"enabled": False}
        enabled = is_feature_enabled(
            ssrf_config.get("enabled"),
            datetime.now(timezone.utc),
            default=True
        )
        assert enabled is False

    def test_ssrf_tool_policy_with_disabled_until(self):
        """ToolPolicyChecker should skip SSRF when disabled_until is future."""
        from ai_guardian.tool_policy import ToolPolicyChecker

        config = {
            "ssrf_protection": {
                "enabled": {
                    "value": False,
                    "disabled_until": FUTURE_TIME,
                    "reason": "testing"
                }
            },
            "permissions": {"enabled": False}
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {'AI_GUARDIAN_CONFIG_DIR': tmp}):
                checker = ToolPolicyChecker(config=config)
                hook_data = {
                    "tool_name": "Bash",
                    "tool_input": {
                        "command": "curl http://169.254.169.254/latest/meta-data/"
                    }
                }
                is_allowed, error_msg, tool_name = checker.check_tool_allowed(hook_data)
                assert is_allowed is True


class TestDirectoryRulesTimeBased:
    """Test directory rules honor disabled_until."""

    def test_dir_exclusions_disabled_until_future(self):
        """Directory exclusions should be disabled when disabled_until is future."""
        config = {
            "enabled": {
                "value": False,
                "disabled_until": FUTURE_TIME,
                "reason": "debugging"
            }
        }
        enabled = is_feature_enabled(
            config.get("enabled"),
            datetime.now(timezone.utc),
            default=False
        )
        assert enabled is False

    def test_dir_exclusions_disabled_until_past_auto_reenables(self):
        """Directory exclusions should auto re-enable when disabled_until passed."""
        config = {
            "enabled": {
                "value": False,
                "disabled_until": PAST_TIME,
                "reason": "debugging"
            }
        }
        enabled = is_feature_enabled(
            config.get("enabled"),
            datetime.now(timezone.utc),
            default=False
        )
        assert enabled is True

    def test_dir_exclusions_simple_bool_true(self):
        """Backward compat: simple 'enabled': true still works."""
        config = {"enabled": True}
        enabled = is_feature_enabled(
            config.get("enabled"),
            datetime.now(timezone.utc),
            default=False
        )
        assert enabled is True

    def test_dir_exclusions_simple_bool_false(self):
        """Backward compat: simple 'enabled': false still works."""
        config = {"enabled": False}
        enabled = is_feature_enabled(
            config.get("enabled"),
            datetime.now(timezone.utc),
            default=False
        )
        assert enabled is False


class TestViolationLoggingTimeBased:
    """Test violation logging honors disabled_until."""

    def test_logging_disabled_until_future_skips_log(self):
        """ViolationLogger should not log when disabled_until is in the future."""
        from ai_guardian.violation_logger import ViolationLogger

        config = {
            "enabled": {
                "value": False,
                "disabled_until": FUTURE_TIME,
                "reason": "debugging"
            },
            "max_entries": 1000,
            "retention_days": 30,
            "log_types": ["tool_permission"]
        }
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "violations.jsonl"
            vl = ViolationLogger(log_path=log_path, config=config)

            assert vl._is_logging_enabled() is False

            vl.log_violation(
                violation_type="tool_permission",
                blocked={"tool": "test"},
                context={"ide": "test"}
            )
            assert not log_path.exists()

    def test_logging_disabled_until_past_auto_reenables(self):
        """ViolationLogger should log when disabled_until has passed."""
        from ai_guardian.violation_logger import ViolationLogger

        config = {
            "enabled": {
                "value": False,
                "disabled_until": PAST_TIME,
                "reason": "debugging"
            },
            "max_entries": 1000,
            "retention_days": 30,
            "log_types": ["tool_permission"]
        }
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "violations.jsonl"
            vl = ViolationLogger(log_path=log_path, config=config)

            assert vl._is_logging_enabled() is True

            vl.log_violation(
                violation_type="tool_permission",
                blocked={"tool": "test"},
                context={"ide": "test"}
            )
            assert log_path.exists()
            with open(log_path) as f:
                entry = json.loads(f.readline())
            assert entry["violation_type"] == "tool_permission"

    def test_logging_simple_bool_true(self):
        """Backward compat: simple 'enabled': true still works."""
        from ai_guardian.violation_logger import ViolationLogger

        config = {
            "enabled": True,
            "max_entries": 1000,
            "retention_days": 30,
            "log_types": ["tool_permission"]
        }
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "violations.jsonl"
            vl = ViolationLogger(log_path=log_path, config=config)
            assert vl._is_logging_enabled() is True

    def test_logging_simple_bool_false(self):
        """Backward compat: simple 'enabled': false still works."""
        from ai_guardian.violation_logger import ViolationLogger

        config = {
            "enabled": False,
            "max_entries": 1000,
            "retention_days": 30,
            "log_types": ["tool_permission"]
        }
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "violations.jsonl"
            vl = ViolationLogger(log_path=log_path, config=config)
            assert vl._is_logging_enabled() is False

    def test_logging_missing_enabled_defaults_true(self):
        """When 'enabled' key is missing, logging defaults to enabled."""
        from ai_guardian.violation_logger import ViolationLogger

        config = {
            "max_entries": 1000,
            "retention_days": 30,
            "log_types": ["tool_permission"]
        }
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "violations.jsonl"
            vl = ViolationLogger(log_path=log_path, config=config)
            assert vl._is_logging_enabled() is True


class TestConfigInspectorTimeBased:
    """Test config_inspector shows correct SSRF status with disabled_until."""

    def test_ssrf_inspector_disabled_until_future(self):
        """Config inspector should show DISABLED when disabled_until is future."""
        enabled = is_feature_enabled(
            {"value": False, "disabled_until": FUTURE_TIME},
            default=True
        )
        assert enabled is False

    def test_ssrf_inspector_disabled_until_past(self):
        """Config inspector should show ENABLED when disabled_until expired."""
        enabled = is_feature_enabled(
            {"value": False, "disabled_until": PAST_TIME},
            default=True
        )
        assert enabled is True
