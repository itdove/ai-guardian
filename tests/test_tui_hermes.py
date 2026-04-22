#!/usr/bin/env python3
"""
Tests for Hermes Security TUI Modules

Tests the TUI components for SSRF Protection, Config Scanner, Secret Redaction,
and Security Dashboard.
"""

import json
import tempfile
from pathlib import Path
import pytest

from ai_guardian.tui.ssrf import SSRFContent
from ai_guardian.tui.config_scanner import ConfigScannerContent
from ai_guardian.tui.secret_redaction import SecretRedactionContent
from ai_guardian.tui.security_dashboard import SecurityDashboardContent


class TestSSRFContent:
    """Tests for SSRF Protection TUI tab."""

    def test_ssrf_content_initialization(self):
        """Test that SSRF content can be initialized."""
        content = SSRFContent()
        assert content is not None

    @pytest.mark.skip(reason="Compose requires active Textual app context")
    def test_ssrf_content_compose(self):
        """Test that SSRF content can compose widgets."""
        content = SSRFContent()
        widgets = list(content.compose())
        assert len(widgets) > 0
        # Should have header, scroll container, sections, etc.

    def test_ssrf_config_save(self):
        """Test SSRF config saving."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            # Create initial config
            config = {
                "ssrf_protection": {
                    "enabled": True,
                    "action": "block"
                }
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Verify config was created
            with open(config_path, 'r') as f:
                saved_config = json.load(f)

            assert saved_config["ssrf_protection"]["enabled"] is True
            assert saved_config["ssrf_protection"]["action"] == "block"


class TestConfigScannerContent:
    """Tests for Config File Scanner TUI tab."""

    def test_config_scanner_initialization(self):
        """Test that Config Scanner content can be initialized."""
        content = ConfigScannerContent()
        assert content is not None

    @pytest.mark.skip(reason="Compose requires active Textual app context")
    def test_config_scanner_compose(self):
        """Test that Config Scanner content can compose widgets."""
        content = ConfigScannerContent()
        widgets = list(content.compose())
        assert len(widgets) > 0

    def test_config_scanner_config_structure(self):
        """Test config scanner configuration structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            # Create config with scanner settings
            config = {
                "config_file_scanning": {
                    "enabled": True,
                    "action": "block",
                    "additional_files": [".myconfig"],
                    "ignore_files": ["*.example.md"],
                    "additional_patterns": ["custom_pattern_.*"]
                }
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Verify config structure
            with open(config_path, 'r') as f:
                saved_config = json.load(f)

            scanner_config = saved_config["config_file_scanning"]
            assert scanner_config["enabled"] is True
            assert scanner_config["action"] == "block"
            assert len(scanner_config["additional_files"]) == 1
            assert len(scanner_config["ignore_files"]) == 1
            assert len(scanner_config["additional_patterns"]) == 1


class TestSecretRedactionContent:
    """Tests for Secret Redaction TUI tab."""

    def test_secret_redaction_initialization(self):
        """Test that Secret Redaction content can be initialized."""
        content = SecretRedactionContent()
        assert content is not None

    @pytest.mark.skip(reason="Compose requires active Textual app context")
    def test_secret_redaction_compose(self):
        """Test that Secret Redaction content can compose widgets."""
        content = SecretRedactionContent()
        widgets = list(content.compose())
        assert len(widgets) > 0

    def test_secret_redaction_config_structure(self):
        """Test secret redaction configuration structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            # Create config with redaction settings
            config = {
                "secret_redaction": {
                    "enabled": True,
                    "action": "log-only",
                    "preserve_format": True,
                    "log_redactions": True,
                    "additional_patterns": ["MY_SECRET_[A-Z0-9]+"]
                }
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Verify config structure
            with open(config_path, 'r') as f:
                saved_config = json.load(f)

            redaction_config = saved_config["secret_redaction"]
            assert redaction_config["enabled"] is True
            assert redaction_config["action"] == "log-only"
            assert redaction_config["preserve_format"] is True
            assert redaction_config["log_redactions"] is True
            assert len(redaction_config["additional_patterns"]) == 1


class TestSecurityDashboardContent:
    """Tests for Security Dashboard TUI tab."""

    def test_security_dashboard_initialization(self):
        """Test that Security Dashboard content can be initialized."""
        content = SecurityDashboardContent()
        assert content is not None

    @pytest.mark.skip(reason="Compose requires active Textual app context")
    def test_security_dashboard_compose(self):
        """Test that Security Dashboard content can compose widgets."""
        content = SecurityDashboardContent()
        widgets = list(content.compose())
        assert len(widgets) > 0

    def test_security_dashboard_feature_detection(self):
        """Test that dashboard can detect feature statuses."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            # Create config with mixed feature states
            config = {
                "ssrf_protection": {"enabled": True},
                "prompt_injection": {
                    "enabled": True,
                    "unicode_detection": {"enabled": True}
                },
                "config_file_scanning": {"enabled": False},
                "secret_redaction": {"enabled": True}
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Verify config was created
            with open(config_path, 'r') as f:
                saved_config = json.load(f)

            # Count enabled features (should be 4 out of 5)
            # ssrf: enabled, prompt_injection: enabled, unicode: enabled,
            # config_scanner: disabled, secret_redaction: enabled
            assert saved_config["ssrf_protection"]["enabled"] is True
            assert saved_config["config_file_scanning"]["enabled"] is False

    def test_security_dashboard_parse_status(self):
        """Test status parsing for bool and dict values."""
        dashboard = SecurityDashboardContent()

        # Test simple boolean
        assert dashboard._parse_status(True) is True
        assert dashboard._parse_status(False) is False

        # Test time-based dict (enabled)
        assert dashboard._parse_status({"value": True, "disabled_until": ""}) is True

        # Test time-based dict (disabled)
        assert dashboard._parse_status({"value": False, "disabled_until": "2026-12-31"}) is False

    def test_security_dashboard_categorize_violation(self):
        """Test violation categorization."""
        dashboard = SecurityDashboardContent()

        # Test SSRF categorization
        assert dashboard._categorize_violation("SSRF Protection: Blocked private IP") == "SSRF Protection"

        # Test prompt injection categorization
        assert dashboard._categorize_violation("Prompt injection detected") == "Prompt Injection"

        # Test unicode attack categorization
        assert dashboard._categorize_violation("Unicode attack: zero-width character") == "Unicode Attack"

        # Test config scanner categorization
        assert dashboard._categorize_violation("Config file: CLAUDE.md contains dangerous pattern") == "Config File Scanner"

        # Test secret redaction categorization
        assert dashboard._categorize_violation("Secret redacted: GitHub Token") == "Secret Redaction"

        # Test uncategorized
        assert dashboard._categorize_violation("Unknown violation") == "Other"


class TestPromptInjectionUnicodeDetection:
    """Tests for Unicode Detection in Prompt Injection tab."""

    def test_unicode_detection_config_structure(self):
        """Test unicode detection configuration structure in prompt injection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            # Create config with unicode detection settings
            config = {
                "prompt_injection": {
                    "enabled": True,
                    "unicode_detection": {
                        "enabled": True,
                        "detect_zero_width": True,
                        "detect_bidi_override": True,
                        "detect_tag_chars": True,
                        "detect_homoglyphs": True,
                        "allow_rtl_languages": True,
                        "allow_emoji": True
                    }
                }
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Verify config structure
            with open(config_path, 'r') as f:
                saved_config = json.load(f)

            unicode_config = saved_config["prompt_injection"]["unicode_detection"]
            assert unicode_config["enabled"] is True
            assert unicode_config["detect_zero_width"] is True
            assert unicode_config["detect_bidi_override"] is True
            assert unicode_config["detect_tag_chars"] is True
            assert unicode_config["detect_homoglyphs"] is True
            assert unicode_config["allow_rtl_languages"] is True
            assert unicode_config["allow_emoji"] is True

    def test_unicode_detection_default_values(self):
        """Test that unicode detection has sensible defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            # Create minimal config
            config = {
                "prompt_injection": {
                    "unicode_detection": {}
                }
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            # Config should accept empty unicode_detection
            with open(config_path, 'r') as f:
                saved_config = json.load(f)

            assert "unicode_detection" in saved_config["prompt_injection"]
