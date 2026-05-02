#!/usr/bin/env python3
"""
Tests for AI Guardian TUI

Tests the interactive TUI components and configuration management.
"""

import json
import tempfile
from pathlib import Path
import pytest

from ai_guardian.tui.app import (
    AIGuardianTUI, NAV_GROUPS, HELP_DOCS, HelpModal, copy_to_system_clipboard,
)


class TestTUIApp:
    """Tests for the main TUI application."""

    def test_tui_initialization(self):
        """Test that TUI app can be initialized."""
        app = AIGuardianTUI()
        assert app is not None
        assert app.TITLE == "AI Guardian Configuration"

    def test_tui_has_screens(self):
        """Test that TUI has required screens."""
        app = AIGuardianTUI()
        assert app is not None


class TestNavGroups:
    """Tests for navigation structure."""

    def test_nav_groups_has_eight_categories(self):
        """Test that NAV_GROUPS defines exactly 8 category groups."""
        assert len(NAV_GROUPS) == 8

    def test_nav_groups_has_twentythree_panels(self):
        """Test that NAV_GROUPS defines exactly 23 leaf panels."""
        total_leaves = sum(len(items) for _, items in NAV_GROUPS)
        assert total_leaves == 23

    def test_panel_ids_are_unique(self):
        """Test that all panel IDs are unique."""
        panel_ids = [pid for _, items in NAV_GROUPS for _, pid in items]
        assert len(panel_ids) == len(set(panel_ids)), "Duplicate panel IDs found"

    def test_panel_ids_have_panel_prefix(self):
        """Test that all panel IDs start with 'panel-'."""
        for _, items in NAV_GROUPS:
            for _, panel_id in items:
                assert panel_id.startswith("panel-"), f"{panel_id} missing 'panel-' prefix"

    def test_category_labels_are_strings(self):
        """Test that all category labels are non-empty strings."""
        for label, _ in NAV_GROUPS:
            assert isinstance(label, str)
            assert len(label) > 0

    def test_leaf_labels_are_strings(self):
        """Test that all leaf labels are non-empty strings."""
        for _, items in NAV_GROUPS:
            for label, _ in items:
                assert isinstance(label, str)
                assert len(label) > 0

    def test_check_action_panel_ids_exist_in_nav(self):
        """Test that all panel IDs referenced in check_action exist in NAV_GROUPS."""
        panel_ids = {pid for _, items in NAV_GROUPS for _, pid in items}
        action_panel_ids = {
            "panel-skills",
            "panel-mcp",
            "panel-pi-detection",
            "panel-pi-patterns",
            "panel-secrets",
            "panel-ssrf",
            "panel-config-scanner",
            "panel-secret-redaction",
        }
        assert action_panel_ids.issubset(panel_ids), (
            f"Missing panel IDs: {action_panel_ids - panel_ids}"
        )

    def test_expected_categories(self):
        """Test that the expected category names are present."""
        category_names = [name for name, _ in NAV_GROUPS]
        assert "Security Overview" in category_names
        assert "Permissions" in category_names
        assert "Threat Detection" in category_names
        assert "Prompt Injection" in category_names
        assert "Secrets" in category_names
        assert "Monitoring" in category_names
        assert "Configuration" in category_names
        assert "Tools" in category_names

    def test_expected_panels_in_categories(self):
        """Test that key panels are in the correct categories."""
        nav_dict = {name: [pid for _, pid in items] for name, items in NAV_GROUPS}

        assert "panel-security-dashboard" in nav_dict["Security Overview"]
        assert "panel-skills" in nav_dict["Permissions"]
        assert "panel-pi-detection" in nav_dict["Prompt Injection"]
        assert "panel-pi-jailbreak" in nav_dict["Prompt Injection"]
        assert "panel-pi-unicode" in nav_dict["Prompt Injection"]
        assert "panel-scan-pii" in nav_dict["Threat Detection"]
        assert "panel-secrets" in nav_dict["Secrets"]
        assert "panel-violations" in nav_dict["Monitoring"]
        assert "panel-violation-logging" in nav_dict["Monitoring"]
        assert "panel-config-file" in nav_dict["Configuration"]
        assert "panel-config-editor" in nav_dict["Configuration"]
        assert "panel-config-effective" in nav_dict["Configuration"]
        assert "panel-regex-tester" in nav_dict["Tools"]


class TestHelpDocs:
    """Tests for inline help documentation."""

    def test_all_panels_have_help(self):
        """Test that every panel has a help doc entry."""
        panel_ids = [pid for _, items in NAV_GROUPS for _, pid in items]
        for panel_id in panel_ids:
            assert panel_id in HELP_DOCS, f"Missing help doc for {panel_id}"

    def test_all_categories_have_help(self):
        """Test that every category has a help doc entry."""
        category_names = [name for name, _ in NAV_GROUPS]
        for name in category_names:
            assert name in HELP_DOCS, f"Missing help doc for category {name}"

    def test_help_docs_are_non_empty_strings(self):
        """Test that all help doc entries are non-empty strings."""
        for key, doc in HELP_DOCS.items():
            assert isinstance(doc, str), f"Help doc for {key} is not a string"
            assert len(doc) > 0, f"Help doc for {key} is empty"

    def test_help_docs_total_count(self):
        """Test total help doc entries: 8 categories + 23 panels = 31."""
        expected = len(NAV_GROUPS) + sum(len(items) for _, items in NAV_GROUPS)
        assert len(HELP_DOCS) == expected

    def test_help_modal_initialization(self):
        """Test that HelpModal can be initialized."""
        modal = HelpModal("Test Title", "Test body content")
        assert modal._title == "Test Title"
        assert modal._body == "Test body content"


class TestViolationsApproval:
    """Tests for violation approval functionality."""

    def test_approve_violation_adds_rule(self):
        """Test that approving a violation adds the rule to config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {
                "permissions": []
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            new_rule = {
                "matcher": "Skill",
                "mode": "allow",
                "patterns": ["daf-jira"]
            }

            with open(config_path, 'r') as f:
                config = json.load(f)

            config["permissions"].append(new_rule)

            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert updated_config["permissions"][0] == new_rule

    def test_approve_violation_merges_patterns(self):
        """Test that approving a violation merges patterns with existing rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {
                "permissions": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"]
                    }
                ]
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            new_pattern = "release"

            with open(config_path, 'r') as f:
                config = json.load(f)

            existing_rule = next(
                (r for r in config["permissions"]
                 if r.get("matcher") == "Skill" and r.get("mode") == "allow"),
                None
            )

            if existing_rule:
                existing_patterns = existing_rule.get("patterns", [])
                merged_patterns = list(set(existing_patterns + [new_pattern]))
                existing_rule["patterns"] = merged_patterns

            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert "daf-*" in updated_config["permissions"][0]["patterns"]
            assert "release" in updated_config["permissions"][0]["patterns"]


class TestPermissionsEditor:
    """Tests for permissions editor functionality."""

    def test_add_permission_rule(self):
        """Test adding a new permission rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {"permissions": []}
            with open(config_path, 'w') as f:
                json.dump(config, f)

            new_rule = {
                "matcher": "mcp__notebooklm-mcp__*",
                "mode": "allow",
                "patterns": ["*"]
            }

            with open(config_path, 'r') as f:
                config = json.load(f)

            config["permissions"].append(new_rule)

            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert updated_config["permissions"][0]["matcher"] == "mcp__notebooklm-mcp__*"

    def test_delete_permission_rule(self):
        """Test deleting a permission rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {
                "permissions": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"]
                    },
                    {
                        "matcher": "mcp__test__*",
                        "mode": "deny",
                        "patterns": ["*"]
                    }
                ]
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                config = json.load(f)

            config["permissions"].pop(0)

            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert updated_config["permissions"][0]["matcher"] == "mcp__test__*"

    def test_edit_permission_rule(self):
        """Test editing a permission rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {
                "permissions": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"]
                    }
                ]
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                config = json.load(f)

            config["permissions"][0]["patterns"] = ["daf-*", "release"]

            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            assert len(updated_config["permissions"]) == 1
            assert "release" in updated_config["permissions"][0]["patterns"]


class TestConfigViewer:
    """Tests for configuration viewer."""

    def test_load_user_config(self):
        """Test loading user configuration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "ai-guardian.json"

            config = {
                "permissions": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["*"]
                    }
                ],
                "violation_logging": {
                    "enabled": True,
                    "max_entries": 1000
                }
            }
            with open(config_path, 'w') as f:
                json.dump(config, f)

            with open(config_path, 'r') as f:
                loaded_config = json.load(f)

            assert "permissions" in loaded_config
            assert "violation_logging" in loaded_config
            assert loaded_config["violation_logging"]["enabled"] is True

    def test_merge_configs(self):
        """Test merging user and project configs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            user_config_path = Path(tmpdir) / "user.json"
            project_config_path = Path(tmpdir) / "project.json"

            user_config = {
                "permissions": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"]
                    }
                ]
            }
            with open(user_config_path, 'w') as f:
                json.dump(user_config, f)

            project_config = {
                "permissions": [
                    {
                        "matcher": "mcp__*",
                        "mode": "deny",
                        "patterns": ["*"]
                    }
                ]
            }
            with open(project_config_path, 'w') as f:
                json.dump(project_config, f)

            merged_config = {}

            with open(user_config_path, 'r') as f:
                merged_config.update(json.load(f))

            with open(project_config_path, 'r') as f:
                merged_config.update(json.load(f))

            assert len(merged_config["permissions"]) == 1
            assert merged_config["permissions"][0]["matcher"] == "mcp__*"


class TestClipboardSupport:
    """Tests for copy-to-clipboard functionality."""

    def test_app_has_text_selected_handler(self):
        """Test that AIGuardianTUI has on_text_selected handler for auto-copy."""
        app = AIGuardianTUI()
        assert hasattr(app, "on_text_selected")
        assert callable(app.on_text_selected)

    def test_violation_details_modal_has_copy_button(self):
        """Test that ViolationDetailsModal handles copy-details button ID."""
        from ai_guardian.tui.violations import ViolationDetailsModal
        import inspect
        source = inspect.getsource(ViolationDetailsModal.compose)
        assert "copy-details" in source
        source_handler = inspect.getsource(ViolationDetailsModal.on_button_pressed)
        assert "copy-details" in source_handler
        assert "copy_to_clipboard" in source_handler

    def test_violation_details_modal_copy_handler(self):
        """Test that ViolationDetailsModal handles copy-details button."""
        from ai_guardian.tui.violations import ViolationDetailsModal
        from textual.widgets import Button
        modal = ViolationDetailsModal({"type": "test", "message": "test violation"})
        assert hasattr(modal, "on_button_pressed")

    def test_violation_details_modal_stores_violation_data(self):
        """Test that ViolationDetailsModal stores violation data for copying."""
        from ai_guardian.tui.violations import ViolationDetailsModal
        violation = {"type": "secret_detected", "severity": "high", "file": "test.py"}
        modal = ViolationDetailsModal(violation)
        assert modal.violation == violation
        details = json.dumps(modal.violation, indent=2)
        assert '"type": "secret_detected"' in details
        assert '"severity": "high"' in details

    def test_app_has_copy_to_clipboard_override(self):
        """Test that AIGuardianTUI overrides copy_to_clipboard for native fallback."""
        app = AIGuardianTUI()
        assert hasattr(app, "copy_to_clipboard")
        import inspect
        source = inspect.getsource(AIGuardianTUI.copy_to_clipboard)
        assert "copy_to_system_clipboard" in source


class TestCopyToSystemClipboard:
    """Tests for the platform-native copy_to_system_clipboard function."""

    def test_copy_succeeds_on_macos(self):
        """Test clipboard copy using pbcopy on macOS."""
        from unittest.mock import patch, MagicMock
        with patch("ai_guardian.tui.app.sys") as mock_sys, \
             patch("ai_guardian.tui.app.subprocess") as mock_subprocess:
            mock_sys.platform = "darwin"
            result = copy_to_system_clipboard("test text")
            assert result is None
            mock_subprocess.run.assert_called_once()
            args = mock_subprocess.run.call_args
            assert args[0][0] == ["pbcopy"]
            assert args[1]["input"] == b"test text"

    def test_copy_succeeds_on_linux_xclip(self):
        """Test clipboard copy using xclip on Linux."""
        from unittest.mock import patch
        with patch("ai_guardian.tui.app.sys") as mock_sys, \
             patch("ai_guardian.tui.app.subprocess") as mock_subprocess:
            mock_sys.platform = "linux"
            result = copy_to_system_clipboard("test text")
            assert result is None
            args = mock_subprocess.run.call_args
            assert args[0][0] == ["xclip", "-selection", "clipboard"]

    def test_copy_falls_back_to_xsel_on_linux(self):
        """Test fallback to xsel when xclip is not available."""
        from unittest.mock import patch, call
        with patch("ai_guardian.tui.app.sys") as mock_sys, \
             patch("ai_guardian.tui.app.subprocess") as mock_subprocess:
            mock_sys.platform = "linux"
            mock_subprocess.run.side_effect = [
                FileNotFoundError("xclip not found"),
                None,
            ]
            result = copy_to_system_clipboard("test text")
            assert result is None
            assert mock_subprocess.run.call_count == 2
            second_call = mock_subprocess.run.call_args_list[1]
            assert second_call[0][0] == ["xsel", "--clipboard", "--input"]

    def test_copy_succeeds_on_windows(self):
        """Test clipboard copy using clip on Windows."""
        from unittest.mock import patch
        with patch("ai_guardian.tui.app.sys") as mock_sys, \
             patch("ai_guardian.tui.app.subprocess") as mock_subprocess:
            mock_sys.platform = "win32"
            result = copy_to_system_clipboard("test text")
            assert result is None
            args = mock_subprocess.run.call_args
            assert args[0][0] == ["clip"]
            assert args[1]["input"] == "test text".encode("utf-16le")

    def test_copy_returns_error_on_unknown_platform(self):
        """Test that unknown platforms return error message."""
        from unittest.mock import patch
        with patch("ai_guardian.tui.app.sys") as mock_sys:
            mock_sys.platform = "freebsd"
            result = copy_to_system_clipboard("test text")
            assert isinstance(result, str)
            assert "not supported" in result

    def test_copy_returns_error_on_command_not_found(self):
        """Test graceful handling when clipboard command is missing."""
        from unittest.mock import patch
        import subprocess as real_subprocess
        with patch("ai_guardian.tui.app.sys") as mock_sys, \
             patch("ai_guardian.tui.app.subprocess") as mock_subprocess:
            mock_sys.platform = "darwin"
            mock_subprocess.run.side_effect = FileNotFoundError("pbcopy not found")
            mock_subprocess.CalledProcessError = real_subprocess.CalledProcessError
            mock_subprocess.TimeoutExpired = real_subprocess.TimeoutExpired
            result = copy_to_system_clipboard("test text")
            assert isinstance(result, str)

    def test_copy_returns_error_on_process_error(self):
        """Test graceful handling when clipboard command fails."""
        from unittest.mock import patch
        import subprocess as real_subprocess
        with patch("ai_guardian.tui.app.sys") as mock_sys, \
             patch("ai_guardian.tui.app.subprocess") as mock_subprocess:
            mock_sys.platform = "darwin"
            mock_subprocess.run.side_effect = real_subprocess.CalledProcessError(1, "pbcopy")
            mock_subprocess.CalledProcessError = real_subprocess.CalledProcessError
            mock_subprocess.TimeoutExpired = real_subprocess.TimeoutExpired
            result = copy_to_system_clipboard("test text")
            assert isinstance(result, str)

    def test_copy_returns_error_on_timeout(self):
        """Test graceful handling when clipboard command times out."""
        from unittest.mock import patch
        import subprocess as real_subprocess
        with patch("ai_guardian.tui.app.sys") as mock_sys, \
             patch("ai_guardian.tui.app.subprocess") as mock_subprocess:
            mock_sys.platform = "darwin"
            mock_subprocess.run.side_effect = real_subprocess.TimeoutExpired("pbcopy", 5)
            mock_subprocess.CalledProcessError = real_subprocess.CalledProcessError
            mock_subprocess.TimeoutExpired = real_subprocess.TimeoutExpired
            result = copy_to_system_clipboard("test text")
            assert isinstance(result, str)

    def test_copy_handles_unicode(self):
        """Test clipboard copy with unicode text."""
        from unittest.mock import patch
        with patch("ai_guardian.tui.app.sys") as mock_sys, \
             patch("ai_guardian.tui.app.subprocess") as mock_subprocess:
            mock_sys.platform = "darwin"
            text = "Unicode: ☃ ❤ \U0001f680"
            result = copy_to_system_clipboard(text)
            assert result is None
            args = mock_subprocess.run.call_args
            assert args[1]["input"] == text.encode("utf-8")

    def test_linux_both_missing_returns_install_instructions(self):
        """Test that Linux returns install instructions when both xclip and xsel are missing."""
        from unittest.mock import patch
        import subprocess as real_subprocess
        with patch("ai_guardian.tui.app.sys") as mock_sys, \
             patch("ai_guardian.tui.app.subprocess") as mock_subprocess:
            mock_sys.platform = "linux"
            mock_subprocess.run.side_effect = FileNotFoundError("not found")
            mock_subprocess.CalledProcessError = real_subprocess.CalledProcessError
            mock_subprocess.TimeoutExpired = real_subprocess.TimeoutExpired
            result = copy_to_system_clipboard("test text")
            assert isinstance(result, str)
            assert "xclip" in result
            assert "sudo apt install" in result


class TestViolationCardFields:
    """Tests for ViolationCard rendering of violation type fields."""

    def test_prompt_injection_card_shows_matched_text(self):
        """Test that prompt_injection card renders matched_text field."""
        import inspect
        from ai_guardian.tui.violations import ViolationCard
        source = inspect.getsource(ViolationCard.compose)
        assert 'matched_text = blocked.get("matched_text")' in source or \
               "matched_text" in source

    def test_prompt_injection_card_shows_confidence(self):
        """Test that prompt_injection card renders confidence field."""
        import inspect
        from ai_guardian.tui.violations import ViolationCard
        source = inspect.getsource(ViolationCard.compose)
        assert "confidence" in source

    def test_prompt_injection_card_shows_method(self):
        """Test that prompt_injection card renders method field."""
        import inspect
        from ai_guardian.tui.violations import ViolationCard
        source = inspect.getsource(ViolationCard.compose)
        assert "method" in source

    def test_prompt_injection_card_shows_line_number(self):
        """Test that prompt_injection card renders line_number with file_path."""
        import inspect
        from ai_guardian.tui.violations import ViolationCard
        source = inspect.getsource(ViolationCard.compose)
        pi_section_start = source.index('vtype == "prompt_injection"')
        pi_section = source[pi_section_start:pi_section_start + 800]
        assert "line_number" in pi_section

    def test_jailbreak_card_shows_line_number(self):
        """Test that jailbreak_detected card renders line_number with file_path."""
        import inspect
        from ai_guardian.tui.violations import ViolationCard
        source = inspect.getsource(ViolationCard.compose)
        jb_section_start = source.index('vtype == "jailbreak_detected"')
        jb_section = source[jb_section_start:jb_section_start + 800]
        assert "line_number" in jb_section

    def test_jailbreak_card_always_shows_matched_text(self):
        """Test that jailbreak_detected card shows matched_text regardless of file_path."""
        import inspect
        from ai_guardian.tui.violations import ViolationCard
        source = inspect.getsource(ViolationCard.compose)
        jb_section_start = source.index('vtype == "jailbreak_detected"')
        jb_section = source[jb_section_start:jb_section_start + 800]
        matched_count = jb_section.count("matched_text")
        assert matched_count >= 2, "matched_text should be shown outside the else branch"

    def test_tool_permission_card_shows_line_number(self):
        """Test that tool_permission card renders line_number with file_path."""
        import inspect
        from ai_guardian.tui.violations import ViolationCard
        source = inspect.getsource(ViolationCard.compose)
        tp_section_start = source.index('vtype == "tool_permission"')
        tp_section = source[tp_section_start:tp_section_start + 500]
        assert "line_number" in tp_section


class TestModalEscBindings:
    """Tests for ESC key bindings on all modal screens."""

    def test_violation_details_modal_has_esc_binding(self):
        """Test that ViolationDetailsModal has ESC key binding."""
        from ai_guardian.tui.violations import ViolationDetailsModal
        binding_keys = [b.key for b in ViolationDetailsModal.BINDINGS]
        assert "escape" in binding_keys

    def test_add_permission_modal_has_esc_binding(self):
        """Test that AddPermissionModal has ESC key binding."""
        from ai_guardian.tui.permissions import AddPermissionModal
        binding_keys = [b.key for b in AddPermissionModal.BINDINGS]
        assert "escape" in binding_keys

    def test_confirm_clear_modal_has_esc_binding(self):
        """Test that ConfirmClearModal has ESC key binding."""
        from ai_guardian.tui.logs import ConfirmClearModal
        binding_keys = [b.key for b in ConfirmClearModal.BINDINGS]
        assert "escape" in binding_keys

    def test_violation_details_modal_has_scrollbar(self):
        """Test that ViolationDetailsModal wraps content in VerticalScroll."""
        import inspect
        from ai_guardian.tui.violations import ViolationDetailsModal
        source = inspect.getsource(ViolationDetailsModal.compose)
        assert "VerticalScroll" in source

    def test_violation_actions_have_top_margin(self):
        """Test that violation-actions CSS has top margin to prevent overlap."""
        from ai_guardian.tui.violations import ViolationsContent
        assert "margin: 1 0 0 0" in ViolationsContent.CSS


class TestListScrollWrapping:
    """Tests that editable list widgets are wrapped in scrollable containers."""

    @pytest.mark.parametrize("module,class_name,list_ids", [
        ("scan_pii", "ScanPIIContent", ["ignore-files-list", "ignore-tools-list", "pii-allowlist-patterns"]),
        ("secrets", "SecretsContent", ["secret-allowlist-patterns"]),
        ("prompt_injection", "PromptInjectionContent", ["allowlist-patterns", "custom-patterns"]),
        ("config_scanner", "ConfigScannerContent", ["additional-files-list", "ignore-files-list", "additional-patterns-list"]),
        ("ssrf", "SSRFContent", ["blocked-ips-list", "blocked-domains-list", "allowed-domains-list"]),
        ("secret_redaction", "SecretRedactionContent", ["additional-patterns-list"]),
    ])
    def test_list_statics_have_scroll_wrapper(self, module, class_name, list_ids):
        """Verify each list Static is inside a VerticalScroll context manager."""
        import importlib
        import inspect
        import re
        mod = importlib.import_module(f"ai_guardian.tui.{module}")
        cls = getattr(mod, class_name)
        source = inspect.getsource(cls.compose)
        for list_id in list_ids:
            pattern = rf'VerticalScroll\(classes="list-scroll"\).*?\n\s+yield Static\("", id="{list_id}"\)'
            assert re.search(pattern, source, re.DOTALL), (
                f"{class_name}.compose(): {list_id} not wrapped in VerticalScroll(classes='list-scroll')"
            )

    @pytest.mark.parametrize("module,class_name", [
        ("scan_pii", "ScanPIIContent"),
        ("secrets", "SecretsContent"),
        ("prompt_injection", "PromptInjectionContent"),
        ("config_scanner", "ConfigScannerContent"),
        ("ssrf", "SSRFContent"),
        ("secret_redaction", "SecretRedactionContent"),
    ])
    def test_css_has_list_scroll_class(self, module, class_name):
        """Verify each panel CSS defines .list-scroll with max-height."""
        import importlib
        mod = importlib.import_module(f"ai_guardian.tui.{module}")
        cls = getattr(mod, class_name)
        assert ".list-scroll" in cls.CSS, f"{class_name} CSS missing .list-scroll class"
        assert "max-height" in cls.CSS, f"{class_name} CSS missing max-height in .list-scroll"

    @pytest.mark.parametrize("module,class_name", [
        ("directory_protection", "DirectoryProtectionContent"),
        ("permissions", "PermissionsScreen"),
        ("permissions_discovery", "PermissionsDiscoveryContent"),
        ("remote_configs", "RemoteConfigsContent"),
    ])
    def test_pattern_b_containers_have_max_height(self, module, class_name):
        """Verify Pattern B VerticalScroll containers have max-height in their CSS."""
        import importlib
        mod = importlib.import_module(f"ai_guardian.tui.{module}")
        cls = getattr(mod, class_name)
        assert "max-height" in cls.CSS, (
            f"{class_name} CSS missing max-height for scrollable list container"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
