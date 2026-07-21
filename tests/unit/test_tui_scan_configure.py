#!/usr/bin/env python3
"""
Tests for the Scan Configure TUI panel.

Tests integration with the TUI app (NAV_GROUPS, HELP_DOCS) and verifies
the panel can be imported without errors.
"""

from ai_guardian.tui.scan_configure import ScanConfigureContent
from ai_guardian.tui.app import NAV_GROUPS, HELP_DOCS


class TestScanConfigureImport:
    """Verify the panel integrates with the TUI app."""

    def test_scan_configure_content_can_be_imported(self):
        assert ScanConfigureContent is not None

    def test_scan_configure_in_nav_groups(self):
        nav_dict = {name: [pid for _, pid in items] for name, items in NAV_GROUPS}
        assert "panel-scan-configure" in nav_dict["Tools"]

    def test_scan_configure_has_help_doc(self):
        assert "panel-scan-configure" in HELP_DOCS
        assert len(HELP_DOCS["panel-scan-configure"]) > 0

    def test_scan_configure_position_in_tools(self):
        """Scan Configure appears after Directory Scan in Tools."""
        for name, items in NAV_GROUPS:
            if name == "Tools":
                panel_ids = [pid for _, pid in items]
                idx = panel_ids.index("panel-scan-configure")
                assert panel_ids[idx - 1] == "panel-directory-scan"
                break

    def test_help_doc_mentions_init_project(self):
        """Help doc references the CLI equivalent."""
        assert "init-project" in HELP_DOCS["panel-scan-configure"]
