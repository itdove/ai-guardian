#!/usr/bin/env python3
"""
Tests for the Directory Scan TUI panel.

Tests integration with the TUI app (NAV_GROUPS, HELP_DOCS) and verifies
the panel can be imported without errors.
"""

import pytest

from ai_guardian.tui.directory_scan import DirectoryScanContent
from ai_guardian.tui.app import NAV_GROUPS, HELP_DOCS


class TestDirectoryScanImport:
    """Verify the panel integrates with the TUI app."""

    def test_directory_scan_content_can_be_imported(self):
        assert DirectoryScanContent is not None

    def test_directory_scan_in_nav_groups(self):
        nav_dict = {name: [pid for _, pid in items] for name, items in NAV_GROUPS}
        assert "panel-directory-scan" in nav_dict["Tools"]

    def test_directory_scan_has_help_doc(self):
        assert "panel-directory-scan" in HELP_DOCS
        assert len(HELP_DOCS["panel-directory-scan"]) > 0

    def test_tools_category_help_mentions_directory_scan(self):
        assert "Directory Scan" in HELP_DOCS["Tools"]

    def test_directory_scan_position_in_tools(self):
        """Directory Scan appears after Engine Tester (last item in Tools)."""
        for name, items in NAV_GROUPS:
            if name == "Tools":
                panel_ids = [pid for _, pid in items]
                idx = panel_ids.index("panel-directory-scan")
                assert panel_ids[idx - 1] == "panel-engine-tester"
                assert idx == len(panel_ids) - 1
                break

    def test_help_doc_mentions_cli_equivalent(self):
        help_text = HELP_DOCS["panel-directory-scan"]
        assert "ai-guardian scan" in help_text

    def test_help_doc_mentions_export(self):
        help_text = HELP_DOCS["panel-directory-scan"]
        assert "JSON" in help_text
        assert "SARIF" in help_text
