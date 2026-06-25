#!/usr/bin/env python3
"""
Tests for the Engine Tester TUI panel.

Tests integration with the TUI app (NAV_GROUPS, HELP_DOCS) and verifies
the panel can be imported without errors.
"""


from ai_guardian.tui.engine_tester import EngineTesterContent
from ai_guardian.tui.app import NAV_GROUPS, HELP_DOCS


class TestEngineTesterImport:
    """Verify the panel integrates with the TUI app."""

    def test_engine_tester_content_can_be_imported(self):
        assert EngineTesterContent is not None

    def test_engine_tester_in_nav_groups(self):
        nav_dict = {name: [pid for _, pid in items] for name, items in NAV_GROUPS}
        assert "panel-engine-tester" in nav_dict["Tools"]

    def test_engine_tester_has_help_doc(self):
        assert "panel-engine-tester" in HELP_DOCS
        assert len(HELP_DOCS["panel-engine-tester"]) > 0

    def test_tools_category_help_mentions_engine_tester(self):
        assert "Engine Tester" in HELP_DOCS["Tools"]

    def test_engine_tester_position_in_tools(self):
        """Engine Tester appears between Hook Simulator and Directory Scan."""
        for name, items in NAV_GROUPS:
            if name == "Tools":
                panel_ids = [pid for _, pid in items]
                idx = panel_ids.index("panel-engine-tester")
                assert panel_ids[idx - 1] == "panel-hook-simulator"
                assert panel_ids[idx + 1] == "panel-directory-scan"
                break
