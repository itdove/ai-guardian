"""Tests for Supply Chain page — web console and TUI panel (#1133)."""

import inspect
from unittest.mock import patch, MagicMock

import pytest


class TestWebPageImport:
    """Verify web page module is importable."""

    @pytest.fixture(autouse=True)
    def _skip_no_nicegui(self):
        pytest.importorskip("nicegui", reason="NiceGUI requires Python >= 3.10")

    def test_create_function_exists(self):
        from ai_guardian.web.pages.supply_chain import create_supply_chain_page

        assert callable(create_supply_chain_page)

    def test_stats_helper_exists(self):
        from ai_guardian.web.pages.supply_chain import _load_sc_stats

        assert callable(_load_sc_stats)


class TestWebRouteRegistration:
    """Verify route is registered in app.py."""

    @pytest.fixture(autouse=True)
    def _skip_no_nicegui(self):
        pytest.importorskip("nicegui", reason="NiceGUI requires Python >= 3.10")

    def test_route_in_app_source(self):
        from ai_guardian.web.app import WebConsole

        source = inspect.getsource(WebConsole._register_pages)
        assert "/supply-chain" in source

    def test_route_in_sidebar_nav(self):
        from ai_guardian.web.components.header import NAV_GROUPS

        all_suffixes = [suffix for _, items in NAV_GROUPS for _, suffix in items]
        assert "/supply-chain" in all_suffixes

    def test_supply_chain_in_threat_detection_group(self):
        from ai_guardian.web.components.header import NAV_GROUPS

        nav_dict = {name: items for name, items in NAV_GROUPS}
        threat_labels = [label for label, _ in nav_dict["Threat Detection"]]
        assert "Supply Chain" in threat_labels


class TestTUIImport:
    """Verify TUI panel module is importable."""

    def test_content_class_exists(self):
        from ai_guardian.tui.supply_chain import SupplyChainContent

        assert SupplyChainContent is not None

    def test_format_enabled_helper(self):
        from ai_guardian.tui.supply_chain import _format_enabled

        assert callable(_format_enabled)


class TestTUIRegistration:
    """Verify TUI panel is registered in app.py."""

    def test_panel_in_nav_groups(self):
        from ai_guardian.tui.app import NAV_GROUPS

        all_panels = [pid for _, items in NAV_GROUPS for _, pid in items]
        assert "panel-supply-chain" in all_panels

    def test_panel_in_threat_detection_group(self):
        from ai_guardian.tui.app import NAV_GROUPS

        nav_dict = {name: [pid for _, pid in items] for name, items in NAV_GROUPS}
        assert "panel-supply-chain" in nav_dict["Threat Detection"]

    def test_panel_in_help_docs(self):
        from ai_guardian.tui.app import HELP_DOCS

        assert "panel-supply-chain" in HELP_DOCS

    def test_help_doc_is_nonempty_string(self):
        from ai_guardian.tui.app import HELP_DOCS

        doc = HELP_DOCS["panel-supply-chain"]
        assert isinstance(doc, str)
        assert len(doc) > 20


class TestFormatEnabled:
    """Test _format_enabled helper for various input types."""

    def test_bool_true(self):
        from ai_guardian.tui.supply_chain import _format_enabled

        result = _format_enabled(True)
        assert "green" in result
        assert "Yes" in result

    def test_bool_false(self):
        from ai_guardian.tui.supply_chain import _format_enabled

        result = _format_enabled(False)
        assert "red" in result
        assert "No" in result

    def test_dict_value_true(self):
        from ai_guardian.tui.supply_chain import _format_enabled

        result = _format_enabled({"value": True})
        assert "green" in result

    def test_dict_value_false(self):
        from ai_guardian.tui.supply_chain import _format_enabled

        result = _format_enabled({"value": False})
        assert "red" in result

    def test_dict_with_expired_disabled_until(self):
        from ai_guardian.tui.supply_chain import _format_enabled

        result = _format_enabled(
            {
                "value": True,
                "disabled_until": "2020-01-01T00:00:00Z",
            }
        )
        assert "green" in result


class TestLoadScStats:
    """Test _load_sc_stats helper."""

    @pytest.fixture(autouse=True)
    def _skip_no_nicegui(self):
        pytest.importorskip("nicegui", reason="NiceGUI requires Python >= 3.10")

    def test_no_violations(self):
        mock_vl = MagicMock()
        mock_vl.return_value.get_recent_violations.return_value = []
        from ai_guardian.web.pages.supply_chain import _load_sc_stats

        with patch("ai_guardian.violation_logger.ViolationLogger", mock_vl):
            result = _load_sc_stats()
        assert result == 0

    def test_with_violations(self):
        mock_vl = MagicMock()
        mock_vl.return_value.get_recent_violations.return_value = [
            {"violation_type": "supply_chain"},
            {"violation_type": "supply_chain"},
            {"violation_type": "supply_chain"},
        ]
        from ai_guardian.web.pages.supply_chain import _load_sc_stats

        with patch("ai_guardian.violation_logger.ViolationLogger", mock_vl):
            result = _load_sc_stats()
        assert result == 3

    def test_exception_returns_none(self):
        from ai_guardian.web.pages.supply_chain import _load_sc_stats

        with patch(
            "ai_guardian.violation_logger.ViolationLogger",
            side_effect=Exception("test error"),
        ):
            result = _load_sc_stats()
        assert result is None
