"""Tests for the local_time web component."""

import sys

import pytest

pytest.importorskip("nicegui", reason="NiceGUI requires Python >= 3.10")


class TestLocalTimeModule:
    """Verify the local_time component module is importable."""

    def test_module_imports(self):
        from ai_guardian.web.components.local_time import (
            local_time_label,
            inject_local_time_js,
        )
        assert callable(local_time_label)
        assert callable(inject_local_time_js)


class TestLocalTimeLabelOutput:
    """Verify local_time_label produces correct HTML with data attributes."""

    def test_contains_utc_timestamp_class(self):
        from ai_guardian.web.components.local_time import local_time_label
        from unittest.mock import patch, MagicMock

        captured_html = None

        def fake_html(html_str):
            nonlocal captured_html
            captured_html = html_str
            mock_el = MagicMock()
            mock_el.classes.return_value = mock_el
            return mock_el

        with patch("ai_guardian.web.components.local_time.ui") as mock_ui:
            mock_ui.html.side_effect = fake_html
            local_time_label("2026-06-04T12:48:57.772789Z")

        assert captured_html is not None
        assert 'class="utc-timestamp' in captured_html

    def test_contains_data_utc_attribute(self):
        from ai_guardian.web.components.local_time import local_time_label
        from unittest.mock import patch, MagicMock

        captured_html = None

        def fake_html(html_str):
            nonlocal captured_html
            captured_html = html_str
            mock_el = MagicMock()
            mock_el.classes.return_value = mock_el
            return mock_el

        with patch("ai_guardian.web.components.local_time.ui") as mock_ui:
            mock_ui.html.side_effect = fake_html
            local_time_label("2026-06-04T12:48:57.772789Z")

        assert 'data-utc="2026-06-04T12:48:57.772789Z"' in captured_html

    def test_fallback_text_is_truncated_utc(self):
        from ai_guardian.web.components.local_time import local_time_label
        from unittest.mock import patch, MagicMock

        captured_html = None

        def fake_html(html_str):
            nonlocal captured_html
            captured_html = html_str
            mock_el = MagicMock()
            mock_el.classes.return_value = mock_el
            return mock_el

        with patch("ai_guardian.web.components.local_time.ui") as mock_ui:
            mock_ui.html.side_effect = fake_html
            local_time_label("2026-06-04T12:48:57.772789Z")

        # Fallback text between > and < should be truncated to 19 chars
        assert ">2026-06-04T12:48:57<" in captured_html

    def test_empty_timestamp(self):
        from ai_guardian.web.components.local_time import local_time_label
        from unittest.mock import patch, MagicMock

        captured_html = None

        def fake_html(html_str):
            nonlocal captured_html
            captured_html = html_str
            mock_el = MagicMock()
            mock_el.classes.return_value = mock_el
            return mock_el

        with patch("ai_guardian.web.components.local_time.ui") as mock_ui:
            mock_ui.html.side_effect = fake_html
            local_time_label("")

        assert 'data-utc=""' in captured_html
        assert "><" in captured_html  # empty fallback

    def test_timestamp_without_z_suffix(self):
        from ai_guardian.web.components.local_time import local_time_label
        from unittest.mock import patch, MagicMock

        captured_html = None

        def fake_html(html_str):
            nonlocal captured_html
            captured_html = html_str
            mock_el = MagicMock()
            mock_el.classes.return_value = mock_el
            return mock_el

        with patch("ai_guardian.web.components.local_time.ui") as mock_ui:
            mock_ui.html.side_effect = fake_html
            local_time_label("2026-06-04T12:48:57")

        assert 'data-utc="2026-06-04T12:48:57"' in captured_html
        assert ">2026-06-04T12:48:57<" in captured_html


class TestConvertJsContent:
    """Verify the JavaScript conversion snippet has required elements."""

    def test_js_contains_utc_timestamp_selector(self):
        from ai_guardian.web.components.local_time import _CONVERT_JS
        assert "utc-timestamp" in _CONVERT_JS

    def test_js_contains_toLocaleString(self):
        from ai_guardian.web.components.local_time import _CONVERT_JS
        assert "toLocaleString" in _CONVERT_JS

    def test_js_reads_data_utc_attribute(self):
        from ai_guardian.web.components.local_time import _CONVERT_JS
        assert "data-utc" in _CONVERT_JS

    def test_js_handles_missing_z_suffix(self):
        """JS should append 'Z' if the timestamp doesn't end with it."""
        from ai_guardian.web.components.local_time import _CONVERT_JS
        assert "Z" in _CONVERT_JS


class TestInjectLocalTimeJs:
    """Verify inject_local_time_js calls ui.run_javascript."""

    def test_calls_run_javascript(self):
        from ai_guardian.web.components.local_time import (
            inject_local_time_js,
            _CONVERT_JS,
        )
        from unittest.mock import patch

        with patch("ai_guardian.web.components.local_time.ui") as mock_ui:
            inject_local_time_js()
            mock_ui.run_javascript.assert_called_once_with(_CONVERT_JS)
