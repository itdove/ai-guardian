"""Tests for the unified theme module (Issue #1288)."""

import re

import pytest

from ai_guardian.theme import (
    PRIMARY,
    SUCCESS,
    ERROR,
    WARNING,
    CAUTION,
    INFO,
    SURFACE,
    SURFACE_ALT,
    TEXT,
    TEXT_MUTED,
    TEXT_DIM,
    CODE_BG,
    HIGHLIGHT_BG,
    ANNOTATION_FG,
    SEVERITY_COLORS,
    VIOLATION_BADGES,
    BUTTON_COLORS,
    quasar_color,
    quasar_severity,
    quasar_button,
    violation_badge,
    textual_severity_class,
    get_images_dir,
    get_image_path,
)

HEX_PATTERN = re.compile(r"^#[0-9A-Fa-f]{6}$")


class TestPaletteConstants:
    """All palette constants must be valid 6-digit hex colors."""

    @pytest.mark.parametrize(
        "name,value",
        [
            ("PRIMARY", PRIMARY),
            ("SUCCESS", SUCCESS),
            ("ERROR", ERROR),
            ("WARNING", WARNING),
            ("CAUTION", CAUTION),
            ("INFO", INFO),
            ("SURFACE", SURFACE),
            ("SURFACE_ALT", SURFACE_ALT),
            ("TEXT", TEXT),
            ("TEXT_MUTED", TEXT_MUTED),
            ("TEXT_DIM", TEXT_DIM),
            ("CODE_BG", CODE_BG),
            ("HIGHLIGHT_BG", HIGHLIGHT_BG),
            ("ANNOTATION_FG", ANNOTATION_FG),
        ],
    )
    def test_valid_hex(self, name, value):
        assert HEX_PATTERN.match(value), f"{name}={value} is not a valid hex color"


class TestSeverityColors:
    """Severity color mapping coverage."""

    @pytest.mark.parametrize("sev", ["critical", "high", "warning", "medium", "low", "info"])
    def test_all_severities_mapped(self, sev):
        assert sev in SEVERITY_COLORS
        assert HEX_PATTERN.match(SEVERITY_COLORS[sev])


class TestViolationBadges:
    """Violation badge mapping coverage."""

    KNOWN_TYPES = [
        "secret_detected",
        "prompt_injection",
        "pii_detected",
        "ssrf_blocked",
        "config_file_exfil",
        "context_poisoning",
        "supply_chain",
        "directory_blocking",
        "jailbreak_detected",
        "tool_permission",
        "secret_redaction",
        "secret_in_transcript",
        "pii_in_transcript",
        "prompt_injection_in_transcript",
        "annotation_suppressed",
        "image_secret_detected",
        "image_pii_detected",
    ]

    @pytest.mark.parametrize("vtype", KNOWN_TYPES)
    def test_all_violation_types_mapped(self, vtype):
        assert vtype in VIOLATION_BADGES
        badge = VIOLATION_BADGES[vtype]
        assert "color" in badge
        assert "icon" in badge
        assert HEX_PATTERN.match(badge["color"])
        assert len(badge["icon"]) > 0

    def test_violation_badge_helper(self):
        icon, color = violation_badge("secret_detected")
        assert icon == "\U0001f511"
        assert color == ERROR

    def test_unknown_violation_type_fallback(self):
        icon, color = violation_badge("unknown_type_xyz")
        assert icon == "❓"
        assert color == INFO


class TestButtonColors:
    """Button color mapping."""

    @pytest.mark.parametrize(
        "key", ["block", "allow_once", "allow_always", "suppress_in_source", "ignore_file"]
    )
    def test_action_buttons_have_colors(self, key):
        assert key in BUTTON_COLORS
        assert BUTTON_COLORS[key] is not None
        assert HEX_PATTERN.match(BUTTON_COLORS[key])

    def test_view_file_is_neutral(self):
        assert BUTTON_COLORS["view_file"] is None

    def test_cancel_is_neutral(self):
        assert BUTTON_COLORS["cancel"] is None


class TestQuasarAdapters:
    """Quasar color mapping functions."""

    def test_quasar_color_known(self):
        assert quasar_color(ERROR) == "red-8"
        assert quasar_color(SUCCESS) == "green-8"
        assert quasar_color(PRIMARY) == "blue-8"

    def test_quasar_color_none(self):
        assert quasar_color(None) == "grey"

    def test_quasar_color_unknown(self):
        assert quasar_color("#123456") == "grey"

    def test_quasar_severity(self):
        assert quasar_severity("critical") == "red-8"
        assert quasar_severity("high") == "orange-8"
        assert quasar_severity("low") == "blue-grey-7"

    def test_quasar_button(self):
        assert quasar_button("block") == "red-8"
        assert quasar_button("allow_once") == "green-8"
        assert quasar_button("view_file") == "grey"


class TestTextualAdapter:
    """Textual CSS class mapping."""

    def test_textual_severity_class(self):
        assert textual_severity_class("critical") == "status-error"
        assert textual_severity_class("high") == "status-error"
        assert textual_severity_class("warning") == "status-warn"
        assert textual_severity_class("low") == "status-info"

    def test_textual_severity_class_unknown(self):
        assert textual_severity_class("unknown") == ""


class TestImagePaths:
    """Image path resolution in development layout."""

    def test_images_dir_exists(self):
        d = get_images_dir()
        assert d is not None
        assert d.is_dir()

    def test_get_tray_icon(self):
        p = get_image_path("tray-icon-32.png")
        assert p is not None
        assert p.exists()

    def test_get_nonexistent_image(self):
        p = get_image_path("does-not-exist.png")
        assert p is None
